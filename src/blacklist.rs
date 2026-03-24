use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use futures_util::stream::Stream;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use tokio_stream::StreamExt;
use url::Url;

use crate::disk_blacklist::{DiskBlacklist, DiskBlacklistBuilder};
use crate::files_stream::{create_files_stream, create_files_stream_to_disk};
use crate::prefix_tree::PrefixTree;

/// Trait for domain blacklist lookups.
pub trait Blacklist: Send + Sync {
    fn contains(&self, domain: &str) -> bool;
}

impl Blacklist for PrefixTree {
    fn contains(&self, domain: &str) -> bool {
        PrefixTree::contains(self, domain)
    }
}

impl Blacklist for DiskBlacklist {
    fn contains(&self, domain: &str) -> bool {
        DiskBlacklist::contains(self, domain)
    }
}

#[derive(Deserialize)]
struct BlacklistEntry {
    d: String,
}

pub fn rvzdata(
    blacklist_url: Url,
    update_interval: Duration,
    data_dir: PathBuf,
) -> Result<impl Stream<Item = Box<dyn Blacklist>>> {
    let json_path = data_dir.join("rvzdata.json");
    let bl_path = data_dir.join("rvzdata.bl");
    Ok(
        create_files_stream_to_disk(blacklist_url, update_interval, json_path.clone())?.filter_map(
            move |json_path| {
                let bl_path = bl_path.clone();
                let result = parse_json_dump_to_disk(&json_path, &bl_path);
                // Remove JSON file after parsing — it's 93 MB and no longer needed.
                // Frees disk space and page cache.
                if let Err(e) = std::fs::remove_file(&json_path) {
                    log::warn!("Failed to remove temp JSON file: {:#}", e);
                }
                match result {
                    Ok(bl) => Some(Box::new(bl) as Box<dyn Blacklist>),
                    Err(err) => {
                        log::error!("Error occurred while parsing blacklist: {:#}", err);
                        None
                    }
                }
            },
        ),
    )
}

/// Parse JSON dump from disk file, building a DiskBlacklist (sorted hash file).
/// Uses streaming deserialization — processes one entry at a time, never holds full Vec.
/// Peak memory: ~8 KB (BufReader buffer) + one entry (~100 bytes), steady state: ~0 MB (mmap).
fn parse_json_dump_to_disk(json_path: &Path, bl_path: &Path) -> Result<DiskBlacklist> {
    let file = std::fs::File::open(json_path)?;
    let reader = BufReader::new(file);
    let mut builder = DiskBlacklistBuilder::new(bl_path.to_path_buf())?;

    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let seed = DumpSeed {
        builder: &mut builder,
    };
    seed.deserialize(&mut deserializer)?;

    builder.finish()
}

/// DeserializeSeed that streams the top-level `{"h": ..., "list": [...]}` object.
/// Only processes the "list" field, skipping everything else.
struct DumpSeed<'a> {
    builder: &'a mut DiskBlacklistBuilder,
}

impl<'de, 'a> DeserializeSeed<'de> for DumpSeed<'a> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(DumpVisitor {
            builder: self.builder,
        })
    }
}

struct DumpVisitor<'a> {
    builder: &'a mut DiskBlacklistBuilder,
}

impl<'de, 'a> Visitor<'de> for DumpVisitor<'a> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("blacklist dump object with 'list' field")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "list" {
                map.next_value_seed(ListSeed {
                    builder: self.builder,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

/// DeserializeSeed that streams the "list" array, processing entries one by one.
struct ListSeed<'a> {
    builder: &'a mut DiskBlacklistBuilder,
}

impl<'de, 'a> DeserializeSeed<'de> for ListSeed<'a> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(ListVisitor {
            builder: self.builder,
        })
    }
}

struct ListVisitor<'a> {
    builder: &'a mut DiskBlacklistBuilder,
}

impl<'de, 'a> Visitor<'de> for ListVisitor<'a> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("array of blacklist entries")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(entry) = seq.next_element::<BlacklistEntry>()? {
            self.builder.add(&entry.d).map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

pub fn inside_raw(
    blacklist_url: Url,
    update_interval: Duration,
) -> Result<impl Stream<Item = Box<dyn Blacklist>>> {
    Ok(
        create_files_stream(blacklist_url, update_interval)?.filter_map(
            |dump| match parse_text_dump(&dump) {
                Ok(tree) => Some(Box::new(tree) as Box<dyn Blacklist>),
                Err(err) => {
                    log::error!("Error occurred while parsing text blacklist: {:#}", err);
                    None
                }
            },
        ),
    )
}

fn parse_text_dump(dump: &[u8]) -> Result<PrefixTree> {
    let text = std::str::from_utf8(dump)?;
    let mut tree = PrefixTree::default();
    for line in text.lines() {
        let domain = line.trim().trim_start_matches('.');
        if !domain.is_empty() {
            tree.add(format!("*.{domain}"));
        }
    }
    Ok(tree)
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    #[test]
    fn json_parse_to_disk_test() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let json_path = dir.path().join("dump.json");
        let bl_path = dir.path().join("dump.bl");

        std::fs::copy("test/dump.json", &json_path)?;

        let bl = parse_json_dump_to_disk(&json_path, &bl_path)?;

        assert!(bl.contains("blocked.example.org"));
        assert!(bl.contains("www.blocked.example.com"));
        assert!(bl.contains("something.test"));
        assert!(bl.contains("wildcard.example.net"));
        assert!(bl.contains("sub.wildcard.example.net"));
        assert!(bl.contains("another.example.org"));
        assert!(!bl.contains("notblocked.example.org"));
        Ok(())
    }

    #[test]
    fn text_parse_test() -> Result<()> {
        let dump = include_bytes!("../test/inside-raw.lst");

        let parsed_domains = parse_text_dump(dump)?;

        assert!(parsed_domains.contains("blocked.fake.ua"));
        assert!(parsed_domains.contains("blocked-site.example.org"));
        assert!(parsed_domains.contains("test.fake.com"));
        assert!(parsed_domains.contains("wildcard.fake.net"));
        assert!(parsed_domains.contains("sub.wildcard.fake.net"));
        assert!(parsed_domains.contains("another.fake.org"));
        assert!(!parsed_domains.contains("notblocked.fake.org"));
        Ok(())
    }
}
