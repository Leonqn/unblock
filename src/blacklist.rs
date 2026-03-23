use std::io::BufReader;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use futures_util::stream::Stream;
use reqwest::Url;
use serde::Deserialize;
use tokio_stream::StreamExt;

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
struct BlacklistDump {
    list: Vec<BlacklistEntry>,
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
                match parse_json_dump_to_disk(&json_path, &bl_path) {
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
/// Uses typed deserialization from a buffered reader — avoids loading raw JSON bytes.
/// Peak memory: ~40 MB (Vec of 1.3M domain strings), steady state: ~0 MB (mmap).
fn parse_json_dump_to_disk(json_path: &PathBuf, bl_path: &PathBuf) -> Result<DiskBlacklist> {
    let file = std::fs::File::open(json_path)?;
    let reader = BufReader::new(file);
    let dump: BlacklistDump = serde_json::from_reader(reader)?;

    let mut builder = DiskBlacklistBuilder::new(bl_path.clone())?;
    for entry in dump.list {
        builder.add(&entry.d)?;
    }
    builder.finish()
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
