use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use futures_util::stream::Stream;
use log::info;
use tokio_stream::StreamExt;
use url::Url;

use crate::files_stream::create_files_stream_to_disk;

/// Trait for domain blacklist lookups.
pub trait Blacklist: Send + Sync {
    fn contains(&self, domain: &str) -> bool;
}

/// Memory-efficient domain set storing only u64 hashes.
/// ~4 MB for 500K domains instead of hundreds of MB with a tree.
#[derive(Default)]
pub struct DomainHashSet {
    hashes: HashSet<u64>,
}

impl DomainHashSet {
    pub fn insert(&mut self, domain: &str) {
        self.hashes.insert(Self::hash_domain(domain));
    }

    pub fn contains(&self, domain: &str) -> bool {
        let mut remaining = domain;
        loop {
            if self.hashes.contains(&Self::hash_domain(remaining)) {
                return true;
            }
            match remaining.find('.') {
                Some(pos) => remaining = &remaining[pos + 1..],
                None => return false,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    fn hash_domain(domain: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        for c in domain.bytes() {
            c.to_ascii_lowercase().hash(&mut hasher);
        }
        hasher.finish()
    }
}

impl Blacklist for DomainHashSet {
    fn contains(&self, domain: &str) -> bool {
        DomainHashSet::contains(self, domain)
    }
}

pub fn download_and_parse(
    blacklist_url: Url,
    update_interval: Duration,
    dest_path: PathBuf,
) -> Result<impl Stream<Item = Box<dyn Blacklist>>> {
    Ok(
        create_files_stream_to_disk(blacklist_url, update_interval, dest_path)?
            .then(|path| async move {
                let result =
                    tokio::task::spawn_blocking(move || parse_text_dump_from_file(&path)).await;
                match result {
                    Ok(Ok(bl)) => Some(Box::new(bl) as Box<dyn Blacklist>),
                    Ok(Err(err)) => {
                        log::error!("Error occurred while parsing text blacklist: {:#}", err);
                        None
                    }
                    Err(err) => {
                        log::error!("spawn_blocking panicked: {:#}", err);
                        None
                    }
                }
            })
            .filter_map(|x| x),
    )
}

fn parse_text_dump_from_file(path: &std::path::Path) -> Result<DomainHashSet> {
    use std::io::BufRead;
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut bl = DomainHashSet::default();
    for line in reader.lines() {
        let line = line?;
        let domain = line.trim().trim_start_matches('.');
        if !domain.is_empty() {
            bl.insert(domain);
        }
    }
    info!("Loaded blacklist with {} domain hashes", bl.len());
    Ok(bl)
}

#[cfg(test)]
mod test {
    use super::DomainHashSet;
    use anyhow::Result;

    fn parse_text_dump(dump: &[u8]) -> Result<DomainHashSet> {
        let text = std::str::from_utf8(dump)?;
        let mut bl = DomainHashSet::default();
        for line in text.lines() {
            let domain = line.trim().trim_start_matches('.');
            if !domain.is_empty() {
                bl.insert(domain);
            }
        }
        Ok(bl)
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
