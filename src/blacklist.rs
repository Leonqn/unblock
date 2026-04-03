use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use futures_util::stream::Stream;
use tokio_stream::StreamExt;
use url::Url;

use crate::files_stream::create_files_stream_to_disk;
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
                    Ok(Ok(tree)) => Some(Box::new(tree) as Box<dyn Blacklist>),
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

fn parse_text_dump_from_file(path: &std::path::Path) -> Result<PrefixTree> {
    let dump = std::fs::read(path)?;
    parse_text_dump(&dump)
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
