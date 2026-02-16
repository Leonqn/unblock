use std::time::Duration;

use anyhow::Result;
use futures_util::stream::Stream;
use reqwest::Url;
use serde::Deserialize;
use tokio_stream::StreamExt;

use crate::{files_stream::create_files_stream, prefix_tree::PrefixTree};

#[derive(Deserialize)]
struct BlacklistDump {
    list: Vec<BlacklistEntry>,
}

#[derive(Deserialize)]
struct BlacklistEntry {
    d: String,
}

pub fn blacklists(
    blacklist_url: Url,
    update_inverval: Duration,
) -> Result<impl Stream<Item = PrefixTree>> {
    Ok(create_files_stream(blacklist_url, update_inverval)?
        .filter_map(|dump| match parse_json_dump(&dump) {
            Ok(tree) => Some(tree),
            Err(err) => {
                log::error!("Error occured while parsing blacklist: {:#}", err);
                None
            }
        }))
}

fn parse_json_dump(dump: &[u8]) -> Result<PrefixTree> {
    let blacklist: BlacklistDump = serde_json::from_slice(dump)?;
    let mut tree = PrefixTree::default();
    for entry in blacklist.list {
        tree.add(entry.d);
    }
    Ok(tree)
}

#[cfg(test)]
mod test {
    use super::parse_json_dump;
    use anyhow::Result;

    #[test]
    fn json_parse_test() -> Result<()> {
        let dump = include_bytes!("../test/dump.json");

        let parsed_domains = parse_json_dump(dump)?;

        assert!(parsed_domains.contains("blocked.example.org"));
        assert!(parsed_domains.contains("www.blocked.example.com"));
        assert!(parsed_domains.contains("something.test"));
        assert!(parsed_domains.contains("wildcard.example.net"));
        assert!(parsed_domains.contains("sub.wildcard.example.net"));
        assert!(parsed_domains.contains("another.example.org"));
        assert!(!parsed_domains.contains("notblocked.example.org"));
        Ok(())
    }
}
