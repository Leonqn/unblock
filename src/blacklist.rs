use std::time::Duration;

use anyhow::Result;
use futures_util::stream::Stream;
use reqwest::Url;
use tokio_stream::StreamExt;

use crate::{files_stream::create_files_stream, prefix_tree::PrefixTree};

pub fn blacklists(
    blacklist_url: Url,
    update_inverval: Duration,
) -> Result<impl Stream<Item = PrefixTree>> {
    Ok(create_files_stream(blacklist_url, update_inverval)?
        .map(|dump| parse_csv_dump(dump.as_ref())))
}

fn parse_csv_dump(dump: &[u8]) -> PrefixTree {
    dump.split(|b| *b == b'\n')
        .filter_map(|line| {
            let mut iter = line.split(|b| *b == b';');
            iter.next()?;
            let domain = iter.next()?;
            iter.next()
                .and_then(|x| std::str::from_utf8(x).ok())
                .map_or(true, |url| !url.contains("http://"))
                .then_some(domain)
        })
        .filter_map(|domains| std::str::from_utf8(domains).ok())
        .flat_map(|domains| {
            domains
                .split('|')
                .map(str::trim)
                .filter(|domain| !domain.is_empty())
                .map(|x| x.to_owned())
        })
        .fold(PrefixTree::default(), |mut acc, x| {
            acc.add(x);
            acc
        })
}

#[cfg(test)]
mod test {
    use super::parse_csv_dump;
    use anyhow::Result;

    #[test]
    fn csv_parse_test() -> Result<()> {
        env_logger::init();

        let dump = include_bytes!("../test/dump.csv");

        let parsed_domains = parse_csv_dump(dump);

        assert!(parsed_domains.contains("www.linkeddb.com"));
        assert!(parsed_domains.contains("www.linkedin.com"));
        assert!(parsed_domains.contains("ousportasdasdas.live"));
        assert!(parsed_domains.contains("tvrain.ru"));
        assert!(parsed_domains.contains("test.tvrain.ru"));
        assert!(!parsed_domains.contains("youtube.com"));
        Ok(())
    }
}
