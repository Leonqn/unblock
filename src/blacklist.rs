use std::{collections::HashSet, net::IpAddr, net::Ipv4Addr, time::Duration};

use anyhow::Result;
use futures_util::stream::Stream;
use log::error;
use reqwest::Url;
use tokio_stream::StreamExt;

use crate::files_stream::create_files_stream;

pub fn blacklists(
    blacklist_url: Url,
    update_inverval: Duration,
) -> Result<impl Stream<Item = HashSet<Ipv4Addr>>> {
    Ok(create_files_stream(blacklist_url, update_inverval)?
        .map(|dump| parse_csv_dump(dump.as_ref())))
}

fn parse_csv_dump(dump: &[u8]) -> HashSet<Ipv4Addr> {
    dump.split(|b| *b == b'\n')
        .filter_map(|line| line.split(|b| *b == b';').next())
        .filter_map(|ips| match std::str::from_utf8(ips) {
            Ok(ips) => Some(ips),
            Err(err) => {
                error!("Ips contain non-utf8 symbols. Err: {:#}", err);
                None
            }
        })
        .flat_map(|ips| {
            ips.split('|')
                .map(str::trim)
                .filter(|ip| !ip.is_empty())
                .filter_map(|ip| match ip.parse() {
                    Ok(IpAddr::V4(addr)) => Some(addr),
                    _ => None,
                })
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::parse_csv_dump;
    use anyhow::Result;

    #[test]
    fn csv_parse_test() -> Result<()> {
        env_logger::init();

        let dump = include_bytes!("../test/dump.csv");

        let parsed_ips = parse_csv_dump(dump);

        assert!(parsed_ips.contains(&"1.179.201.18".parse()?));
        assert!(parsed_ips.contains(&"104.16.61.11".parse()?));
        assert!(parsed_ips.contains(&"172.67.136.125".parse()?));
        Ok(())
    }
}
