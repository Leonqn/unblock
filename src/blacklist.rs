use std::{collections::HashSet, net::IpAddr, net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use futures_util::{StreamExt, TryStreamExt};
use log::{error, info, warn};
use reqwest::{header::HeaderValue, Client, Response, StatusCode, Url};
use tokio::{
    io::{stream_reader, AsyncBufReadExt, BufReader},
    time::interval,
};

pub struct Blacklist {
    http: Client,
    url: Url,
    blacklist: ArcSwap<Versioned>,
}

struct Versioned {
    etag: Option<HeaderValue>,
    blacklist: HashSet<Ipv4Addr>,
}

impl Versioned {
    async fn from_response(response: Response) -> Result<Self> {
        let etag = response.headers().get("Etag").cloned();
        let buf_reader =
            BufReader::new(stream_reader(response.bytes_stream().map_err(|err| {
                tokio::io::Error::new(tokio::io::ErrorKind::Other, err)
            })));
        Ok(Versioned {
            etag,
            blacklist: parse_csv_dump(buf_reader).await?,
        })
    }
}

impl Blacklist {
    pub async fn new(url: Url) -> Result<Self> {
        let http = Client::builder().gzip(true).build()?;
        let blacklist = Versioned::from_response(http.get(url.clone()).send().await?).await?;
        Ok(Self {
            http,
            url,
            blacklist: ArcSwap::new(Arc::new(blacklist)),
        })
    }

    pub async fn start_updating(&self, update_interval: Duration) {
        let mut interval = Box::pin(interval(update_interval));
        interval.next().await;
        loop {
            interval.next().await;
            info!("Start updating blacklist");
            if let Err(err) = self.update_if_needed().await {
                error!("Error occurred while updating blacklist: {}", err);
            }
        }
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        self.blacklist.load().blacklist.contains(&addr)
    }

    async fn update_if_needed(&self) -> Result<()> {
        let request = if let Some(etag) = &self.blacklist.load().etag {
            self.http
                .get(self.url.clone())
                .header("If-None-Match", etag)
        } else {
            self.http.get(self.url.clone())
        };
        let response = request.send().await?;
        match response.status() {
            StatusCode::NOT_MODIFIED => {
                info!("Blacklist not modified");
                Ok(())
            }
            StatusCode::OK => {
                let updated = Versioned::from_response(response).await?;
                info!(
                    "Updated to version {:?} with {} items",
                    updated.etag,
                    updated.blacklist.len()
                );
                self.blacklist.store(Arc::new(updated));
                Ok(())
            }
            code => Err(anyhow!("unknown status code {}", code)),
        }
    }
}

async fn parse_csv_dump<ABR: AsyncBufReadExt + Unpin>(
    mut buf_reader: ABR,
) -> Result<HashSet<Ipv4Addr>> {
    let mut parsed_ips = HashSet::new();
    let mut ips = Vec::new();
    buf_reader.read_until(0xA, &mut ips).await?;
    ips.clear();
    loop {
        buf_reader.read_until(b';', &mut ips).await?;
        if let [ips @ .., _] = ips.as_slice() {
            std::str::from_utf8(&ips)?
                .split('|')
                .map(str::trim)
                .filter(|ip| !ip.is_empty())
                .filter_map(|ip| match ip.parse() {
                    Ok(IpAddr::V4(addr)) => Some(addr),
                    Ok(IpAddr::V6(_)) => None,
                    Err(err) => {
                        warn!("ip parsing error. not_ip: {}, error: {}", ip, err);
                        None
                    }
                })
                .for_each(|ip| {
                    parsed_ips.insert(ip);
                });
        } else {
            return Ok(parsed_ips);
        }
        buf_reader.read_until(0xA, &mut ips).await?;
        ips.clear();
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::parse_csv_dump;
    use anyhow::Result;

    #[tokio::test]
    async fn csv_parse_test() -> Result<()> {
        env_logger::init();

        let dump = include_bytes!("../test/dump.csv");
        let cursor = Cursor::new(dump);

        let parsed_ips = parse_csv_dump(cursor).await?;

        assert!(parsed_ips.contains(&"1.179.201.18".parse()?));
        assert!(parsed_ips.contains(&"104.16.61.11".parse()?));
        assert!(parsed_ips.contains(&"172.67.136.125".parse()?));
        Ok(())
    }
}
