use std::{collections::HashSet, net::IpAddr, net::Ipv4Addr, time::Duration};

use anyhow::{anyhow, Result};
use futures_util::{stream::Stream, TryStreamExt};
use log::{error, info};
use reqwest::{header::HeaderValue, Client, Response, StatusCode, Url};
use tokio::{
    io::{stream_reader, AsyncBufReadExt, BufReader},
    stream::StreamExt,
    time::delay_for,
};

pub async fn create_blacklists_stream(
    blacklist_url: Url,
    update_inverval: Duration,
) -> Result<impl Stream<Item = HashSet<Ipv4Addr>>> {
    let http = Client::builder().gzip(true).build()?;
    let initial_blacklist = get_blacklist(&http, blacklist_url.clone()).await?;

    let blacklists = futures_util::stream::unfold(
        (http, initial_blacklist.etag, blacklist_url),
        move |(http, etag, url)| async move {
            loop {
                delay_for(update_inverval).await;
                match update_blacklist(&http, url.clone(), etag.clone()).await {
                    Ok(Some(blacklist)) => {
                        info!(
                            "Received new blacklist with {} items",
                            blacklist.blacklist.len()
                        );
                        return Some((blacklist.blacklist, (http, blacklist.etag, url)));
                    }
                    Err(err) => {
                        error!("Got error while updating blacklist {:#}", err);
                    }
                    _ => {}
                }
            }
        },
    );
    Ok(tokio::stream::once(initial_blacklist.blacklist).chain(blacklists))
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

async fn update_blacklist(
    http: &Client,
    url: Url,
    etag: Option<HeaderValue>,
) -> Result<Option<Versioned>> {
    match etag {
        Some(etag) => try_get_new_blacklist(&http, url, etag).await,
        None => Ok(Some(get_blacklist(&http, url).await?)),
    }
}

async fn get_blacklist(http: &Client, url: Url) -> Result<Versioned> {
    Versioned::from_response(http.get(url).send().await?).await
}

async fn try_get_new_blacklist(
    http: &Client,
    url: Url,
    etag: HeaderValue,
) -> Result<Option<Versioned>> {
    let request = http.get(url).header("If-None-Match", etag);
    let response = request.send().await?;
    match response.status() {
        StatusCode::NOT_MODIFIED => Ok(None),
        StatusCode::OK => {
            let updated = Versioned::from_response(response).await?;
            Ok(Some(updated))
        }
        code => Err(anyhow!("unknown status code {}", code)),
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
                    _ => None,
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
    use super::parse_csv_dump;
    use anyhow::Result;
    use std::io::Cursor;

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
