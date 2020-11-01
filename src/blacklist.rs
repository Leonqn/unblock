use std::{collections::HashSet, future::Future, net::IpAddr, net::Ipv4Addr, time::Duration};

use anyhow::{anyhow, Result};
use futures_util::TryStreamExt;
use log::error;
use reqwest::{header::HeaderValue, Client, Response, StatusCode, Url};
use tokio::{
    io::{stream_reader, AsyncBufReadExt, BufReader},
    sync::mpsc::UnboundedSender,
    time::interval,
};

pub async fn create_blacklist_receiver(
    blacklist_sender: UnboundedSender<HashSet<Ipv4Addr>>,
    blacklist_url: Url,
    update_inverval: Duration,
) -> Result<impl Future<Output = ()>> {
    let http = Client::builder().gzip(true).build()?;
    let initial_blacklist = get_blacklist(&http, blacklist_url.clone()).await?;
    blacklist_sender
        .send(initial_blacklist.blacklist)
        .expect("Receiver dropped");
    let etag = initial_blacklist.etag;

    Ok(messages_handler(
        blacklist_sender,
        blacklist_url,
        update_inverval,
        http,
        etag,
    ))
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

async fn messages_handler(
    blacklist_sender: UnboundedSender<HashSet<Ipv4Addr>>,
    blacklist_url: Url,
    update_inverval: Duration,
    http: Client,
    mut etag: Option<HeaderValue>,
) {
    let mut interval = interval(update_inverval);
    interval.tick().await;

    loop {
        interval.tick().await;
        let handle_message = async {
            let maybe_new_blacklist = match &etag {
                Some(etag) => {
                    try_get_new_blacklist(&http, blacklist_url.clone(), etag.clone()).await?
                }
                None => Some(get_blacklist(&http, blacklist_url.clone()).await?),
            };

            if let Some(new_blacklist) = maybe_new_blacklist {
                etag = new_blacklist.etag;
                blacklist_sender
                    .send(new_blacklist.blacklist)
                    .expect("Receiver dropped");
            }
            Ok::<_, anyhow::Error>(())
        };

        if let Err(e) = handle_message.await {
            error!("Got error while handling dns message: {:#}", e);
        }
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
