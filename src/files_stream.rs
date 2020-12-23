use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_util::stream::{self, Stream};
use log::error;
use reqwest::{header::HeaderValue, Client, StatusCode, Url};
use tokio::time::delay_for;

pub fn create_files_stream(
    file_url: Url,
    update_inverval: Duration,
) -> Result<impl Stream<Item = Bytes>> {
    let http = Client::builder().gzip(true).build()?;
    Ok(stream::unfold(
        (http, None, file_url, true),
        move |(http, etag, url, first_request)| async move {
            loop {
                match try_get_file(&http, url.clone(), etag.clone()).await {
                    Ok(Some((new_etag, body))) => {
                        if !first_request {
                            delay_for(update_inverval).await;
                        }
                        return Some((body, (http, new_etag, url, false)));
                    }
                    Ok(None) => {
                        delay_for(update_inverval).await;
                    }
                    Err(err) => {
                        error!(
                            "Error {:#} occured while downloading {}. Retrying",
                            err, url
                        );
                        delay_for(Duration::from_secs(1)).await
                    }
                }
            }
        },
    ))
}

async fn try_get_file(
    http: &Client,
    url: Url,
    etag: Option<HeaderValue>,
) -> Result<Option<(Option<HeaderValue>, Bytes)>> {
    let request = if let Some(etag) = etag {
        http.get(url).header("If-None-Match", etag)
    } else {
        http.get(url)
    };
    let response = request.send().await?;
    match response.status() {
        StatusCode::NOT_MODIFIED => Ok(None),
        StatusCode::OK => {
            let etag = response.headers().get("Etag").cloned();
            let bytes = response.bytes().await?;
            Ok(Some((etag, bytes)))
        }
        code => Err(anyhow!("unknown status code {}", code)),
    }
}
