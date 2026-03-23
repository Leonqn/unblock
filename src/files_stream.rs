use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_util::stream::{self, Stream};
use futures_util::StreamExt;
use log::{error, info};
use reqwest::{header::HeaderValue, Client, StatusCode, Url};
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;

pub fn create_files_stream(
    file_url: Url,
    update_inverval: Duration,
) -> Result<impl Stream<Item = Bytes>> {
    let http = Client::builder()
        .gzip(true)
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(30))
        .build()?;
    Ok(stream::unfold(
        (http, None, file_url, true),
        move |(http, etag, url, first_request)| async move {
            loop {
                info!("Checking {} for new version", url);
                match try_get_file(&http, url.clone(), etag.clone()).await {
                    Ok(Some((new_etag, body))) => {
                        if !first_request {
                            sleep(update_inverval).await;
                        }
                        return Some((body, (http, new_etag, url, false)));
                    }
                    Ok(None) => {
                        sleep(update_inverval).await;
                    }
                    Err(err) => {
                        error!(
                            "Error {:#} occured while downloading {}. Retrying",
                            err, url
                        );
                        sleep(Duration::from_secs(1)).await
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

/// Creates a stream that downloads a file to disk using streaming (chunked) download.
/// Each stream item is the path to the downloaded file.
/// Memory usage: ~chunk size (~64 KB) instead of full file in RAM.
pub fn create_files_stream_to_disk(
    file_url: Url,
    update_interval: Duration,
    dest_path: PathBuf,
) -> Result<impl Stream<Item = PathBuf>> {
    let http = Client::builder()
        .gzip(true)
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(30))
        .build()?;
    Ok(stream::unfold(
        (http, None, file_url, dest_path, true),
        move |(http, etag, url, dest_path, first_request)| async move {
            loop {
                info!("Checking {} for new version (disk mode)", url);
                match try_download_to_file(&http, url.clone(), etag.clone(), &dest_path).await {
                    Ok(Some(new_etag)) => {
                        if !first_request {
                            sleep(update_interval).await;
                        }
                        return Some((dest_path.clone(), (http, new_etag, url, dest_path, false)));
                    }
                    Ok(None) => {
                        sleep(update_interval).await;
                    }
                    Err(err) => {
                        error!(
                            "Error {:#} occurred while downloading {} to disk. Retrying",
                            err, url
                        );
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        },
    ))
}

async fn try_download_to_file(
    http: &Client,
    url: Url,
    etag: Option<HeaderValue>,
    dest_path: &PathBuf,
) -> Result<Option<Option<HeaderValue>>> {
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
            let tmp_path = dest_path.with_extension("tmp");
            let mut file = tokio::fs::File::create(&tmp_path).await?;
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            drop(file);
            tokio::fs::rename(&tmp_path, dest_path).await?;
            Ok(Some(etag))
        }
        code => Err(anyhow!("unknown status code {}", code)),
    }
}
