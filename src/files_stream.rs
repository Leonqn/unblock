use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_compression::tokio::bufread::GzipDecoder;
use bytes::Bytes;
use futures_util::stream::{self, Stream};
use http_body_util::{BodyExt, Empty};
use hyper::header::HeaderValue;
use hyper::{Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use log::{error, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::sleep;
use url::Url;

type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

fn build_http_client() -> Result<HttpClient> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(30))
        .build(https);
    Ok(client)
}

pub fn create_files_stream(
    file_url: Url,
    update_inverval: Duration,
) -> Result<impl Stream<Item = Bytes>> {
    let http = build_http_client()?;
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
    http: &HttpClient,
    url: Url,
    etag: Option<HeaderValue>,
) -> Result<Option<(Option<HeaderValue>, Bytes)>> {
    let mut req_builder = Request::builder()
        .method(Method::GET)
        .uri(url.as_str())
        .header("Accept-Encoding", "gzip");
    if let Some(etag) = etag {
        req_builder = req_builder.header("If-None-Match", etag);
    }
    let req = req_builder.body(Empty::<Bytes>::new())?;
    let res = http.request(req).await?;

    match res.status().as_u16() {
        304 => Ok(None),
        200 => {
            let new_etag = res.headers().get("Etag").cloned();
            let is_gzip = is_gzip_encoded(res.headers());
            let body = res.into_body().collect().await?.to_bytes();
            let bytes = if is_gzip {
                decompress_gzip(body).await?
            } else {
                body
            };
            Ok(Some((new_etag, bytes)))
        }
        code => Err(anyhow!("unknown status code {}", code)),
    }
}

/// Creates a stream that downloads a file to disk using streaming (chunked) download.
/// Each stream item is the path to the downloaded file.
pub fn create_files_stream_to_disk(
    file_url: Url,
    update_interval: Duration,
    dest_path: PathBuf,
) -> Result<impl Stream<Item = PathBuf>> {
    let http = build_http_client()?;
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
    http: &HttpClient,
    url: Url,
    etag: Option<HeaderValue>,
    dest_path: &PathBuf,
) -> Result<Option<Option<HeaderValue>>> {
    let mut req_builder = Request::builder()
        .method(Method::GET)
        .uri(url.as_str())
        .header("Accept-Encoding", "gzip");
    if let Some(etag) = etag {
        req_builder = req_builder.header("If-None-Match", etag);
    }
    let req = req_builder.body(Empty::<Bytes>::new())?;
    let res = http.request(req).await?;

    match res.status().as_u16() {
        304 => Ok(None),
        200 => {
            let new_etag = res.headers().get("Etag").cloned();
            let is_gzip = is_gzip_encoded(res.headers());
            let tmp_path = dest_path.with_extension("tmp");
            let file = tokio::fs::File::create(&tmp_path).await?;
            let mut writer = tokio::io::BufWriter::new(file);

            if is_gzip {
                use futures_util::TryStreamExt;
                use http_body_util::BodyStream;
                use tokio_util::io::StreamReader;

                let body_stream = BodyStream::new(res.into_body())
                    .try_filter_map(|frame| async move { Ok(frame.into_data().ok()) })
                    .map_err(std::io::Error::other);
                let reader = StreamReader::new(body_stream);
                let mut decoder = Box::pin(GzipDecoder::new(BufReader::new(reader)));
                tokio::io::copy(&mut decoder, &mut writer).await?;
            } else {
                let mut body = res.into_body();
                while let Some(frame) = body.frame().await {
                    if let Ok(chunk) = frame?.into_data() {
                        writer.write_all(&chunk).await?;
                    }
                }
            }

            writer.flush().await?;
            drop(writer);
            tokio::fs::rename(&tmp_path, dest_path).await?;
            Ok(Some(new_etag))
        }
        code => Err(anyhow!("unknown status code {}", code)),
    }
}

fn is_gzip_encoded(headers: &hyper::HeaderMap) -> bool {
    headers
        .get("Content-Encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "gzip")
        .unwrap_or(false)
}

async fn decompress_gzip(data: Bytes) -> Result<Bytes> {
    let cursor = std::io::Cursor::new(data);
    let mut decoder = GzipDecoder::new(BufReader::new(cursor));
    let mut output = Vec::new();
    decoder.read_to_end(&mut output).await?;
    Ok(Bytes::from(output))
}
