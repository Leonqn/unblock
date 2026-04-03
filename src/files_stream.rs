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
use serde::{Deserialize, Serialize};
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

/// Cached headers for conditional requests, persisted as a `.meta` JSON sidecar file.
#[derive(Serialize, Deserialize, Default)]
struct CachedMeta {
    etag: Option<String>,
    last_modified: Option<String>,
}

impl CachedMeta {
    fn load(dest_path: &std::path::Path) -> Self {
        let meta_path = dest_path.with_extension("meta");
        std::fs::read_to_string(meta_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    async fn save(&self, dest_path: &std::path::Path) {
        let meta_path = dest_path.with_extension("meta");
        if let Ok(json) = serde_json::to_string(self) {
            let _ = tokio::fs::write(meta_path, json).await;
        }
    }
}

/// Creates a stream that downloads a file to disk using streaming (chunked) download.
/// Each stream item is the path to the downloaded file.
/// Uses ETag + Last-Modified headers for conditional requests, persisted in a `.meta` sidecar.
pub fn create_files_stream_to_disk(
    file_url: Url,
    update_interval: Duration,
    dest_path: PathBuf,
) -> Result<impl Stream<Item = PathBuf>> {
    let http = build_http_client()?;
    let cached_meta = CachedMeta::load(&dest_path);
    Ok(stream::unfold(
        (http, cached_meta, file_url, dest_path, true),
        move |(http, meta, url, dest_path, first_request)| async move {
            if !first_request {
                sleep(update_interval).await;
            }
            loop {
                info!("Checking {} for new version (disk mode)", url);
                match try_download_to_file(&http, url.clone(), &meta, &dest_path).await {
                    Ok(Some(new_meta)) => {
                        new_meta.save(&dest_path).await;
                        return Some((dest_path.clone(), (http, new_meta, url, dest_path, false)));
                    }
                    Ok(None) => {
                        if first_request && dest_path.exists() {
                            // File exists on disk from previous run, emit it
                            return Some((dest_path.clone(), (http, meta, url, dest_path, false)));
                        }
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
    meta: &CachedMeta,
    dest_path: &PathBuf,
) -> Result<Option<CachedMeta>> {
    let mut req_builder = Request::builder()
        .method(Method::GET)
        .uri(url.as_str())
        .header("Accept-Encoding", "gzip");
    if let Some(etag) = &meta.etag {
        req_builder = req_builder.header("If-None-Match", etag.as_str());
    }
    if let Some(last_modified) = &meta.last_modified {
        req_builder = req_builder.header("If-Modified-Since", last_modified.as_str());
    }
    let req = req_builder.body(Empty::<Bytes>::new())?;
    let res = http.request(req).await?;

    match res.status().as_u16() {
        304 => Ok(None),
        200 => {
            let new_meta = CachedMeta {
                etag: res
                    .headers()
                    .get("Etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_owned()),
                last_modified: res
                    .headers()
                    .get("Last-Modified")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_owned()),
            };
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
            Ok(Some(new_meta))
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
