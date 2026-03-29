use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use log::{error, info};
use serde::{Deserialize, Serialize};

const GITHUB_REPO: Option<&str> = option_env!("GITHUB_REPOSITORY");

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

#[derive(Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    pub name: Option<String>,
    pub assets: Vec<AssetInfo>,
}

#[derive(Serialize, Deserialize)]
pub struct AssetInfo {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
}

fn build_client() -> Result<HttpsClient> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(https))
}

pub async fn check_latest_release() -> Result<ReleaseInfo> {
    let repo = GITHUB_REPO
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("GitHub repository not configured"))?;

    let client = build_client()?;

    let url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let req = Request::builder()
        .method("GET")
        .uri(&url)
        .header("User-Agent", "reroute-updater")
        .body(Empty::<Bytes>::new())?;

    let res = client.request(req).await?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.into_body().collect().await?.to_bytes();
        let text = String::from_utf8_lossy(&body);
        return Err(anyhow!("GitHub API error {}: {}", status, text));
    }

    let body = res.into_body().collect().await?.to_bytes();
    let mut release: ReleaseInfo = serde_json::from_slice(&body)?;
    release.assets.retain(|a| a.name.starts_with("reroute-"));
    Ok(release)
}

pub async fn apply_update(download_url: &str) -> Result<()> {
    let client = build_client()?;

    let binary_data = download_following_redirects(&client, download_url).await?;

    info!("Downloaded update binary: {} bytes", binary_data.len());

    let current_exe = std::env::current_exe()?;
    let exe_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow!("Cannot determine executable directory"))?;

    let tmp_path = exe_dir.join(".reroute.update.tmp");
    tokio::fs::write(&tmp_path, &binary_data).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&tmp_path, perms)?;
    }

    std::fs::rename(&tmp_path, &current_exe)?;

    info!("Binary replaced successfully, restarting service...");

    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let result = std::process::Command::new("sh")
            .arg("-c")
            .arg("/opt/etc/init.d/S99reroute restart")
            .spawn();
        if let Err(e) = result {
            error!("Failed to restart service: {}", e);
        }
    });

    Ok(())
}

async fn download_following_redirects(client: &HttpsClient, url: &str) -> Result<Bytes> {
    let mut current_url = url.to_string();
    for _ in 0..5 {
        let req = Request::builder()
            .method("GET")
            .uri(&current_url)
            .header("User-Agent", "reroute-updater")
            .body(Empty::<Bytes>::new())?;

        let res = client.request(req).await?;
        let status = res.status();

        if status.is_redirection() {
            let location = res
                .headers()
                .get("location")
                .ok_or_else(|| anyhow!("Redirect without Location header"))?
                .to_str()?
                .to_string();
            info!("Following redirect to: {}", location);
            let _ = res.into_body().collect().await?;
            current_url = location;
            continue;
        }

        if !status.is_success() {
            let body = res.into_body().collect().await?.to_bytes();
            let text = String::from_utf8_lossy(&body);
            return Err(anyhow!("Download failed with status {}: {}", status, text));
        }

        let body = res.into_body().collect().await?.to_bytes();
        return Ok(body);
    }
    Err(anyhow!("Too many redirects"))
}
