use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use url::Url;

use crate::dns::message::{Query, Response};

use super::DnsClient;

pub struct DohClient {
    http_client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>,
    server_url: Url,
}

impl DohClient {
    pub fn new(server_url: Url) -> Result<Self> {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()?
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        let http_client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(30))
            .build(https);
        Ok(Self { http_client, server_url })
    }
}

#[async_trait]
impl DnsClient for DohClient {
    async fn send(&self, query: Query) -> Result<Response> {
        let encoded = URL_SAFE_NO_PAD.encode(query.bytes().as_ref());
        let mut url = self.server_url.clone();
        url.query_pairs_mut().append_pair("dns", &encoded);

        let req = Request::builder()
            .method("GET")
            .uri(url.as_str())
            .header("Accept", "application/dns-message")
            .body(Empty::<Bytes>::new())?;

        let res = self.http_client.request(req).await?;
        if !res.status().is_success() {
            return Err(anyhow!("DoH request failed with status: {}", res.status()));
        }
        let body = res.into_body().collect().await?.to_bytes();
        Response::from_bytes(body)
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::client::{DnsClient, Query};
    use anyhow::Result;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;

    use super::DohClient;

    #[tokio::test]
    async fn test_google_doh_request() -> Result<()> {
        let request = Query::from_bytes(Bytes::from_static(include_bytes!(
            "../../../test/dns_packets/q_api.browser.yandex.com.bin"
        )))?;
        let request_message = request.parse()?;
        let doh_client = DohClient::new("https://dns.google/dns-query".parse()?)?;

        let response = doh_client.send(request.clone()).await?;
        let message = response.parse()?;

        assert_eq!(request_message.questions, message.questions);
        Ok(())
    }
}
