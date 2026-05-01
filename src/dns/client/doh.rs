use std::net::Ipv4Addr;
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
use log::info;
use url::Url;

use crate::dns::message::{Query, Response};

use super::DnsClient;

pub struct DohClient {
    http_client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>,
    server_url: Url,
    ecs_override_ip: Ipv4Addr,
}

impl DohClient {
    pub fn new(server_url: Url, ecs_override_ip: Ipv4Addr) -> Result<Self> {
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
        Ok(Self {
            http_client,
            server_url,
            ecs_override_ip,
        })
    }

    async fn do_request(&self, query: &Query) -> Result<Response> {
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
        let mut response = Response::from_bytes(body)?;
        response.append_trace(self.server_url.as_str());
        Ok(response)
    }
}

#[async_trait]
impl DnsClient for DohClient {
    async fn send(&self, query: Query) -> Result<Response> {
        let response = self.do_request(&query).await?;
        if response.has_loopback() {
            let domains = query
                .parse()
                .map(|m| m.domains().collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            info!(
                "Got loopback for {}, retrying with ECS override {}",
                domains, self.ecs_override_ip
            );
            let query_ecs = query.with_ecs(self.ecs_override_ip);
            let mut retry_response = self.do_request(&query_ecs).await?;
            retry_response.append_trace("ecs-override-retry");
            if retry_response.has_loopback() {
                return Err(anyhow!(
                    "DoH still returned loopback for {} after ECS override",
                    domains
                ));
            }
            return Ok(retry_response);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

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
        let doh_client = DohClient::new(
            "https://dns.google/dns-query".parse()?,
            Ipv4Addr::new(185, 76, 151, 0),
        )?;

        let response = doh_client.send(request.clone()).await?;
        let message = response.parse()?;

        assert_eq!(request_message.questions, message.questions);
        Ok(())
    }
}
