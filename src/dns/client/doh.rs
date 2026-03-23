use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::{header::HeaderMap, header::HeaderValue, Client, Url};

use crate::dns::message::{Query, Response};

use super::DnsClient;

pub struct DohClient {
    http_client: Client,
    server_url: Url,
}

impl DohClient {
    pub fn new(server_url: Url) -> Result<Self> {
        let mut headers = HeaderMap::with_capacity(1);
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/dns-message"),
        );
        let http_client = Client::builder()
            .use_rustls_tls()
            .default_headers(headers)
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http_client,
            server_url,
        })
    }
}

#[async_trait]
impl DnsClient for DohClient {
    async fn send(&self, query: Query) -> Result<Response> {
        let encoded = URL_SAFE_NO_PAD.encode(query.bytes().as_ref());
        let mut url = self.server_url.clone();
        url.query_pairs_mut().append_pair("dns", &encoded);
        let response = self
            .http_client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        Response::from_bytes(response)
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
