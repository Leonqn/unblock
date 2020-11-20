use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use reqwest::{header::HeaderMap, header::HeaderValue, Client, Url};

use crate::dns::message::{Query, Response};

use super::DnsClient;

pub struct DohClient {
    http_client: Client,
    server_url: Url,
}

impl DohClient {
    pub fn new(server_url: Url) -> Result<Self> {
        let mut headers = HeaderMap::with_capacity(2);
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/dns-message"),
        );
        headers.insert(
            "Content-Type",
            HeaderValue::from_static("application/dns-message"),
        );
        let http_client = Client::builder()
            .use_rustls_tls()
            .http2_prior_knowledge()
            .default_headers(headers)
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
        let mut request_buf = BytesMut::from(query.bytes().as_ref());
        request_buf[0..2].copy_from_slice([0, 0].as_ref());
        let base_64_request = base64::encode_config(request_buf, base64::STANDARD_NO_PAD);
        let request = self
            .http_client
            .get(self.server_url.clone())
            .query(&[("dns", base_64_request)]);
        let response = request.send().await?;
        let response = response.bytes().await?;
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
