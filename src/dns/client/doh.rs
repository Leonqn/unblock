use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use reqwest::{header::HeaderMap, header::HeaderValue, Client, Url};

use crate::dns::message::Message;

pub struct DohResponse {
    pub response: Bytes,
    pub age: Option<Duration>,
    pub cache_max_age: Option<Duration>,
}

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

    pub async fn send(&self, request: &[u8]) -> Result<DohResponse> {
        if request.len() < 12 {
            return Err(anyhow!("Bad dns packet"));
        }
        let without_id = &[[0u8, 0u8].as_ref(), &request[2..]].concat();
        let base_64_request = base64::encode_config(without_id, base64::STANDARD_NO_PAD);
        let request = self
            .http_client
            .get(self.server_url.clone())
            .query(&[("dns", base_64_request)]);
        let response = request.send().await?;
        let headers = response.headers();
        let age = headers
            .get("Age")
            .map(|age| age.to_str())
            .transpose()?
            .and_then(parse_age);
        let cache_max_age = headers
            .get("Cache-Control")
            .map(|c| c.to_str())
            .transpose()?
            .and_then(parse_cache_control);
        let response = response.bytes().await?;
        Ok(DohResponse {
            response,
            age,
            cache_max_age,
        })
    }
}

fn calculate_ttl(
    message: &Message,
    age: Option<Duration>,
    cache_max_age: Option<Duration>,
) -> Option<Duration> {
    match (cache_max_age, age) {
        (Some(max_age), _) => Some(max_age),
        (None, Some(age)) => Some(message.ttl()? - age),
        _ => message.ttl(),
    }
}

fn parse_age(age: &str) -> Option<Duration> {
    Some(Duration::from_secs(age.parse().ok()?))
}

fn parse_cache_control(cache_control: &str) -> Option<Duration> {
    let max_age = cache_control
        .split(',')
        .find(|s| s.trim().starts_with("max-age"))?
        .split('=')
        .last()?
        .parse()
        .ok()?;
    Some(Duration::from_secs(max_age))
}

#[cfg(test)]
mod tests {
    use crate::dns::message::Message;
    use anyhow::Result;
    use pretty_assertions::assert_eq;
    use std::time::Duration;

    use super::{parse_age, parse_cache_control, DohClient};

    #[test]
    fn test_parse_headers() {
        assert_eq!(
            Some(Duration::from_secs(10)),
            parse_cache_control("max-age=10")
        );
        assert_eq!(
            Some(Duration::from_secs(50)),
            parse_cache_control("private, max-age=50")
        );
        assert_eq!(None, parse_cache_control("private, "));
        assert_eq!(Some(Duration::from_secs(5)), parse_age("5"));
        assert_eq!(None, parse_age(""));
    }

    #[tokio::test]
    async fn test_google_doh_request() -> Result<()> {
        let request = include_bytes!("../../../test/dns_packets/q_api.browser.yandex.com.bin");
        let request_message = Message::from_packet(request.as_ref())?;
        let doh_client = DohClient::new("https://dns.google/dns-query".parse()?)?;

        let response = doh_client.send(request.as_ref()).await?;
        let message = Message::from_packet(&response.response)?;
        let ttl = message.ttl();

        assert_eq!(ttl, response.cache_max_age);
        assert_eq!(request_message.questions, message.questions);
        Ok(())
    }
}
