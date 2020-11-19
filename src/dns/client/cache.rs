use crate::{cache::Cache, dns::message::Message};

use super::{DnsClient, DnsRequest, DnsResponse};
use anyhow::Result;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::sync::RwLock;

pub struct CachedClient<C> {
    inner_client: C,
    cache: RwLock<Cache<Bytes, Bytes>>,
}

impl<C> CachedClient<C>
where
    C: DnsClient,
{
    pub fn new(dns_client: C) -> Self {
        Self {
            inner_client: dns_client,
            cache: RwLock::new(Cache::new()),
        }
    }

    async fn get_from_cache(&self, request: &DnsRequest) -> Option<DnsResponse> {
        let cache = self.cache.read().await;
        let cached_response = cache.get(&request.bytes().slice(2..))?;
        let mut response = BytesMut::from(cached_response.as_ref());
        response[0..2].copy_from_slice(&request.bytes()[0..2]);
        Some(DnsResponse::from_bytes(response.freeze()).expect("Must be valid response"))
    }

    async fn insert_to_cache(&self, request: &DnsRequest, response: &DnsResponse) -> Result<()> {
        let mut cache = self.cache.write().await;
        let ttl = Message::from_packet(response.bytes())?.min_ttl();
        if let Some(ttl) = ttl {
            cache.insert(request.bytes().slice(2..), response.bytes().clone(), ttl);
            cache.remove_expired(3);
        }
        Ok(())
    }
}

#[async_trait]
impl<C> DnsClient for CachedClient<C>
where
    C: DnsClient,
{
    async fn send(&self, request: &DnsRequest) -> Result<DnsResponse> {
        match self.get_from_cache(&request).await {
            Some(response) => Ok(response),
            None => {
                let response = self.inner_client.send(&request).await?;
                self.insert_to_cache(&request, &response).await?;
                Ok(response)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use crate::dns::client::{DnsClient, DnsRequest, DnsResponse};
    use anyhow::Result;
    use async_trait::async_trait;
    use bytes::Bytes;

    use super::CachedClient;

    struct DnsMock {
        is_called: AtomicBool,
    }

    #[async_trait]
    impl DnsClient for DnsMock {
        async fn send(
            &self,
            _request: &crate::dns::client::DnsRequest,
        ) -> anyhow::Result<crate::dns::client::DnsResponse> {
            if self
                .is_called
                .fetch_and(true, std::sync::atomic::Ordering::Relaxed)
            {
                panic!("Should not happen")
            } else {
                DnsResponse::from_bytes(Bytes::from_static(include_bytes!(
                    "../../../test/dns_packets/a_api.browser.yandex.com.bin"
                )))
            }
        }
    }

    #[tokio::test]
    async fn should_cache_response() -> Result<()> {
        let dns_mock = DnsMock {
            is_called: AtomicBool::new(false),
        };
        let cached = CachedClient::new(dns_mock);
        let request = DnsRequest::from_bytes(Bytes::from_static(include_bytes!(
            "../../../test/dns_packets/q_api.browser.yandex.com.bin"
        )))?;
        cached.send(&request).await?;

        let _cached_response = cached.send(&request).await?;

        Ok(())
    }

    #[tokio::test]
    async fn should_change_id_of_cached_response() -> Result<()> {
        let dns_mock = DnsMock {
            is_called: AtomicBool::new(false),
        };
        let cached = CachedClient::new(dns_mock);
        let mut request_bytes =
            include_bytes!("../../../test/dns_packets/q_api.browser.yandex.com.bin").to_owned();
        request_bytes[0] = 5;
        let request = DnsRequest::from_bytes(Bytes::from(request_bytes.as_ref().to_owned()))?;
        cached.send(&request).await?;

        let cached_response = cached.send(&request).await?;

        assert_eq!(&cached_response.bytes().slice(0..2), &request_bytes[0..2]);
        Ok(())
    }
}
