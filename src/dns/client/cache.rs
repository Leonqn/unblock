use std::sync::{Arc, RwLock};

use crate::{
    cache::Cache,
    dns::message::{Query, Response},
};

use super::DnsClient;
use anyhow::Result;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};

#[derive(Clone)]
pub struct DnsCache {
    inner: Arc<RwLock<Cache<Bytes, (Bytes, String)>>>,
}

impl DnsCache {
    fn new(max_size: Option<usize>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Cache::new().with_max_size(max_size))),
        }
    }

    pub fn clear(&self) {
        self.inner.write().unwrap().clear();
    }
}

pub struct CachedClient<C> {
    inner_client: C,
    cache: DnsCache,
}

impl<C> CachedClient<C>
where
    C: DnsClient,
{
    pub fn new(dns_client: C, max_size: Option<usize>) -> (Self, DnsCache) {
        let cache = DnsCache::new(max_size);
        (
            Self {
                inner_client: dns_client,
                cache: cache.clone(),
            },
            cache,
        )
    }

    fn get_from_cache(&self, query: &Query) -> Option<Response> {
        let cache = self.cache.inner.read().unwrap();
        let (cached_bytes, cached_trace) = cache.get(&query.bytes().slice(2..))?;
        let mut response = BytesMut::from(cached_bytes.as_ref());
        response[0..2].copy_from_slice(&query.bytes()[0..2]);
        let mut response = Response::from_bytes(response.freeze()).expect("Must be valid response");
        response.append_trace(cached_trace);
        response.append_trace("cached");
        Some(response)
    }

    fn insert_to_cache(&self, query: &Query, response: &Response) -> Result<()> {
        let mut cache = self.cache.inner.write().unwrap();
        let ttl = response.parse()?.min_ttl();
        if let Some(ttl) = ttl {
            cache.insert(
                query.bytes().slice(2..),
                (response.bytes().clone(), response.trace().to_owned()),
                ttl,
            );
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
    async fn send(&self, query: Query) -> Result<Response> {
        match self.get_from_cache(&query) {
            Some(response) => Ok(response),
            None => {
                let response = self.inner_client.send(query.clone()).await?;
                self.insert_to_cache(&query, &response)?;
                Ok(response)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use crate::dns::{
        client::DnsClient,
        message::{Query, Response},
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use bytes::Bytes;

    use super::CachedClient;

    struct DnsMock {
        is_called: AtomicBool,
    }

    #[async_trait]
    impl DnsClient for DnsMock {
        async fn send(&self, _request: Query) -> anyhow::Result<Response> {
            if self
                .is_called
                .fetch_and(true, std::sync::atomic::Ordering::Relaxed)
            {
                panic!("Should not happen")
            } else {
                Response::from_bytes(Bytes::from_static(include_bytes!(
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
        let (cached, _) = CachedClient::new(dns_mock, None);
        let request = Query::from_bytes(Bytes::from_static(include_bytes!(
            "../../../test/dns_packets/q_api.browser.yandex.com.bin"
        )))?;
        cached.send(request.clone()).await?;

        let _cached_response = cached.send(request).await?;

        Ok(())
    }

    #[tokio::test]
    async fn should_change_id_of_cached_response() -> Result<()> {
        let dns_mock = DnsMock {
            is_called: AtomicBool::new(false),
        };
        let (cached, _) = CachedClient::new(dns_mock, None);
        let mut request_bytes =
            include_bytes!("../../../test/dns_packets/q_api.browser.yandex.com.bin").to_owned();
        request_bytes[0] = 5;
        let request = Query::from_bytes(Bytes::from(request_bytes.as_ref().to_owned()))?;
        cached.send(request.clone()).await?;

        let cached_response = cached.send(request).await?;

        assert_eq!(&cached_response.bytes().slice(0..2), &request_bytes[0..2]);
        Ok(())
    }
}
