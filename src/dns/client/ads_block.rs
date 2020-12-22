use std::sync::Arc;

use super::DnsClient;
use crate::{
    ads_filter::DomainsFilter,
    dns::message::{Query, Response},
};
use anyhow::Result;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::stream::Stream;
use tokio::stream::StreamExt;

pub struct AdsBlockClient<C> {
    dns_client: C,
    domains_filter: Arc<ArcSwapOption<DomainsFilter>>,
}

impl<C> AdsBlockClient<C> {
    pub fn new(
        dns_client: C,
        filter_stream: impl Stream<Item = DomainsFilter> + Send + 'static,
    ) -> Self {
        let mut filter_stream = Box::pin(filter_stream);
        let domains_filter = Arc::new(ArcSwapOption::empty());
        tokio::spawn({
            let domains_filter = domains_filter.clone();
            async move {
                while let Some(filter) = filter_stream.next().await {
                    domains_filter.store(Some(Arc::new(filter)));
                }
            }
        });

        Self {
            dns_client,
            domains_filter,
        }
    }

    fn is_blocked(&self, domain: &str) -> bool {
        self.domains_filter
            .load()
            .as_ref()
            .and_then(|x| x.match_domain(domain))
            .map_or(false, |x| !x.is_allowed)
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for AdsBlockClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        let parsed_query = query.parse()?;
        if parsed_query.domains().any(|x| self.is_blocked(&x)) {
            let mut blocked_resp = BytesMut::from(query.bytes().as_ref());
            blocked_resp[2] = 0x81;
            blocked_resp[3] = 0x83;
            Response::from_bytes(blocked_resp.freeze())
        } else {
            self.dns_client.send(query).await
        }
    }
}
