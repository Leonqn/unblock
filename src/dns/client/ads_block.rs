use super::DnsClient;
use crate::{
    dns::message::{Query, Response},
    domains_filter::DomainsFilter,
    last_item::LastItem,
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::stream::Stream;
use log::info;

pub struct AdsBlockClient<C> {
    dns_client: C,
    domains_filter: LastItem<DomainsFilter>,
}

impl<C> AdsBlockClient<C> {
    pub fn new(dns_client: C, filters: impl Stream<Item = DomainsFilter> + Send + 'static) -> Self {
        let domains_filter = LastItem::new(filters);

        Self {
            dns_client,
            domains_filter,
        }
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for AdsBlockClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        let parsed_query = query.parse()?;
        let domains_filter = self.domains_filter.item();
        let match_result = parsed_query.domains().find_map(|domain| {
            domains_filter
                .as_ref()
                .and_then(|filter| Some((filter.match_domain(&domain)?, domain)))
        });
        match match_result {
            Some((match_result, domain)) if !match_result.is_allowed => {
                info!("Domain {} blocked by rule {:}", domain, match_result.rule);
                let mut blocked_resp = BytesMut::from(query.bytes().as_ref());
                blocked_resp[2] = 0x81;
                blocked_resp[3] = 0x83;
                Response::from_bytes(blocked_resp.freeze())
            }
            _ => self.dns_client.send(query).await,
        }
    }
}
