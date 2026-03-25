use std::sync::Arc;

use super::DnsClient;
use crate::{
    dns::message::{Query, Response},
    stats::StatsCollector,
};
use anyhow::Result;
use async_trait::async_trait;

pub struct StatsClient<C> {
    dns_client: C,
    stats: Arc<StatsCollector>,
}

impl<C> StatsClient<C> {
    pub fn new(dns_client: C, stats: Arc<StatsCollector>) -> Self {
        Self { dns_client, stats }
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for StatsClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        let sender = query.sender();
        let domain = query.parse().ok().and_then(|m| m.domains().next());
        let response = self.dns_client.send(query).await?;
        if let (Some(sender), Some(domain)) = (sender, domain) {
            self.stats
                .record(sender, domain, response.trace().to_owned());
        }
        Ok(response)
    }
}
