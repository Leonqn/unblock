use super::DnsClient;
use crate::{
    dns::{
        message::{Query, Response},
        metrics::PerDomainCounter,
    },
    unblock::{UnblockResponse, Unblocker},
};
use anyhow::Result;
use async_trait::async_trait;
use once_cell::sync::Lazy;

pub struct UnblockClient<C> {
    client: C,
    unblocker: Unblocker,
}

impl<C> UnblockClient<C> {
    pub fn new(client: C, unblocker: Unblocker) -> Self {
        Self { client, unblocker }
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for UnblockClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        let dns_response = self.client.send(query).await?;
        let parsed_response = dns_response.parse()?;
        let unblocked = self
            .unblocker
            .unblock(&parsed_response.ips().collect::<Vec<_>>())
            .await?;
        if let UnblockResponse::Unblocked(_) = unblocked {
            for domain in parsed_response.domains() {
                METRICS.unblocked.inc(&domain);
            }
        }
        Ok(dns_response)
    }
}

static METRICS: Lazy<Metrics> = Lazy::new(|| Metrics::new());

struct Metrics {
    unblocked: PerDomainCounter,
}

impl Metrics {
    fn new() -> Self {
        Self {
            unblocked: PerDomainCounter::new("requests_unblocked"),
        }
    }
}
