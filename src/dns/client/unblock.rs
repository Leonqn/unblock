use super::DnsClient;
use crate::{
    dns::message::{Query, Response},
    unblock::{UnblockResponse, Unblocker},
};
use anyhow::Result;
use async_trait::async_trait;
use log::info;

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
        if let UnblockResponse::Unblocked(ips) = unblocked {
            info!(
                "Ips {:?} for domains {:?} were unblocked",
                ips,
                parsed_response.domains().collect::<Vec<_>>()
            )
        }
        Ok(dns_response)
    }
}
