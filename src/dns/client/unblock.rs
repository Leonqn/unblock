use super::DnsClient;
use crate::{
    dns::message::{Query, Response},
    unblock::Unblocker,
};
use anyhow::Result;
use async_trait::async_trait;

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
        self.unblocker
            .unblock(parsed_response.ips().collect())
            .await?;
        Ok(dns_response)
    }
}
