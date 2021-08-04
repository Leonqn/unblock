use std::collections::HashSet;

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
    manual_whitelist: HashSet<String>,
}

impl<C> UnblockClient<C> {
    pub fn new(client: C, unblocker: Unblocker, manual_whitelist: HashSet<String>) -> Self {
        Self {
            client,
            unblocker,
            manual_whitelist,
        }
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for UnblockClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        let dns_response = self.client.send(query).await?;
        let parsed_response = dns_response.parse()?;
        let ips = parsed_response.ips().collect::<Vec<_>>();
        let unblocked = if parsed_response
            .domains()
            .any(|x| self.manual_whitelist.contains(&x))
        {
            self.unblocker.unblock(ips).await?
        } else {
            self.unblocker.unblock_blocked(&ips).await?
        };
        if let UnblockResponse::Unblocked(_) = unblocked {
            for domain in parsed_response.domains() {
                info!("domain {} unblocked", domain);
            }
        }
        Ok(dns_response)
    }
}
