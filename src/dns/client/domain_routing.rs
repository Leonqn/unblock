use anyhow::Result;

use crate::{
    blacklist::DomainHashSet,
    dns::message::{Query, Response},
};

use super::DnsClient;
use async_trait::async_trait;

pub struct DomainRoutingClient<C> {
    routes: Vec<(DomainHashSet, Box<dyn DnsClient>)>,
    default_client: C,
}

impl<C> DomainRoutingClient<C>
where
    C: DnsClient,
{
    pub fn new(routes: Vec<(DomainHashSet, Box<dyn DnsClient>)>, default_client: C) -> Self {
        Self {
            routes,
            default_client,
        }
    }
}

#[async_trait]
impl<C> DnsClient for DomainRoutingClient<C>
where
    C: DnsClient,
{
    async fn send(&self, query: Query) -> Result<Response> {
        let domains: Vec<String> = query.parse()?.domains().collect();
        for (tree, client) in &self.routes {
            if let Some(domain) = domains.iter().find(|d| tree.contains(d)) {
                let mut response = client.send(query).await?;
                response.append_trace(&format!("route: {}", domain));
                return Ok(response);
            }
        }
        let mut response = self.default_client.send(query).await?;
        response.append_trace("route: default");
        Ok(response)
    }
}
