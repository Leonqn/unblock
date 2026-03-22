use anyhow::Result;

use crate::{
    dns::message::{Query, Response},
    prefix_tree::PrefixTree,
};

use super::DnsClient;
use async_trait::async_trait;

pub struct DomainRoutingClient<C> {
    routes: Vec<(PrefixTree, Box<dyn DnsClient>)>,
    default_client: C,
}

impl<C> DomainRoutingClient<C>
where
    C: DnsClient,
{
    pub fn new(routes: Vec<(PrefixTree, Box<dyn DnsClient>)>, default_client: C) -> Self {
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
            if domains.iter().any(|d| tree.contains(d)) {
                return client.send(query).await;
            }
        }
        self.default_client.send(query).await
    }
}
