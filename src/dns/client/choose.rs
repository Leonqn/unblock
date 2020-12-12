use anyhow::Result;
use std::collections::HashSet;

use crate::dns::message::{Query, Response};

use super::DnsClient;
use async_trait::async_trait;

pub struct ChooseClient<C1, C2> {
    first: C1,
    second: C2,
    through_first_domains: HashSet<String>,
}

impl<C1, C2> ChooseClient<C1, C2>
where
    C1: DnsClient,
    C2: DnsClient,
{
    pub fn new(first: C1, second: C2, through_first_domains: HashSet<String>) -> Self {
        Self {
            first,
            second,
            through_first_domains,
        }
    }
}

#[async_trait]
impl<C1, C2> DnsClient for ChooseClient<C1, C2>
where
    C1: DnsClient,
    C2: DnsClient,
{
    async fn send(&self, query: Query) -> Result<Response> {
        let through_first = query
            .parse()?
            .domains()
            .map(|d| d.join("."))
            .any(|d| self.through_first_domains.contains(&d));
        if through_first {
            self.first.send(query).await
        } else {
            self.second.send(query).await
        }
    }
}
