use std::{collections::HashSet, net::Ipv4Addr, pin::Pin};

use super::DnsClient;
use crate::{
    dns::message::{Message, Query, Response},
    domains_filter::{DomainsFilter, MatchResult},
    last_item::LastItem,
    prefix_tree::PrefixTree,
    unblock::{UnblockResponse, Unblocker},
};
use anyhow::Result;
use async_trait::async_trait;
use futures_util::Stream;
use log::info;

pub struct UnblockClient<C> {
    client: C,
    unblocker: Unblocker,
    manual_dns_whitelist: DomainsFilter,
    manual_ip_whitelist: HashSet<Ipv4Addr>,
    blacklists: Vec<LastItem<PrefixTree>>,
}

impl<C> UnblockClient<C> {
    pub fn new(
        client: C,
        unblocker: Unblocker,
        manual_dns_whitelist: DomainsFilter,
        manual_ip_whitelist: HashSet<Ipv4Addr>,
        blacklists: Vec<Pin<Box<dyn Stream<Item = PrefixTree> + Send>>>,
    ) -> Self {
        let blacklists = blacklists.into_iter().map(LastItem::new).collect();
        Self {
            client,
            unblocker,
            manual_dns_whitelist,
            manual_ip_whitelist,
            blacklists,
        }
    }

    fn get_blocked<'a>(
        &'a self,
        parsed_response: &'a Message<'a>,
    ) -> impl Iterator<Item = Ipv4Addr> + 'a {
        let manual_dns_list = parsed_response
            .domains()
            .filter_map(|d| self.manual_dns_whitelist.match_domain(&d))
            .collect::<Vec<_>>();

        let blacklisted = parsed_response
            .domains()
            .any(|domain| is_blacklisted(&domain, &self.blacklists, &manual_dns_list))
            .then(|| parsed_response.ips())
            .into_iter()
            .flatten();
        let manual_ips = parsed_response
            .ips()
            .filter(move |ip| self.manual_ip_whitelist.contains(ip));
        blacklisted.chain(manual_ips)
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for UnblockClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        let dns_response = self.client.send(query).await?;
        let parsed_response = dns_response.parse()?;
        let blocked = self.get_blocked(&parsed_response);
        let domains = parsed_response
            .domains()
            .reduce(|acc, x| acc + "/" + &x)
            .unwrap_or_else(|| "empty".to_owned());
        let unblocked = self.unblocker.unblock(blocked, &domains).await?;
        if let UnblockResponse::Unblocked(_) = unblocked {
            for domain in parsed_response.domains() {
                info!("domain {} unblocked", domain);
            }
        }

        Ok(dns_response)
    }
}

fn is_blacklisted(
    domain: &str,
    blacklists: &[LastItem<PrefixTree>],
    filter: &[MatchResult],
) -> bool {
    if filter.iter().any(|m| m.is_allowed) {
        return true;
    }
    if filter.iter().any(|m| !m.is_allowed) {
        return false;
    }
    blacklists
        .iter()
        .filter_map(|b| b.item())
        .any(|bl| bl.contains(domain))
}
