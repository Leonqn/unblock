use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use arc_swap::ArcSwapOption;

use super::DnsClient;
use crate::{
    blacklist::Blacklist,
    dns::message::{Message, Query, Response},
    domains_filter::DomainsFilter,
    last_item::LastItem,
    reroute::{RerouteResponse, Rerouter},
};
use anyhow::Result;
use async_trait::async_trait;
use log::info;

pub struct RerouteClient<C> {
    client: C,
    rerouter: Rerouter,
    manual_dns_whitelist: Arc<ArcSwapOption<DomainsFilter>>,
    manual_ip_whitelist: HashSet<Ipv4Addr>,
    blacklists: Vec<LastItem<Box<dyn Blacklist>>>,
}

impl<C> RerouteClient<C> {
    pub fn new(
        client: C,
        rerouter: Rerouter,
        manual_dns_whitelist: Arc<ArcSwapOption<DomainsFilter>>,
        manual_ip_whitelist: HashSet<Ipv4Addr>,
        blacklists: Vec<LastItem<Box<dyn Blacklist>>>,
    ) -> Self {
        Self {
            client,
            rerouter,
            manual_dns_whitelist,
            manual_ip_whitelist,
            blacklists,
        }
    }

    fn get_blocked<'a>(
        &'a self,
        parsed_response: &'a Message<'a>,
    ) -> impl Iterator<Item = Ipv4Addr> + 'a {
        let filter = self.manual_dns_whitelist.load();
        let manual_dns_signals: Vec<bool> = match filter.as_deref() {
            Some(f) => parsed_response
                .domains()
                .filter_map(|d| f.match_domain(&d).map(|m| m.is_allowed()))
                .collect(),
            None => vec![],
        };

        let ipv4s = |msg: &'a Message<'a>| {
            msg.ips().filter_map(|ip| {
                if let IpAddr::V4(v4) = ip {
                    Some(v4)
                } else {
                    None
                }
            })
        };

        let blacklisted = parsed_response
            .domains()
            .any(|domain| is_blacklisted(&domain, &self.blacklists, &manual_dns_signals))
            .then(|| ipv4s(parsed_response))
            .into_iter()
            .flatten();
        let manual_ips =
            ipv4s(parsed_response).filter(move |ip| self.manual_ip_whitelist.contains(ip));
        blacklisted.chain(manual_ips)
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for RerouteClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        let mut dns_response = self.client.send(query).await?;
        let parsed_response = dns_response.parse()?;
        let blocked = self.get_blocked(&parsed_response);
        let domains = parsed_response
            .domains()
            .reduce(|acc, x| acc + "/" + &x)
            .unwrap_or_else(|| "empty".to_owned());
        let blocked_ips: Vec<Ipv4Addr> = blocked.collect();
        if blocked_ips.is_empty() {
            dns_response.append_trace("not blacklisted");
        } else {
            let ips_str = blocked_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let rerouted = self.rerouter.reroute(blocked_ips, &domains).await?;
            match rerouted {
                RerouteResponse::Rerouted(_) => {
                    for domain in parsed_response.domains() {
                        info!("domain {} rerouted", domain);
                    }
                    dns_response.append_trace(&format!("blacklisted [{}] → routed", ips_str));
                }
                RerouteResponse::Skipped => {
                    dns_response
                        .append_trace(&format!("blacklisted [{}] → already routed", ips_str));
                }
            }
        }

        Ok(dns_response)
    }
}

fn is_blacklisted(
    domain: &str,
    blacklists: &[LastItem<Box<dyn Blacklist>>],
    filter_signals: &[bool],
) -> bool {
    if filter_signals.iter().any(|&is_allowed| is_allowed) {
        return true;
    }
    if filter_signals.iter().any(|&is_allowed| !is_allowed) {
        return false;
    }
    blacklists
        .iter()
        .filter_map(|b| b.item())
        .any(|bl| bl.contains(domain))
}
