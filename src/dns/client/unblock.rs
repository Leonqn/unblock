use std::{collections::HashSet, net::Ipv4Addr};

use super::DnsClient;
use crate::{
    dns::message::{Message, Query, Response},
    last_item::LastItem,
    unblock::{UnblockResponse, Unblocker},
};
use anyhow::Result;
use async_trait::async_trait;
use futures_util::Stream;
use log::info;

pub struct UnblockClient<C> {
    client: C,
    unblocker: Unblocker,
    manual_dns_whitelist: HashSet<String>,
    manual_ip_whitelist: HashSet<Ipv4Addr>,
    blacklist: LastItem<HashSet<Ipv4Addr>>,
}

impl<C> UnblockClient<C> {
    pub fn new(
        client: C,
        unblocker: Unblocker,
        manual_dns_whitelist: HashSet<String>,
        manual_ip_whitelist: HashSet<Ipv4Addr>,
        blacklist: impl Stream<Item = HashSet<Ipv4Addr>> + Send + 'static,
    ) -> Self {
        let blacklist = LastItem::new(blacklist);
        Self {
            client,
            unblocker,
            manual_dns_whitelist,
            manual_ip_whitelist,
            blacklist,
        }
    }

    fn get_blocked<'a>(
        &'a self,
        parsed_response: &'a Message<'a>,
    ) -> impl Iterator<Item = Ipv4Addr> + 'a {
        let blacklist = self.blacklist.item();
        let blacklisted = blacklist
            .map(|blacklist| {
                parsed_response
                    .ips()
                    .filter(move |ip| blacklist.contains(ip))
            })
            .into_iter()
            .flatten();
        let manual_ips = parsed_response
            .ips()
            .filter(move |ip| self.manual_ip_whitelist.contains(ip));
        let manual_dns = parsed_response
            .domains()
            .any(|x| self.manual_dns_whitelist.contains(&x))
            .then(|| parsed_response.ips())
            .into_iter()
            .flatten();

        blacklisted.chain(manual_ips).chain(manual_dns)
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for UnblockClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        let dns_response = self.client.send(query).await?;
        let parsed_response = dns_response.parse()?;
        let blocked = self.get_blocked(&parsed_response);
        let unblocked = self.unblocker.unblock(blocked).await?;
        if let UnblockResponse::Unblocked(_) = unblocked {
            for domain in parsed_response.domains() {
                info!("domain {} unblocked", domain);
            }
        }

        Ok(dns_response)
    }
}
