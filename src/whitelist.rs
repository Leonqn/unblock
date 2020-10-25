use std::{collections::HashSet, net::Ipv4Addr, sync::Arc};

use crate::{blacklist::Blacklist, router_client::RouterClient};
use anyhow::Result;

pub struct Whitelist {
    blacklist: Arc<Blacklist>,
    router_client: Arc<RouterClient>,
    whitelisted: HashSet<Ipv4Addr>,
}

impl Whitelist {
    pub async fn new(blacklist: Arc<Blacklist>, router_client: Arc<RouterClient>) -> Result<Self> {
        let routed = router_client.get_routed().await?;
        Ok(Self {
            blacklist,
            router_client,
            whitelisted: routed,
        })
    }

    pub async fn whitelist(&mut self, ips: &[Ipv4Addr]) -> Result<Vec<Ipv4Addr>> {
        let need_whitelist = ips
            .iter()
            .filter(|ip| self.blacklist.contains(**ip) && !self.whitelisted.contains(ip))
            .copied()
            .collect::<Vec<_>>();
        if need_whitelist.is_empty() {
            Ok(need_whitelist)
        } else {
            self.router_client.add_routes(&need_whitelist).await?;
            for ip in &need_whitelist {
                self.whitelisted.insert(*ip);
            }
            Ok(need_whitelist)
        }
    }
}
