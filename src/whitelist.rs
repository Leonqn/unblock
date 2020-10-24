use std::{collections::HashSet, net::Ipv4Addr, sync::Arc};

use crate::{blacklist::Blacklist, router_client::RouterClient};
use anyhow::Result;
use tokio::sync::Mutex;

pub struct Whitelist {
    blacklist: Arc<Blacklist>,
    router_client: Arc<RouterClient>,
    whitelisted: Mutex<HashSet<Ipv4Addr>>,
}

impl Whitelist {
    pub async fn new(blacklist: Arc<Blacklist>, router_client: Arc<RouterClient>) -> Result<Self> {
        let routed = router_client.get_routed().await?;
        Ok(Self {
            blacklist,
            router_client,
            whitelisted: Mutex::new(routed),
        })
    }

    pub async fn whitelist(&self, ips: &[Ipv4Addr]) -> Result<bool> {
        let mut whitelisted = self.whitelisted.lock().await;
        let need_whitelist = ips
            .iter()
            .filter(|ip| self.blacklist.contains(**ip) && !whitelisted.contains(ip))
            .copied()
            .collect::<Vec<_>>();
        if need_whitelist.is_empty() {
            Ok(false)
        } else {
            self.router_client.add_routes(&need_whitelist).await?;
            for ip in need_whitelist {
                whitelisted.insert(ip);
            }
            Ok(true)
        }
    }
}
