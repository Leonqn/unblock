use std::{collections::HashSet, net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::Result;
use arc_swap::ArcSwapOption;
use ipnet::Ipv4Net;
use log::error;

use crate::{reroute::Rerouter, routers::KeeneticClient};

pub fn spawn_polling(
    router_client: Arc<KeeneticClient>,
    rerouter: Rerouter,
    whitelist_ips: Arc<ArcSwapOption<Vec<Ipv4Net>>>,
    poll_interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(poll_interval).await;
            if let Err(e) = poll(&router_client, &rerouter, &whitelist_ips).await {
                error!("Connections polling error: {:#}", e);
            }
        }
    });
}

async fn poll(
    router_client: &KeeneticClient,
    rerouter: &Rerouter,
    whitelist_ips: &ArcSwapOption<Vec<Ipv4Net>>,
) -> Result<()> {
    let whitelist = whitelist_ips.load();
    let nets = match whitelist.as_deref() {
        Some(nets) if !nets.is_empty() => nets,
        _ => return Ok(()),
    };

    let entries = router_client.get_connections().await?;

    let matched_ips: HashSet<Ipv4Addr> = entries
        .iter()
        .map(|e| e.orig.dst)
        .filter(|ip| nets.iter().any(|net| net.contains(ip)))
        .collect();

    if !matched_ips.is_empty() {
        let ips: Vec<Ipv4Addr> = matched_ips.into_iter().collect();
        rerouter.reroute(ips, "conntrack").await?;
    }
    Ok(())
}
