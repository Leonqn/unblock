use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use blacklist::Blacklist;
use log::info;
use router_client::RouterClient;
use whitelist::Whitelist;

mod blacklist;
mod dns;
mod router_client;
mod whitelist;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let bind_addr: SocketAddr = std::env::var("UNBLOCK_BIND_ADDR")?.parse()?;
    let dns_upstream: SocketAddr = std::env::var("UNBLOCK_DNS_UPSTREAM")?.parse()?;
    let blacklist_dump = std::env::var("UNBLOCK_BLACKLIST_DUMP")?.parse()?;
    let router_api = std::env::var("UNBLOCK_ROUTER_API")?.parse()?;
    let route_interface = std::env::var("UNBLOCK_ROUTE_INTERFACE")?.to_owned();
    let blacklist_update_interval_s =
        Duration::from_secs(std::env::var("UNBLOCK_BLACKLIST_UPDATE_INTERVAL_SEC")?.parse()?);

    let blacklist = Arc::new(Blacklist::new(blacklist_dump).await?);
    let router = Arc::new(RouterClient::new(router_api, route_interface));
    let whitelist = Whitelist::new(blacklist.clone(), router).await?;
    let updater_handle = async move {
        tokio::spawn(async move { blacklist.start_updating(blacklist_update_interval_s).await })
            .await?;
        Ok(())
    };
    let dns_handle = dns::start_server(bind_addr, dns_upstream, whitelist);
    info!("Service spawned");
    tokio::try_join!(updater_handle, dns_handle)?;
    Ok(())
}
