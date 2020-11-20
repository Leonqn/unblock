use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use dns::client::{CachedClient, UdpClient};
use log::info;
use routers::RouterClient;
use unblock::Unblocker;

mod blacklist;
mod cache;
mod dns;
mod dns_handler;
mod routers;
mod unblock;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let bind_addr: SocketAddr = std::env::var("UNBLOCK_BIND_ADDR")?.parse()?;
    let dns_upstream: SocketAddr = std::env::var("UNBLOCK_DNS_UPSTREAM")?.parse()?;
    let blacklist_dump = std::env::var("UNBLOCK_BLACKLIST_DUMP")?.parse()?;
    let router_api = std::env::var("UNBLOCK_ROUTER_API")?.parse()?;
    let route_interface = std::env::var("UNBLOCK_ROUTE_INTERFACE")?;
    let blacklist_update_interval_s =
        Duration::from_secs(std::env::var("UNBLOCK_BLACKLIST_UPDATE_INTERVAL_SEC")?.parse()?);

    let router_client = RouterClient::new(router_api, route_interface);
    let blacklists =
        blacklist::create_blacklists_stream(blacklist_dump, blacklist_update_interval_s).await?;
    let unblocker = Arc::new(Unblocker::new(blacklists, router_client).await?);
    let dns_client = Arc::new(CachedClient::new(UdpClient::new(dns_upstream).await?));
    let dns_handle = tokio::spawn(
        dns::server::create_udp_server(bind_addr, move |query| {
            let unblocker = unblocker.clone();
            let dns_client = dns_client.clone();
            dns_handler::handle_query(query, unblocker, dns_client)
        })
        .await?,
    );

    info!("Service spawned");
    dns_handle.await?;
    Ok(())
}
