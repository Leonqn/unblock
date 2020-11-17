use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use log::info;
use router_client::RouterClient;

mod blacklist;
mod cache;
mod dns;
mod router_client;
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
    let (unblock_requests_tx, unblock_requests_rx) = tokio::sync::mpsc::unbounded_channel();
    let (unblock_responses_tx, unblock_responses_rx) = tokio::sync::mpsc::unbounded_channel();
    let (blacklists_tx, blacklists_rx) = tokio::sync::mpsc::unbounded_channel();

    let dns_handle = tokio::spawn(
        dns::create_server(
            bind_addr,
            dns_upstream,
            unblock_requests_tx,
            unblock_responses_rx,
        )
        .await?,
    );
    let blacklist_handle = tokio::spawn(
        blacklist::create_blacklist_receiver(
            blacklists_tx,
            blacklist_dump,
            blacklist_update_interval_s,
        )
        .await?,
    );
    let unblock_handle = tokio::spawn(
        unblock::create_unblocker(
            blacklists_rx,
            unblock_requests_rx,
            unblock_responses_tx,
            router_client,
        )
        .await?,
    );

    info!("Service spawned");
    tokio::try_join!(dns_handle, blacklist_handle, unblock_handle)?;
    Ok(())
}
