use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use dns::client::{CachedClient, UdpClient};
use log::info;
use routers::KeeneticClient;
use serde::Deserialize;
use tokio::stream::StreamExt;
use unblock::Unblocker;

mod blacklist;
mod cache;
mod dns;
mod dns_handler;
mod routers;
mod unblock;

#[derive(Deserialize)]
struct Config {
    bind_addr: SocketAddr,
    dns_upstream: SocketAddr,
    blacklist_dump_uri: String,
    #[serde(with = "serde_humantime")]
    blacklist_update_interval: Duration,
    router_api_uri: String,
    route_interface: String,
    manual_whitelist: HashSet<Ipv4Addr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let config_name = std::env::args()
        .nth(1)
        .expect("Config file should be specified as first argument");
    let mut settings = config::Config::default();
    settings.merge(config::File::with_name(&config_name))?;
    let config = settings.try_into::<Config>()?;
    let router_client = KeeneticClient::new(config.router_api_uri.parse()?, config.route_interface);
    let blacklists = blacklist::create_blacklists_stream(
        config.blacklist_dump_uri.parse()?,
        config.blacklist_update_interval,
    )
    .await?;
    let manual = config.manual_whitelist;
    let blacklists = blacklists.map(move |mut blacklist| {
        blacklist.extend(manual.iter().copied());
        blacklist
    });
    let unblocker = Arc::new(Unblocker::new(blacklists, router_client).await?);
    let dns_client = Arc::new(CachedClient::new(
        UdpClient::new(config.dns_upstream).await?,
    ));
    let dns_handle = tokio::spawn(
        dns::server::create_udp_server(config.bind_addr, move |query| {
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
