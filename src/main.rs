use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use dns::client::{CachedClient, ChooseClient, DnsClient, DohClient, UdpClient};
use log::info;
use reqwest::Url;
use routers::KeeneticClient;
use serde::Deserialize;
use tokio::{stream::StreamExt, sync::oneshot};
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
    doh_upstream: String,
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
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let dns_client = Arc::new(create_dns_client(config.doh_upstream, config.dns_upstream).await?);
    let bootstrap_server = tokio::spawn(create_bootstrap_server(
        config.bind_addr,
        dns_client.clone(),
        cancel_rx,
    ));
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
    cancel_tx.send(()).expect("Cancel dropped");
    bootstrap_server.await??;

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

async fn create_dns_client(
    doh_upstream: String,
    udp_upstream: SocketAddr,
) -> Result<impl DnsClient + Send + Sync + 'static> {
    let udp_client = UdpClient::new(udp_upstream).await?;
    let doh_upstream: Url = doh_upstream.parse()?;
    let doh_domains = {
        let mut h = HashSet::new();
        h.insert(
            doh_upstream
                .domain()
                .expect("Should have domain")
                .to_owned(),
        );
        h
    };
    let doh_client = DohClient::new(doh_upstream)?;
    let choose_client = ChooseClient::new(udp_client, doh_client, doh_domains);
    let cached_client = CachedClient::new(choose_client);
    Ok(cached_client)
}

async fn create_bootstrap_server(
    bind_addr: SocketAddr,
    client: Arc<impl DnsClient + Send + Sync + 'static>,
    cancel: oneshot::Receiver<()>,
) -> Result<()> {
    let (_, cancel) = tokio::join!(
        dns::server::create_udp_server(bind_addr, move |query| {
            let client = client.clone();
            async move { client.send(query).await }
        })
        .await?,
        cancel,
    );
    cancel?;
    Ok(())
}
