use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use dns::client::{CachedClient, ChoiceClient, DnsClient, DohClient, RoundRobinClient, UdpClient};
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
pub mod ads;

#[derive(Deserialize)]
struct Config {
    bind_addr: SocketAddr,
    dns_upstream: SocketAddr,
    doh_upstreams: Vec<String>,
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
    info!("Starting service");
    create_server(config).await?.await;
    Ok(())
}

async fn create_server(config: Config) -> Result<impl std::future::Future<Output = ()>> {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let dns_client = Arc::new(create_dns_client(config.doh_upstreams, config.dns_upstream).await?);
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

    let dns_handle = dns::server::create_udp_server(config.bind_addr, move |query| {
        let unblocker = unblocker.clone();
        let dns_client = dns_client.clone();
        dns_handler::handle_query(query, unblocker, dns_client)
    })
    .await?;

    Ok(dns_handle)
}

async fn create_dns_client(
    doh_upstreams: Vec<String>,
    udp_upstream: SocketAddr,
) -> Result<impl DnsClient> {
    let udp_client = UdpClient::new(udp_upstream).await?;
    let doh_upstreams = doh_upstreams
        .iter()
        .map(|x| Ok(x.parse()?))
        .collect::<Result<Vec<Url>>>()?;
    let doh_domains = doh_upstreams
        .iter()
        .map(|x| Some(x.domain()?.to_owned()))
        .collect::<Option<HashSet<_>>>()
        .expect("Should have domains");
    let doh_clients = doh_upstreams
        .into_iter()
        .map(DohClient::new)
        .map(|c| Ok(Box::new(c?) as Box<dyn DnsClient>))
        .collect::<Result<_>>()?;
    let round_robin_doh = RoundRobinClient::new(doh_clients);
    let choice_client = ChoiceClient::new(udp_client, round_robin_doh, doh_domains);
    let cached_client = CachedClient::new(choice_client);
    Ok(cached_client)
}

async fn create_bootstrap_server(
    bind_addr: SocketAddr,
    client: Arc<impl DnsClient>,
    cancel: oneshot::Receiver<()>,
) -> Result<()> {
    let server = dns::server::create_udp_server(bind_addr, move |query| {
        let client = client.clone();
        async move { client.send(query).await }
    })
    .await?;
    let _ = tokio::select! {
        _ = server => (),
        _ = cancel => (),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, time::Duration};

    use anyhow::Result;
    use bytes::Bytes;
    use warp::Filter;

    use crate::{
        create_server,
        dns::{
            client::{DnsClient, UdpClient},
            message::Query,
        },
        Config,
    };

    async fn router_http_stub() {
        warp::serve(warp::any().map(|| "{}"))
            .run(([127, 0, 0, 1], 3030))
            .await;
    }

    #[tokio::test]
    async fn should_handle_dns_request() -> Result<()> {
        tokio::spawn(router_http_stub());
        let bind_addr = "0.0.0.0:3356".parse()?;
        let config = Config {
            bind_addr,
            dns_upstream: "8.8.8.8:53".parse()?,
            doh_upstreams: vec![
                "https://dns.google/dns-query".to_owned(),
                "https://dns.cloudflare.com/dns-query".to_owned(),
                "https://dns.quad9.net/dns-query".to_owned(),
            ],
            blacklist_dump_uri:
                "https://raw.githubusercontent.com/zapret-info/z-i/master/dump-00.csv".to_owned(),
            blacklist_update_interval: Duration::from_secs(10),
            router_api_uri: "http://127.0.0.1:3030".to_owned(),
            route_interface: "Ads".to_owned(),
            manual_whitelist: HashSet::new(),
        };
        let server = create_server(config).await.map_err(|x| dbg!(x))?;
        tokio::spawn(server);
        let udp_client = UdpClient::new(bind_addr).await?;
        let requests = vec![
            include_bytes!("../test/dns_packets/q_api.browser.yandex.com.bin").as_ref(),
            include_bytes!("../test/dns_packets/q_www.google.com.bin").as_ref(),
            include_bytes!("../test/dns_packets/q_api.browser.yandex.com.bin").as_ref(),
            include_bytes!("../test/dns_packets/q_www.google.com.bin").as_ref(),
        ]
        .into_iter()
        .map(|request| Query::from_bytes(Bytes::from_static(request)).unwrap());

        for request in requests {
            let response = udp_client.send(request).await?;
            response.parse()?;
        }
        Ok(())
    }
}
