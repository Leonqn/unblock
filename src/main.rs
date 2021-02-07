use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use crate::config::{AdsBlock, Config, Unblock};
use anyhow::Result;
use dns::client::{
    AdsBlockClient, CachedClient, ChoiceClient, DnsClient, DohClient, Either, RoundRobinClient,
    UdpClient, UnblockClient,
};
use log::info;
use prometheus::{Encoder, TextEncoder};
use reqwest::Url;
use routers::KeeneticClient;
use tokio_stream::StreamExt;
use unblock::Unblocker;
use warp::Filter;

mod ads_filter;
mod blacklist;
mod cache;
mod config;
mod dns;
mod files_stream;
mod last_item;
mod routers;
mod unblock;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let config = Config::init()?;
    info!("Starting service");
    let metrics_service = create_metrics_server("0.0.0.0:9090".parse().unwrap());
    let main_service = create_service(config).await?;
    tokio::join!(main_service, metrics_service);
    Ok(())
}

async fn create_service(config: Config) -> Result<impl std::future::Future<Output = ()>> {
    let dns_pipeline = Arc::new(
        create_dns_client(
            config.doh_upstreams,
            config.udp_dns_upstream,
            config.ads_block,
            config.unblock,
        )
        .await?,
    );

    let server = dns::server::create_udp_server(config.bind_addr, move |query| {
        let dns_pipeline = dns_pipeline.clone();
        async move { dns_pipeline.send(query).await }
    })
    .await?;
    Ok(server)
}

async fn create_dns_client(
    doh_upstreams: Option<Vec<String>>,
    udp_upstream: SocketAddr,
    ads_block: Option<AdsBlock>,
    unblock: Option<Unblock>,
) -> Result<impl DnsClient> {
    let udp_client = UdpClient::new(udp_upstream).await?;
    let doh = create_doh_if_needed(udp_client, doh_upstreams)?;
    let unblock_client = create_unblock_if_needed(doh, unblock)?;
    let cached_client = CachedClient::new(unblock_client);
    let ads_block_client = create_ads_block_if_needed(cached_client, ads_block)?;
    Ok(ads_block_client)
}

fn create_ads_block_if_needed(
    client: impl DnsClient,
    config: Option<AdsBlock>,
) -> Result<impl DnsClient> {
    match config {
        Some(config) => {
            let domains_filter_stream = ads_filter::filters_stream(
                config.filter_uri.parse()?,
                config.filter_update_interval,
                config.manual_rules,
            )?;
            Ok(Either::Left(AdsBlockClient::new(
                client,
                domains_filter_stream,
            )))
        }
        None => Ok(Either::Right(client)),
    }
}

fn create_unblock_if_needed(
    client: impl DnsClient,
    config: Option<Unblock>,
) -> Result<impl DnsClient> {
    match config {
        Some(config) => {
            let router_client =
                KeeneticClient::new(config.router_api_uri.parse()?, config.route_interface);
            let blacklists = blacklist::blacklists(
                config.blacklist_dump_uri.parse()?,
                config.blacklist_update_interval,
            )?;
            let manual = config.manual_whitelist;
            let blacklists = blacklists.map(move |mut blacklist| {
                blacklist.extend(manual.iter().copied());
                blacklist
            });
            let unblocker = Unblocker::new(blacklists, router_client, config.clear_interval);
            Ok(Either::Left(UnblockClient::new(client, unblocker)))
        }
        None => Ok(Either::Right(client)),
    }
}

fn create_doh_if_needed(
    client: impl DnsClient,
    doh_upstreams: Option<Vec<String>>,
) -> Result<impl DnsClient> {
    match doh_upstreams {
        Some(doh_upstreams) => {
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
            let choice_client = ChoiceClient::new(client, round_robin_doh, doh_domains);
            Ok(Either::Left(choice_client))
        }
        None => Ok(Either::Right(client)),
    }
}

async fn create_metrics_server(bind_addr: SocketAddr) {
    warp::serve(warp::path("metrics").map(|| {
        let metric_families = prometheus::gather();
        let encoder = TextEncoder::new();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();
        warp::reply::with_header(buffer, "Content-Type", encoder.format_type())
    }))
    .run(bind_addr)
    .await;
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, time::Duration};

    use anyhow::Result;
    use bytes::Bytes;
    use warp::Filter;

    use crate::{
        config::{AdsBlock, Unblock},
        create_service,
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
        tokio::task::yield_now().await;
        let bind_addr = "0.0.0.0:3356".parse()?;
        let config = Config {
            bind_addr,
            udp_dns_upstream: "8.8.8.8:53".parse()?,
            unblock: Some(Unblock {
                blacklist_dump_uri:
                    "https://raw.githubusercontent.com/zapret-info/z-i/master/dump-00.csv"
                        .to_owned(),
                blacklist_update_interval: Duration::from_secs(10),
                router_api_uri: "http://127.0.0.1:3030".to_owned(),
                route_interface: "Ads".to_owned(),
                manual_whitelist: HashSet::new(),
                clear_interval: Duration::from_secs(10),
            }),
            ads_block: Some(AdsBlock {
                filter_uri: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
                    .to_owned(),
                filter_update_interval: Duration::from_secs(10),
                manual_rules: vec!["@||youtube.com".to_owned()],
            }),
            doh_upstreams: Some(vec![
                "https://dns.google/dns-query".to_owned(),
                "https://dns.cloudflare.com/dns-query".to_owned(),
                "https://dns.quad9.net/dns-query".to_owned(),
            ]),
        };
        let server = create_service(config).await.map_err(|x| dbg!(x))?;
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
