use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::config::{AdsBlock, Config, DnsRoute, Retry, Unblock};
use crate::web::AppState;
use anyhow::Result;
use arc_swap::ArcSwapOption;
use dns::client::{
    AdsBlockClient, CachedClient, ChoiceClient, DnsClient, DohClient, DomainRoutingClient, Either,
    RetryClient, RoundRobinClient, UdpClient, UnblockClient,
};
use domains_filter::DomainsFilter;
use futures_util::{stream, StreamExt};
use last_item::LastItem;
use log::info;
use prefix_tree::PrefixTree;
use routers::KeeneticClient;
use unblock::Unblocker;
use url::Url;

mod blacklist;
mod cache;
mod config;
mod disk_blacklist;
mod dns;
mod domains_filter;
mod files_stream;
mod last_item;
mod prefix_tree;
mod routers;
mod unblock;
mod web;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init();
    let config = Config::init()?;
    info!("Starting service");

    let data_dir = PathBuf::from(&config.data_dir);
    std::fs::create_dir_all(&data_dir)?;

    let (dns_pipeline, app_state) = create_dns_client(DnsClientConfig {
        doh_upstreams: config.doh_upstreams,
        dns_routing: config.dns_routing,
        udp_upstream: config.udp_dns_upstream,
        ads_block: config.ads_block,
        unblock_config: config.unblock,
        retry_config: config.retry,
        data_dir,
        cache_max_size: config.cache_max_size,
    })
    .await?;

    let dns_pipeline: Arc<dyn DnsClient> = Arc::new(dns_pipeline);
    let app_state = Arc::new(AppState {
        routed_snapshot: app_state.routed_snapshot,
        dns_pipeline: dns_pipeline.clone(),
    });

    let web_bind_addr = config.web_bind_addr.or(config.metrics_bind_addr);
    let web_service =
        web_bind_addr.map(|addr| tokio::spawn(web::start_web_server(addr, app_state)));

    let request_handler = move |query| {
        let dns_pipeline = dns_pipeline.clone();
        async move { dns_pipeline.send(query).await }
    };
    let udp_server =
        dns::server::create_udp_server(config.bind_addr, request_handler.clone()).await?;
    let tcp_server = dns::server::create_tcp_server(config.bind_addr, request_handler).await?;

    let main_service = tokio::spawn(async move {
        tokio::join!(udp_server, tcp_server);
    });

    tokio::select! {
        web = async { web_service.unwrap().await }, if web_service.is_some() => {
            web
        }
        main_service = main_service => {
            main_service
        }
    }?;
    Ok(())
}

struct UnblockResult<C> {
    client: C,
    routed_snapshot: Arc<ArcSwapOption<Vec<unblock::RoutedEntry>>>,
}

struct PartialAppState {
    routed_snapshot: Arc<ArcSwapOption<Vec<unblock::RoutedEntry>>>,
}

struct DnsClientConfig {
    doh_upstreams: Option<Vec<String>>,
    dns_routing: Option<Vec<DnsRoute>>,
    udp_upstream: SocketAddr,
    ads_block: Option<AdsBlock>,
    unblock_config: Option<Unblock>,
    retry_config: Option<Retry>,
    data_dir: PathBuf,
    cache_max_size: Option<usize>,
}

async fn create_dns_client(cfg: DnsClientConfig) -> Result<(impl DnsClient, PartialAppState)> {
    let DnsClientConfig {
        doh_upstreams,
        dns_routing,
        udp_upstream,
        ads_block,
        unblock_config,
        retry_config,
        data_dir,
        cache_max_size,
    } = cfg;
    let udp_client = UdpClient::new(udp_upstream).await?;
    let doh = create_doh_if_needed(udp_client, doh_upstreams)?;
    let domain_routed = create_domain_routing_if_needed(doh, dns_routing)?;
    let retry_client = match retry_config {
        Some(retry) => Either::Left(RetryClient::new(
            domain_routed,
            retry.attempts_count,
            retry.next_attempt_delay,
        )),
        None => Either::Right(domain_routed),
    };

    let UnblockResult {
        client: unblock_client,
        routed_snapshot,
    } = create_unblock_if_needed(retry_client, unblock_config, &data_dir)?;
    let cached_client = CachedClient::new(unblock_client, cache_max_size);
    let ads_block_client = create_ads_block_if_needed(cached_client, ads_block, &data_dir)?;

    let state = PartialAppState { routed_snapshot };
    Ok((ads_block_client, state))
}

fn create_ads_block_if_needed(
    client: impl DnsClient,
    config: Option<AdsBlock>,
    data_dir: &Path,
) -> Result<impl DnsClient> {
    match config {
        Some(config) => {
            let domains_filter_stream = domains_filter::filters_stream(
                config.filter_uri.parse()?,
                config.filter_update_interval,
                config.manual_rules,
                Some(data_dir.to_path_buf()),
            )?;
            let last_item = LastItem::new(domains_filter_stream);
            Ok(Either::Left(AdsBlockClient::new(client, last_item)))
        }
        None => Ok(Either::Right(client)),
    }
}

fn create_unblock_if_needed(
    client: impl DnsClient,
    config: Option<Unblock>,
    data_dir: &Path,
) -> Result<UnblockResult<impl DnsClient>> {
    match config {
        Some(config) => {
            let router_client =
                KeeneticClient::new(config.router_api_uri.parse()?, config.route_interface);

            let mut blacklist_last_items: Vec<LastItem<Box<dyn blacklist::Blacklist>>> = Vec::new();

            if let Some(url) = config.rvzdata_url {
                let stream = blacklist::rvzdata(
                    url.parse()?,
                    config.blacklist_update_interval,
                    data_dir.to_path_buf(),
                )?;
                let last_item = LastItem::new(stream);
                blacklist_last_items.push(last_item);
            }
            if let Some(url) = config.inside_raw_url {
                let stream = blacklist::inside_raw(url.parse()?, config.blacklist_update_interval)?;
                let last_item = LastItem::new(stream);
                blacklist_last_items.push(last_item);
            }
            if blacklist_last_items.is_empty() {
                let empty: Box<dyn blacklist::Blacklist> = Box::new(PrefixTree::default());
                let stream = stream::iter([empty]).chain(stream::pending());
                blacklist_last_items.push(LastItem::new(stream));
            }

            let unblocker = Unblocker::new(router_client, config.route_ttl);
            let routed_snapshot = unblocker.routed_snapshot();

            let blacklists_for_client: Vec<LastItem<Box<dyn blacklist::Blacklist>>> =
                blacklist_last_items.to_vec();

            let unblock_client = UnblockClient::new(
                client,
                unblocker,
                DomainsFilter::new(
                    &config
                        .manual_whitelist_dns
                        .map(|x| x.join("\n"))
                        .unwrap_or_default(),
                    None,
                )?,
                config.manual_whitelist.unwrap_or_default(),
                blacklists_for_client,
            );
            Ok(UnblockResult {
                client: Either::Left(unblock_client),
                routed_snapshot,
            })
        }
        None => Ok(UnblockResult {
            client: Either::Right(client),
            routed_snapshot: Arc::new(ArcSwapOption::empty()),
        }),
    }
}

fn create_domain_routing_if_needed(
    client: impl DnsClient,
    dns_routing: Option<Vec<DnsRoute>>,
) -> Result<impl DnsClient> {
    match dns_routing {
        Some(routes) if !routes.is_empty() => {
            let routing_rules = routes
                .into_iter()
                .map(|route| {
                    let clients = route
                        .doh_upstreams
                        .into_iter()
                        .map(|u| Ok(Box::new(DohClient::new(u.parse()?)?) as Box<dyn DnsClient>))
                        .collect::<Result<_>>()?;
                    let rr = RoundRobinClient::new(clients);
                    let mut tree = PrefixTree::default();
                    for domain in route.domains {
                        tree.add(domain);
                    }
                    Ok((tree, Box::new(rr) as Box<dyn DnsClient>))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Either::Left(DomainRoutingClient::new(
                routing_rules,
                client,
            )))
        }
        _ => Ok(Either::Right(client)),
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

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::PathBuf, time::Duration};

    use anyhow::Result;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use crate::{
        config::{AdsBlock, Retry, Unblock},
        create_dns_client,
        dns::{
            client::{DnsClient, UdpClient},
            message::Query,
        },
        DnsClientConfig,
    };

    async fn router_http_stub() {
        let listener = TcpListener::bind("127.0.0.1:3030").await.unwrap();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|_req| async {
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .body(Full::new(Bytes::from_static(b"{}")))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    }

    #[tokio::test]
    async fn should_handle_dns_request() -> Result<()> {
        tokio::spawn(router_http_stub());
        tokio::task::yield_now().await;
        let bind_addr = "0.0.0.0:3356".parse()?;
        let data_dir = PathBuf::from("/tmp/unblock-test");
        std::fs::create_dir_all(&data_dir)?;
        let (dns_pipeline, _state) = create_dns_client(DnsClientConfig {
            doh_upstreams: Some(vec![
                "https://dns.google/dns-query".to_owned(),
                "https://dns.cloudflare.com/dns-query".to_owned(),
                "https://dns.quad9.net/dns-query".to_owned(),
            ]),
            dns_routing: None,
            udp_upstream: "8.8.8.8:53".parse()?,
            ads_block: Some(AdsBlock {
                filter_uri: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
                    .to_owned(),
                filter_update_interval: Duration::from_secs(10),
                manual_rules: vec!["@||youtube.com".to_owned()],
            }),
            unblock_config: Some(Unblock {
                rvzdata_url: Some(
                    "https://raw.githubusercontent.com/zapret-info/z-i/master/dump-00.csv"
                        .to_owned(),
                ),
                inside_raw_url: None,
                blacklist_update_interval: Duration::from_secs(10),
                router_api_uri: "http://127.0.0.1:3030".to_owned(),
                route_interface: "Ads".to_owned(),
                manual_whitelist: Some(HashSet::new()),
                route_ttl: Some(Duration::from_secs(10)),
                manual_whitelist_dns: Some(Vec::new()),
            }),
            retry_config: Some(Retry {
                attempts_count: 3,
                next_attempt_delay: Duration::from_millis(200),
            }),
            data_dir,
            cache_max_size: None,
        })
        .await?;

        let dns_pipeline = std::sync::Arc::new(dns_pipeline);
        let request_handler = move |query| {
            let dns_pipeline = dns_pipeline.clone();
            async move { dns_pipeline.send(query).await }
        };
        let udp_server =
            crate::dns::server::create_udp_server(bind_addr, request_handler.clone()).await?;
        let tcp_server = crate::dns::server::create_tcp_server(bind_addr, request_handler).await?;
        tokio::spawn(async move {
            tokio::join!(udp_server, tcp_server);
        });
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
