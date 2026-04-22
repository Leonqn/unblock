use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use serde::Serialize;
use tokio::net::TcpListener;

use ipnet::Ipv4Net;

use crate::{
    dns::{client::DnsClient, message::Query},
    domains_filter::DomainsFilter,
    reroute::RoutedEntry,
    stats::StatsCollector,
    updater,
};

const INDEX_HTML: &str = include_str!("../static/index.html");

pub struct AppState {
    pub routed_snapshot: Arc<ArcSwapOption<Vec<RoutedEntry>>>,
    pub dns_pipeline: Arc<dyn DnsClient>,
    pub stats_collector: Arc<StatsCollector>,
    /// Global route TTL in seconds, from config. None means routes never expire.
    pub route_ttl_secs: Option<u64>,
    pub whitelist_filter: Arc<ArcSwapOption<DomainsFilter>>,
    pub whitelist_rules: Arc<ArcSwapOption<Vec<String>>>,
    pub whitelist_ips: Arc<ArcSwapOption<Vec<Ipv4Net>>>,
    pub whitelist_ip_rules: Arc<ArcSwapOption<Vec<String>>>,
    pub hosts: Arc<ArcSwapOption<HashMap<String, Ipv4Addr>>>,
    pub dns_cache: crate::dns::client::DnsCache,
    pub config_path: PathBuf,
}

#[derive(Serialize)]
struct RoutedResponse<'a> {
    route_ttl_secs: Option<u64>,
    entries: Vec<&'a RoutedEntry>,
}

#[derive(Serialize)]
struct LookupResult {
    domain: String,
    ips: Vec<String>,
    trace: String,
}

#[derive(Serialize)]
struct StatsEntry {
    ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
    total_queries: u64,
    top_domains: Vec<(String, u64)>,
    recent: Vec<StatsRecentEntry>,
}

#[derive(Serialize)]
struct StatsRecentEntry {
    domain: String,
    timestamp: u64,
    trace: String,
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn html_response(html: &'static str) -> Response<BoxBody> {
    Response::builder()
        .header("Content-Type", "text/html")
        .body(
            Full::new(Bytes::from_static(html.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn json_response(data: &impl Serialize) -> Response<BoxBody> {
    let body = serde_json::to_vec(data).unwrap_or_default();
    Response::builder()
        .header("Content-Type", "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn error_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    let error = serde_json::json!({"error": message});
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(
            Full::new(Bytes::from(serde_json::to_vec(&error).unwrap_or_default()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn not_found() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn parse_query_param(query_str: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query_str.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn persist_hosts(config_path: &Path, hosts: &HashMap<String, String>) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(config_path)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;
    value["hosts"] = serde_yaml::to_value(hosts)?;
    let new_content = serde_yaml::to_string(&value)?;
    std::fs::write(config_path, new_content)?;
    Ok(())
}

fn persist_config_field(config_path: &Path, field: &str, rules: &[String]) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(config_path)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

    let reroute = value
        .get_mut("reroute")
        .ok_or_else(|| anyhow::anyhow!("No reroute section in config"))?;

    let rules_value = if rules.is_empty() {
        serde_yaml::Value::Sequence(vec![])
    } else {
        serde_yaml::to_value(rules)?
    };
    reroute[field] = rules_value;

    let new_content = serde_yaml::to_string(&value)?;
    std::fs::write(config_path, new_content)?;
    Ok(())
}

fn persist_whitelist(config_path: &Path, rules: &[String]) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(config_path)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

    let reroute = value
        .get_mut("reroute")
        .ok_or_else(|| anyhow::anyhow!("No reroute section in config"))?;

    let rules_value = if rules.is_empty() {
        serde_yaml::Value::Sequence(vec![])
    } else {
        serde_yaml::to_value(rules)?
    };
    reroute["manual_whitelist_dns"] = rules_value;

    let new_content = serde_yaml::to_string(&value)?;
    std::fs::write(config_path, new_content)?;
    Ok(())
}

pub async fn start_web_server(bind_addr: SocketAddr, state: Arc<AppState>) {
    let listener = TcpListener::bind(bind_addr).await.unwrap();
    info!("Starting web server on {}", bind_addr);
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept error: {}", e);
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let conn = hyper::server::conn::http1::Builder::new().serve_connection(
                TokioIo::new(stream),
                service_fn(move |req| handle_request(req, state.clone())),
            );
            if let Err(e) = conn.await {
                debug!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<BoxBody>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query_str = req.uri().query().unwrap_or("").to_owned();

    let response = match (&method, path.as_str()) {
        (&Method::GET, "/") => html_response(INDEX_HTML),
        (&Method::GET, "/api/routed") => {
            let snapshot = state.routed_snapshot.load_full();
            let entries: Vec<&RoutedEntry> = snapshot
                .as_ref()
                .map(|v| v.iter().collect())
                .unwrap_or_default();
            debug!(
                "GET /api/routed: snapshot={}, entries={}",
                snapshot.as_ref().map_or("none", |_| "present"),
                entries.len()
            );
            json_response(&RoutedResponse {
                route_ttl_secs: state.route_ttl_secs,
                entries,
            })
        }
        (&Method::GET, "/api/stats/dates") => {
            let mut dates = state.stats_collector.available_dates().await;
            let current = state.stats_collector.current_date();
            if !dates.contains(&current) {
                dates.insert(0, current);
            }
            json_response(&dates)
        }
        (&Method::GET, "/api/stats") => {
            let ip_filter = parse_query_param(&query_str, "ip");
            let date = parse_query_param(&query_str, "date");
            let top_n: usize = parse_query_param(&query_str, "top")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10);
            let snapshot = match &date {
                Some(d) if *d != state.stats_collector.current_date() => {
                    state.stats_collector.load_date(d).await
                }
                _ => state.stats_collector.snapshot(),
            };
            let devices = state.stats_collector.devices();
            let entries: Vec<StatsEntry> = snapshot
                .per_ip
                .into_iter()
                .filter(|(ip, _)| ip_filter.as_ref().is_none_or(|f| ip.to_string() == *f))
                .map(|(ip, stats)| {
                    let total_queries: u64 = stats.domain_counts.values().sum();
                    let mut top_domains: Vec<(String, u64)> =
                        stats.domain_counts.into_iter().collect();
                    top_domains.sort_by_key(|b| std::cmp::Reverse(b.1));
                    top_domains.truncate(top_n);
                    let recent = stats
                        .recent_requests
                        .into_iter()
                        .map(|r| StatsRecentEntry {
                            domain: r.domain,
                            timestamp: r.timestamp,
                            trace: r.trace,
                        })
                        .collect();
                    let device_name = devices.get(&ip).cloned();
                    StatsEntry {
                        ip: ip.to_string(),
                        device_name,
                        total_queries,
                        top_domains,
                        recent,
                    }
                })
                .collect();
            json_response(&entries)
        }
        (&Method::GET, "/api/lookup") => {
            let domain = parse_query_param(&query_str, "domain")
                .unwrap_or_default()
                .trim()
                .trim_end_matches('.')
                .to_lowercase();

            let dns_query = Query::for_domain(&domain);
            let (ips, trace) = match state.dns_pipeline.send(dns_query).await {
                Ok(response) => {
                    let trace = response.trace().to_owned();
                    let ips = match response.parse() {
                        Ok(parsed) => parsed.ips().map(|ip| ip.to_string()).collect(),
                        Err(_) => vec![],
                    };
                    (ips, trace)
                }
                Err(_) => (vec![], String::new()),
            };

            json_response(&LookupResult { domain, ips, trace })
        }
        (&Method::GET, "/api/config/whitelist") => {
            let rules = state.whitelist_rules.load_full();
            let rules: Vec<String> = rules.as_deref().cloned().unwrap_or_default();
            json_response(&rules)
        }
        (&Method::PUT, "/api/config/whitelist") => {
            let body = req
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();

            match serde_json::from_slice::<Vec<String>>(&body) {
                Ok(new_rules) => {
                    let rules_str = new_rules.join("\n");
                    match DomainsFilter::new(&rules_str) {
                        Ok(filter) => match persist_whitelist(&state.config_path, &new_rules) {
                            Ok(()) => {
                                state.whitelist_filter.store(Some(Arc::new(filter)));
                                state.whitelist_rules.store(Some(Arc::new(new_rules)));
                                state.dns_cache.clear();
                                json_response(&serde_json::json!({"status": "ok"}))
                            }
                            Err(e) => error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &format!("Failed to save config: {}", e),
                            ),
                        },
                        Err(e) => error_response(
                            StatusCode::BAD_REQUEST,
                            &format!("Invalid rules: {}", e),
                        ),
                    }
                }
                Err(e) => error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
            }
        }
        (&Method::GET, "/api/config/manual-whitelist") => {
            let rules = state.whitelist_ip_rules.load_full();
            let rules: Vec<String> = rules.as_deref().cloned().unwrap_or_default();
            json_response(&rules)
        }
        (&Method::PUT, "/api/config/manual-whitelist") => {
            let body = req
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();

            match serde_json::from_slice::<Vec<String>>(&body) {
                Ok(new_rules) => match crate::parse_ip_whitelist(&new_rules) {
                    Ok(nets) => {
                        match persist_config_field(
                            &state.config_path,
                            "manual_whitelist",
                            &new_rules,
                        ) {
                            Ok(()) => {
                                state.whitelist_ips.store(Some(Arc::new(nets)));
                                state.whitelist_ip_rules.store(Some(Arc::new(new_rules)));
                                state.dns_cache.clear();
                                json_response(&serde_json::json!({"status": "ok"}))
                            }
                            Err(e) => error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &format!("Failed to save config: {}", e),
                            ),
                        }
                    }
                    Err(e) => {
                        error_response(StatusCode::BAD_REQUEST, &format!("Invalid IP/CIDR: {}", e))
                    }
                },
                Err(e) => error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
            }
        }
        (&Method::GET, "/api/config/hosts") => {
            let hosts = state.hosts.load_full();
            let hosts: HashMap<String, String> = hosts
                .as_deref()
                .map(|h| h.iter().map(|(k, v)| (k.clone(), v.to_string())).collect())
                .unwrap_or_default();
            json_response(&hosts)
        }
        (&Method::PUT, "/api/config/hosts") => {
            let body = req
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();

            match serde_json::from_slice::<HashMap<String, String>>(&body) {
                Ok(new_hosts) => {
                    let parsed: Result<HashMap<String, Ipv4Addr>, _> = new_hosts
                        .iter()
                        .map(|(k, v)| v.parse::<Ipv4Addr>().map(|ip| (k.clone(), ip)))
                        .collect();
                    match parsed {
                        Ok(hosts_map) => match persist_hosts(&state.config_path, &new_hosts) {
                            Ok(()) => {
                                state.hosts.store(Some(Arc::new(hosts_map)));
                                state.dns_cache.clear();
                                json_response(&serde_json::json!({"status": "ok"}))
                            }
                            Err(e) => error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &format!("Failed to save config: {}", e),
                            ),
                        },
                        Err(e) => error_response(
                            StatusCode::BAD_REQUEST,
                            &format!("Invalid IP address: {}", e),
                        ),
                    }
                }
                Err(e) => error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
            }
        }
        (&Method::GET, "/api/updates/check") => match updater::check_latest_release().await {
            Ok(release) => json_response(&release),
            Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        },
        (&Method::POST, "/api/updates/apply") => {
            let body = req
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();

            #[derive(serde::Deserialize)]
            struct UpdateRequest {
                url: String,
            }

            match serde_json::from_slice::<UpdateRequest>(&body) {
                Ok(update_req) => match updater::apply_update(&update_req.url).await {
                    Ok(()) => json_response(&serde_json::json!({"status": "ok"})),
                    Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                },
                Err(e) => {
                    error_response(StatusCode::BAD_REQUEST, &format!("Invalid request: {}", e))
                }
            }
        }
        _ => not_found(),
    };

    Ok(response)
}
