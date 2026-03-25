use std::convert::Infallible;
use std::net::SocketAddr;
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

use crate::{
    dns::{client::DnsClient, message::Query},
    stats::StatsCollector,
    unblock::RoutedEntry,
};

const INDEX_HTML: &str = include_str!("../static/index.html");

pub struct AppState {
    pub routed_snapshot: Arc<ArcSwapOption<Vec<RoutedEntry>>>,
    pub dns_pipeline: Arc<dyn DnsClient>,
    pub stats_collector: Arc<StatsCollector>,
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
    let path = req.uri().path().to_owned();
    let query_str = req.uri().query().unwrap_or("").to_owned();

    let response = match (req.method(), path.as_str()) {
        (&Method::GET, "/") => html_response(INDEX_HTML),
        (&Method::GET, "/api/routed") => {
            let snapshot = state.routed_snapshot.load_full();
            let entries = snapshot
                .as_ref()
                .map(|v| v.as_ref().clone())
                .unwrap_or_default();
            debug!(
                "GET /api/routed: snapshot={}, entries={}",
                if snapshot.is_some() {
                    "present"
                } else {
                    "none"
                },
                entries.len()
            );
            json_response(&entries)
        }
        (&Method::GET, "/api/stats") => {
            let ip_filter = parse_query_param(&query_str, "ip");
            let top_n: usize = parse_query_param(&query_str, "top")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10);
            let snapshot = state.stats_collector.snapshot();
            let entries: Vec<StatsEntry> = snapshot
                .per_ip
                .into_iter()
                .filter(|(ip, _)| ip_filter.as_ref().is_none_or(|f| ip.to_string() == *f))
                .map(|(ip, stats)| {
                    let total_queries: u64 = stats.domain_counts.values().sum();
                    let mut top_domains: Vec<(String, u64)> =
                        stats.domain_counts.into_iter().collect();
                    top_domains.sort_by(|a, b| b.1.cmp(&a.1));
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
                    StatsEntry {
                        ip: ip.to_string(),
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
        _ => not_found(),
    };

    Ok(response)
}
