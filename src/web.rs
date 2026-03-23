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
    blacklist::Blacklist,
    dns::{client::DnsClient, message::Query},
    domains_filter::DomainsFilter,
    last_item::LastItem,
    prefix_tree::PrefixTree,
    unblock::RoutedEntry,
};

const INDEX_HTML: &str = include_str!("../static/index.html");

pub struct AppState {
    pub domains_filter: Option<LastItem<DomainsFilter>>,
    pub blacklists: Vec<LastItem<Box<dyn Blacklist>>>,
    pub routed_snapshot: Arc<ArcSwapOption<Vec<RoutedEntry>>>,
    pub dns_pipeline: Arc<dyn DnsClient>,
    pub dns_routing: Vec<(PrefixTree, Vec<String>)>,
    pub default_upstreams: Vec<String>,
}

#[derive(Serialize)]
struct LookupResult {
    domain: String,
    ips: Vec<String>,
    blacklisted: bool,
    ads_blocked: bool,
    ads_rule: Option<String>,
    resolved_by: Vec<String>,
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
        .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
        .unwrap()
}

fn not_found() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Empty::<Bytes>::new().map_err(|never| match never {}).boxed())
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
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service_fn(move |req| {
                    handle_request(req, state.clone())
                }))
                .await
            {
                error!("Connection error: {}", e);
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
                if snapshot.is_some() { "present" } else { "none" },
                entries.len()
            );
            json_response(&entries)
        }
        (&Method::GET, "/api/lookup") => {
            let domain = parse_query_param(&query_str, "domain")
                .unwrap_or_default()
                .trim()
                .trim_end_matches('.')
                .to_lowercase();

            let blacklisted = state
                .blacklists
                .iter()
                .filter_map(|bl| bl.item())
                .any(|bl| bl.contains(&domain));

            let (ads_blocked, ads_rule) = state
                .domains_filter
                .as_ref()
                .and_then(|df| df.item())
                .and_then(|filter| {
                    filter.match_domain(&domain).map(|m| {
                        if m.is_allowed {
                            (false, Some(format!("@@{}", m.rule)))
                        } else {
                            (true, Some(m.rule.to_string()))
                        }
                    })
                })
                .unwrap_or((false, None));

            let resolved_by = state
                .dns_routing
                .iter()
                .find(|(tree, _)| tree.contains(&domain))
                .map(|(_, upstreams)| upstreams.clone())
                .unwrap_or_else(|| state.default_upstreams.clone());

            let dns_query = Query::for_domain(&domain);
            let ips = match state.dns_pipeline.send(dns_query).await {
                Ok(response) => match response.parse() {
                    Ok(parsed) => parsed.ips().map(|ip| ip.to_string()).collect(),
                    Err(_) => vec![],
                },
                Err(_) => vec![],
            };

            json_response(&LookupResult { domain, ips, blacklisted, ads_blocked, ads_rule, resolved_by })
        }
        _ => not_found(),
    };

    Ok(response)
}
