use std::{
    net::SocketAddr,
    sync::Arc,
};

use arc_swap::ArcSwapOption;
use log::{debug, info};
use prometheus::Encoder;
use serde::{Deserialize, Serialize};
use warp::Filter;

use crate::{
    blacklist::Blacklist,
    dns::{
        client::DnsClient,
        message::Query,
    },
    domains_filter::DomainsFilter,
    last_item::LastItem,
    unblock::RoutedEntry,
};

const INDEX_HTML: &str = include_str!("../static/index.html");

pub struct AppState {
    pub domains_filter: Option<LastItem<DomainsFilter>>,
    pub blacklists: Vec<LastItem<Box<dyn Blacklist>>>,
    pub routed_snapshot: Arc<ArcSwapOption<Vec<RoutedEntry>>>,
    pub dns_pipeline: Arc<dyn DnsClient>,
}

#[derive(Deserialize)]
struct LookupQuery {
    domain: String,
}

#[derive(Serialize)]
struct LookupResult {
    domain: String,
    ips: Vec<String>,
    blacklisted: bool,
    ads_blocked: bool,
    ads_rule: Option<String>,
}


pub async fn start_web_server(bind_addr: SocketAddr, state: Arc<AppState>) {
    let state = warp::any().map(move || state.clone());

    let index = warp::path::end()
        .and(warp::get())
        .map(|| warp::reply::html(INDEX_HTML));

    let metrics = warp::path("metrics").map(|| {
        let metric_families = prometheus::gather();
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();
        warp::reply::with_header(buffer, "Content-Type", encoder.format_type())
    });

    let api_routed = warp::path!("api" / "routed")
        .and(warp::get())
        .and(state.clone())
        .map(|state: Arc<AppState>| {
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
            warp::reply::json(&entries)
        });

    let api_lookup = warp::path!("api" / "lookup")
        .and(warp::get())
        .and(warp::query::<LookupQuery>())
        .and(state.clone())
        .and_then(handle_lookup);

    let routes = index
        .or(metrics)
        .or(api_routed)
        .or(api_lookup);

    info!("Starting web server on {}", bind_addr);
    warp::serve(routes).run(bind_addr).await;
}

async fn handle_lookup(
    query: LookupQuery,
    state: Arc<AppState>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let domain = query.domain.trim().trim_end_matches('.').to_lowercase();

    // Check blacklist
    let blacklisted = state
        .blacklists
        .iter()
        .filter_map(|bl| bl.item())
        .any(|bl| bl.contains(&domain));

    // Check ads block
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

    // DNS resolve
    let dns_query = Query::for_domain(&domain);
    let ips = match state.dns_pipeline.send(dns_query).await {
        Ok(response) => match response.parse() {
            Ok(parsed) => parsed.ips().map(|ip| ip.to_string()).collect(),
            Err(_) => vec![],
        },
        Err(_) => vec![],
    };

    Ok(warp::reply::json(&LookupResult {
        domain,
        ips,
        blacklisted,
        ads_blocked,
        ads_rule,
    }))
}


