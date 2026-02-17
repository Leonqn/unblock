use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub metrics_bind_addr: Option<SocketAddr>,
    pub udp_dns_upstream: SocketAddr,
    pub doh_upstreams: Option<Vec<String>>,
    pub unblock: Option<Unblock>,
    pub ads_block: Option<AdsBlock>,
    pub retry: Option<Retry>,
}

impl Config {
    pub fn init() -> Result<Self> {
        let config_name = std::env::args()
            .nth(1)
            .expect("Config file should be specified as first argument");
        Ok(config::Config::builder()
            .add_source(config::File::with_name(&config_name))
            .build()?
            .try_deserialize()?)
    }
}

#[derive(Deserialize)]
pub struct Retry {
    pub attempts_count: usize,
    #[serde(with = "humantime_serde")]
    pub next_attempt_delay: Duration,
}

#[derive(Deserialize)]
pub struct AdsBlock {
    pub filter_uri: String,
    #[serde(with = "humantime_serde")]
    pub filter_update_interval: Duration,
    pub manual_rules: Vec<String>,
}

#[derive(Deserialize)]
pub struct Unblock {
    pub rvzdata_url: Option<String>,
    pub inside_raw_url: Option<String>,
    #[serde(with = "humantime_serde")]
    pub blacklist_update_interval: Duration,
    pub router_api_uri: String,
    pub route_interface: String,
    pub manual_whitelist: Option<HashSet<Ipv4Addr>>,
    pub manual_whitelist_dns: Option<Vec<String>>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub clear_interval: Option<Duration>,
}
