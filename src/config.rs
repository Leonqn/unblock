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
    pub metrics_bind_addr: SocketAddr,
    pub udp_dns_upstream: SocketAddr,
    pub doh_upstreams: Option<Vec<String>>,
    pub unblock: Option<Unblock>,
    pub ads_block: Option<AdsBlock>,
    pub retry: Retry,
}

impl Config {
    pub fn init() -> Result<Self> {
        let config_name = std::env::args()
            .nth(1)
            .expect("Config file should be specified as first argument");
        let mut settings = config::Config::default();
        settings.merge(config::File::with_name(&config_name))?;
        Ok(settings.try_into::<Self>()?)
    }
}

#[derive(Deserialize)]
pub struct Retry {
    pub attempts_count: usize,
    #[serde(with = "serde_humantime")]
    pub next_attempt_delay: Duration,
}

#[derive(Deserialize)]
pub struct AdsBlock {
    pub filter_uri: String,
    #[serde(with = "serde_humantime")]
    pub filter_update_interval: Duration,
    pub manual_rules: Vec<String>,
}

#[derive(Deserialize)]
pub struct Unblock {
    pub blacklist_dump_uri: String,
    #[serde(with = "serde_humantime")]
    pub blacklist_update_interval: Duration,
    pub router_api_uri: String,
    pub route_interface: String,
    pub manual_whitelist: Option<HashSet<Ipv4Addr>>,
    pub manual_whitelist_dns: Option<HashSet<String>>,
    #[serde(with = "serde_humantime")]
    pub clear_interval: Duration,
}
