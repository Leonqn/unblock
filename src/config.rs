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
    pub udp_dns_upstream: SocketAddr,
    pub doh_upstreams: Option<Vec<String>>,
    pub unblock: Option<Unblock>,
    pub ads_block: Option<AdsBlock>,
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
pub struct AdsBlock {
    pub filter_uri: String,
    #[serde(with = "serde_humantime")]
    pub filter_update_interval: Duration,
}

#[derive(Deserialize)]
pub struct Unblock {
    pub blacklist_dump_uri: String,
    #[serde(with = "serde_humantime")]
    pub blacklist_update_interval: Duration,
    pub router_api_uri: String,
    pub route_interface: String,
    pub manual_whitelist: HashSet<Ipv4Addr>,
}
