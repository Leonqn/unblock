use std::{collections::HashSet, net::Ipv4Addr};

use anyhow::Result;
use async_trait::async_trait;

mod keenetic;

pub use keenetic::*;

#[async_trait]
pub trait RouterClient: Send + Sync + 'static {
    async fn get_routed(&self) -> Result<HashSet<Ipv4Addr>>;

    async fn add_routes(&self, ips: &[Ipv4Addr], comment: &str) -> Result<()>;

    async fn remove_route(&self, ip: Ipv4Addr) -> Result<()>;
}
