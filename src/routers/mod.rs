use std::{collections::HashSet, net::Ipv4Addr};

use anyhow::Result;
use async_trait::async_trait;

mod keenetic;

pub use keenetic::*;

#[async_trait]
pub trait RouterClient {
    async fn get_routed(&self) -> Result<HashSet<Ipv4Addr>>;

    async fn add_routes(&self, ips: &[Ipv4Addr]) -> Result<()>;

    async fn remove_routes(&self, ips: &[Ipv4Addr]) -> Result<()>;
}
