use anyhow::Result;

use async_trait::async_trait;

mod cache;
mod doh;
mod udp;

pub use cache::*;
pub use doh::*;
pub use udp::*;

use super::message::{Query, Response};

#[async_trait]
pub trait DnsClient: Send + Sync {
    async fn send(&self, query: Query) -> Result<Response>;
}
