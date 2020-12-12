use anyhow::Result;

use async_trait::async_trait;

mod cache;
mod choice;
mod doh;
mod round_robin;
mod udp;

pub use cache::*;
pub use choice::*;
pub use doh::*;
pub use round_robin::*;
pub use udp::*;

use super::message::{Query, Response};

#[async_trait]
pub trait DnsClient: Send + Sync + 'static {
    async fn send(&self, query: Query) -> Result<Response>;
}
