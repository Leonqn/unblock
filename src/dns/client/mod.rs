use anyhow::Result;

use async_trait::async_trait;

mod ads_block;
mod cache;
mod choice;
mod doh;
mod either;
mod retry;
mod round_robin;
mod udp;
mod unblock;

use super::message::{Query, Response};
pub use ads_block::*;
pub use cache::*;
pub use choice::*;
pub use doh::*;
pub use either::*;
pub use retry::*;
pub use round_robin::*;
pub use udp::*;
pub use unblock::*;

#[async_trait]
pub trait DnsClient: Send + Sync + 'static {
    async fn send(&self, query: Query) -> Result<Response>;
}
