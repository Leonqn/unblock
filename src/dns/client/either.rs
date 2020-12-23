use crate::dns::message::{Query, Response};

use super::DnsClient;
use anyhow::Result;
use async_trait::async_trait;

pub enum Either<A, B> {
    Left(A),
    Right(B),
}

#[async_trait]
impl<A: DnsClient, B: DnsClient> DnsClient for Either<A, B> {
    async fn send(&self, query: Query) -> Result<Response> {
        match self {
            Either::Left(l) => l.send(query).await,
            Either::Right(r) => r.send(query).await,
        }
    }
}
