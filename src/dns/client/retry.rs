use std::time::Duration;

use super::DnsClient;
use crate::dns::message::{Query, Response};
use anyhow::Result;
use async_trait::async_trait;
use fure::policies::{attempts, interval};

pub struct RetryClient<C> {
    client: C,
    attempts_count: usize,
    next_attempt_delay: Duration,
}

impl<C> RetryClient<C> {
    pub fn new(client: C, attempts_count: usize, next_attempt_delay: Duration) -> Self {
        Self {
            client,
            attempts_count,
            next_attempt_delay,
        }
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for RetryClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        fure::retry(
            || self.client.send(query.clone()),
            attempts(interval(self.next_attempt_delay), self.attempts_count),
        )
        .await
    }
}
