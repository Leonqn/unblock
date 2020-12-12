use std::sync::atomic::{AtomicUsize, Ordering};

use super::DnsClient;
use crate::dns::message::{Query, Response};
use anyhow::Result;
use async_trait::async_trait;

pub struct RoundRobinClient {
    clients: Vec<Box<dyn DnsClient>>,
    counter: AtomicUsize,
}

impl RoundRobinClient {
    pub fn new(clients: Vec<Box<dyn DnsClient>>) -> Self {
        Self {
            clients,
            counter: AtomicUsize::default(),
        }
    }
}

#[async_trait]
impl DnsClient for RoundRobinClient {
    async fn send(&self, query: Query) -> Result<Response> {
        let client_idx = self.counter.fetch_add(1, Ordering::SeqCst) % self.clients.len();
        let client = &self.clients[client_idx];
        client.send(query).await
    }
}
