use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use log::info;

use super::DnsClient;
use crate::dns::message::{Query, Response};

pub struct HostsClient<C> {
    client: C,
    hosts: Arc<ArcSwapOption<HashMap<String, Ipv4Addr>>>,
}

impl<C> HostsClient<C> {
    pub fn new(client: C, hosts: Arc<ArcSwapOption<HashMap<String, Ipv4Addr>>>) -> Self {
        Self { client, hosts }
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for HostsClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        let hosts = self.hosts.load();
        if let Some(hosts) = hosts.as_deref() {
            if let Ok(parsed) = query.parse() {
                for domain in parsed.domains() {
                    if let Some(&ip) = hosts.get(&domain) {
                        info!("hosts: {} -> {}", domain, ip);
                        let mut response = if query.is_aaaa() {
                            query.empty_response()
                        } else {
                            query.response_with_ip(ip)
                        };
                        response.append_trace(&format!("hosts: {ip}"));
                        return Ok(response);
                    }
                }
            }
        }
        self.client.send(query).await
    }
}
