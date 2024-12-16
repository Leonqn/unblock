use std::{collections::HashSet, net::Ipv4Addr};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use reqwest::{Body, Client, Url};
use serde::Deserialize;

use super::RouterClient;

pub struct KeeneticClient {
    http: Client,
    base_url: Url,
    vpn_interface: String,
}

impl KeeneticClient {
    pub fn new(base_url: Url, vpn_interface: String) -> Self {
        Self {
            http: Client::new(),
            base_url,
            vpn_interface,
        }
    }

    async fn remove_route(&self, addr: Ipv4Addr) -> Result<()> {
        let request_body = format!(
            r#"[{{"ip":{{"route":{{"auto":true,"interface":"{interface}","host":"{host}","no":true,"name":"{interface}"}}}}}},{{"system":{{"configuration":{{"save":true}}}}}}]"#,
            interface = &self.vpn_interface,
            host = addr
        );
        self.send_rci(request_body).await
    }

    async fn add_route(&self, addr: Ipv4Addr, comment: &str) -> Result<()> {
        let request_body = format!(
            r#"[{{"ip":{{"route":{{"auto":true,"interface":"{interface}","host":"{host}", "comment": "{comment}"}}}}}},{{"system":{{"configuration":{{"save":true}}}}}}]"#,
            interface = &self.vpn_interface,
            host = addr,
            comment = comment,
        );
        self.send_rci(request_body).await
    }

    async fn send_rci(&self, request_body: String) -> Result<()> {
        let response = self
            .http
            .post(self.base_url.join("/rci/")?)
            .body(Body::from(request_body))
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Got unsucessful response from router {}",
                response.text().await?
            ))
        }
    }
}
#[async_trait]
impl RouterClient for KeeneticClient {
    async fn get_routed(&self) -> Result<HashSet<Ipv4Addr>> {
        let response = self
            .http
            .get(self.base_url.join("/rci/ip/route")?)
            .send()
            .await?
            .bytes()
            .await?;
        let routes: Routes = serde_json::from_slice(&response)?;
        Ok(routes
            .routes()
            .into_iter()
            .flatten()
            .filter(|r| r.interface == self.vpn_interface)
            .filter_map(|r| r.host)
            .collect())
    }

    async fn add_routes(&self, ips: &[Ipv4Addr], comment: &str) -> Result<()> {
        let add_addrs_tasks = ips.iter().map(|addr| self.add_route(*addr, comment));
        futures_util::future::try_join_all(add_addrs_tasks).await?;
        Ok(())
    }

    async fn remove_route(&self, ip: Ipv4Addr) -> Result<()> {
        self.remove_route(ip).await?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Routes {
    Routes(Vec<Route>),
    None {},
}

impl Routes {
    fn routes(self) -> Option<Vec<Route>> {
        match self {
            Routes::Routes(r) => Some(r),
            Routes::None {} => None,
        }
    }
}

#[derive(Deserialize)]
struct Route {
    host: Option<Ipv4Addr>,
    interface: String,
}
