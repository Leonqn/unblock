use std::{collections::HashSet, net::Ipv4Addr};

use anyhow::{anyhow, Result};
use reqwest::{Body, Client, Url};
use serde::Deserialize;

pub struct RouterClient {
    http: Client,
    base_url: Url,
    vpn_interface: String,
}

impl RouterClient {
    pub fn new(base_url: Url, vpn_interface: String) -> Self {
        Self {
            http: Client::new(),
            base_url,
            vpn_interface,
        }
    }

    pub async fn get_routed(&self) -> Result<HashSet<Ipv4Addr>> {
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
            .map(|r| r.host)
            .collect())
    }

    pub async fn add_routes(&self, addrs: &[Ipv4Addr]) -> Result<()> {
        let add_addrs_tasks = addrs.iter().map(|addr| self.add_route(*addr));
        futures_util::future::try_join_all(add_addrs_tasks).await?;
        Ok(())
    }

    pub async fn remove_routes(&self, addrs: &[Ipv4Addr]) -> Result<()> {
        let romove_addrs_tasks = addrs.iter().map(|addr| self.remove_route(*addr));
        futures_util::future::try_join_all(romove_addrs_tasks).await?;
        Ok(())
    }

    async fn remove_route(&self, addr: Ipv4Addr) -> Result<()> {
        let request_body = format!(
            r#"[{{"ip":{{"route":{{"auto":false,"interface":"{interface}","host":"{host}","no":true,"name":"{interface}"}}}}}},{{"system":{{"configuration":{{"save":true}}}}}}]"#,
            interface = &self.vpn_interface,
            host = addr
        );
        self.send_rci(request_body).await
    }

    async fn add_route(&self, addr: Ipv4Addr) -> Result<()> {
        let request_body = format!(
            r#"[{{"ip":{{"route":{{"auto":false,"interface":"{interface}","host":"{host}"}}}}}},{{"system":{{"configuration":{{"save":true}}}}}}]"#,
            interface = &self.vpn_interface,
            host = addr
        );
        self.send_rci(request_body).await
    }

    async fn send_rci(&self, request_body: String) -> Result<()> {
        let response = self
            .http
            .post(self.base_url.join("/rci")?)
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
    host: Ipv4Addr,
    interface: String,
}
