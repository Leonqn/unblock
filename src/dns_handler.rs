use anyhow::Result;
use std::sync::Arc;

use crate::{
    dns::{
        client::DnsClient,
        message::{Query, Response},
    },
    unblock::Unblocker,
};

pub async fn handle_query(
    query: Query,
    unblocker: Arc<Unblocker>,
    dns_client: Arc<impl DnsClient + Send + Sync + 'static>,
) -> Result<Response> {
    let dns_response = dns_client.send(&query).await?;
    let parsed_response = dns_response.parse()?;
    unblocker.unblock(parsed_response.ips().collect()).await?;
    Ok(dns_response)
}
