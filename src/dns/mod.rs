use anyhow::Result;
use log::{error, info};
use std::{
    collections::HashMap,
    collections::HashSet,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;

use crate::{blacklist::Blacklist, router_client::RouterClient};

use self::message::{Message, MessageType, ResourceData};

mod message;

pub async fn create_server(
    bind_addr: SocketAddr,
    dns_upstream_addr: SocketAddr,
    router_client: Arc<RouterClient>,
    blacklist: Arc<Blacklist>,
) -> Result<impl Future<Output = ()>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    let whitelisted = router_client.get_routed().await?;
    Ok(requests_handler(
        socket,
        whitelisted,
        router_client,
        blacklist,
        dns_upstream_addr,
    ))
}

async fn requests_handler(
    mut socket: UdpSocket,
    whitelisted: HashSet<Ipv4Addr>,
    router_client: Arc<RouterClient>,
    blacklist: Arc<Blacklist>,
    dns_upstream_addr: SocketAddr,
) {
    let mut senders = HashMap::new();
    let mut buf = [0; 512];
    loop {
        let handle_request = async {
            let (bytes_read, sender) = socket.recv_from(&mut buf).await?;
            let dns_packet = &buf[0..bytes_read];
            let message = Message::from_packet(dns_packet)?;
            match message.header.flags.message_type {
                MessageType::Query => {
                    senders.insert(message.header.id, sender);
                    socket.send_to(dns_packet, &dns_upstream_addr).await?;
                    Ok::<(), anyhow::Error>(())
                }
                MessageType::Response => {
                    if let Some(sender) = senders.remove(&message.header.id) {
                        let blocked = find_blocked(&message, &whitelisted, &blacklist);
                        whitelist(&router_client, &message, &blocked).await?;
                        socket.send_to(dns_packet, &sender).await?;
                    }
                    Ok(())
                }
            }
        };

        if let Err(e) = handle_request.await {
            error!("Got error while handling request: {:#}", e);
        }
    }
}

fn find_blocked(
    message: &Message,
    whitelisted: &HashSet<Ipv4Addr>,
    blacklist: &Blacklist,
) -> Vec<Ipv4Addr> {
    message
        .answer
        .iter()
        .flatten()
        .filter_map(|r| {
            if let ResourceData::Ipv4(ip) = &r.data {
                Some(*ip)
            } else {
                None
            }
        })
        .filter(|ip| blacklist.contains(*ip) && !whitelisted.contains(ip))
        .collect()
}

async fn whitelist(
    router_client: &RouterClient,
    message: &Message<'_>,
    blocked: &[Ipv4Addr],
) -> Result<()> {
    if !blocked.is_empty() {
        router_client.add_routes(&blocked).await?;
        info!(
            "Whitelisted: {:?}, questions: {:?}",
            blocked, &message.questions
        )
    }
    Ok(())
}
