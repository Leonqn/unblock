use anyhow::Result;
use log::{error, info};
use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
};
use tokio::net::UdpSocket;

use crate::whitelist::Whitelist;

mod packet;

pub async fn create_server(
    bind_addr: SocketAddr,
    dns_upstream_addr: SocketAddr,
    whitelist: Whitelist,
) -> Result<impl Future<Output = ()>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    Ok(requests_handler(socket, whitelist, dns_upstream_addr))
}

async fn requests_handler(
    mut socket: UdpSocket,
    mut whitelist: Whitelist,
    dns_upstream_addr: SocketAddr,
) {
    let mut senders = HashMap::new();
    let mut ips = Vec::new();
    let mut domains = Vec::new();
    let mut buf = [0; 512];
    loop {
        let handle_request = async {
            let (bytes_read, sender) = socket.recv_from(&mut buf).await?;
            let dns_packet = &buf[0..bytes_read];
            let packet_id = packet::get_id(dns_packet)?;

            if packet::is_response(dns_packet)? {
                if let Some(sender) = senders.remove(&packet_id) {
                    whitelist_if_needed(dns_packet, &mut whitelist, &mut ips, &mut domains).await?;
                    socket.send_to(dns_packet, &sender).await?;
                }
                Ok::<(), anyhow::Error>(())
            } else {
                senders.insert(packet_id, sender);
                socket.send_to(dns_packet, &dns_upstream_addr).await?;
                Ok(())
            }
        };

        if let Err(e) = handle_request.await {
            error!("Got error while handling request: {:#}", e);
        }
    }
}

async fn whitelist_if_needed(
    dns_packet: &[u8],
    whitelist: &mut Whitelist,
    ips: &mut Vec<Ipv4Addr>,
    domains: &mut Vec<String>,
) -> Result<()> {
    ips.clear();
    domains.clear();
    packet::extract_ips(dns_packet, ips)?;
    match whitelist.whitelist(&ips).await?.as_slice() {
        [] => {}
        whitelisted => {
            domains.clear();
            packet::extract_domains(dns_packet, domains)?;
            info!(
                "Whitelisted: domains - {:?}, ips - {:?}",
                domains, whitelisted
            );
        }
    }
    Ok(())
}
