use anyhow::Result;
use log::error;
use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
};
use tokio::{net::UdpSocket, sync::mpsc::UnboundedSender};

use self::message::{Message, MessageType, ResourceData};

mod message;

pub async fn create_server(
    bind_addr: SocketAddr,
    dns_upstream_addr: SocketAddr,
    ips_sender: UnboundedSender<Vec<Ipv4Addr>>,
) -> Result<impl Future<Output = ()>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    Ok(requests_handler(socket, dns_upstream_addr, ips_sender))
}

async fn requests_handler(
    mut socket: UdpSocket,
    dns_upstream_addr: SocketAddr,
    ips_sender: UnboundedSender<Vec<Ipv4Addr>>,
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
                        let ips = get_ips(&message);
                        ips_sender.send(ips).expect("Receiver dropped");
                        socket.send_to(dns_packet, &sender).await?;
                    }
                    Ok(())
                }
            }
        };

        if let Err(e) = handle_request.await {
            error!("Got error while handling dns message: {:#}", e);
        }
    }
}

fn get_ips(message: &Message) -> Vec<Ipv4Addr> {
    message
        .answer
        .iter()
        .chain(&message.authority)
        .chain(&message.additional)
        .flatten()
        .filter_map(|r| {
            if let ResourceData::Ipv4(ip) = &r.data {
                Some(*ip)
            } else {
                None
            }
        })
        .collect()
}
