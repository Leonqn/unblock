use anyhow::Result;
use log::{error, info};
use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
};
use tokio::{net::UdpSocket, sync::mpsc::UnboundedSender};

use crate::unblock::{UnblockRequest, UnblockResponse};

use self::message::{Message, MessageType, ResourceData};

mod message;

pub async fn create_server(
    bind_addr: SocketAddr,
    dns_upstream_addr: SocketAddr,
    unblock_requests_tx: UnboundedSender<UnblockRequest>,
) -> Result<impl Future<Output = ()>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    Ok(messages_handler(
        socket,
        dns_upstream_addr,
        unblock_requests_tx,
    ))
}

async fn messages_handler(
    mut socket: UdpSocket,
    dns_upstream_addr: SocketAddr,
    unblock_requests_tx: UnboundedSender<UnblockRequest>,
) {
    let mut senders = HashMap::new();
    let mut buf = [0; 512];
    loop {
        let handle_message = async {
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
                        let (reply, response) = tokio::sync::oneshot::channel();
                        unblock_requests_tx
                            .send(UnblockRequest { ips, reply })
                            .expect("Receiver dropped");
                        if let UnblockResponse::Unblocked(ips) = response.await? {
                            info!("Unblocked {:?} from message {:?}", ips, message)
                        }
                        socket.send_to(dns_packet, &sender).await?;
                    }
                    Ok(())
                }
            }
        };

        if let Err(e) = handle_message.await {
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
