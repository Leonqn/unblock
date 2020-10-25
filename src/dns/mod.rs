use anyhow::Result;
use log::{error, info};
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    net::{
        udp::{RecvHalf, SendHalf},
        UdpSocket,
    },
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

use crate::whitelist::Whitelist;

use self::packet::DnsPacket;

mod packet;

pub async fn start_server(
    bind_addr: SocketAddr,
    dns_upstream_addr: SocketAddr,
    whitelist: Whitelist,
) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    let (recv_socket, send_socket) = socket.split();
    let (messages_tx, messages_rx) = tokio::sync::mpsc::unbounded_channel();
    let messages_handler = tokio::spawn(messages_handler(
        messages_rx,
        send_socket,
        whitelist,
        dns_upstream_addr,
    ));
    let requests_handler = tokio::spawn(requests_handler(recv_socket, messages_tx));
    tokio::try_join!(messages_handler, requests_handler)?;
    Ok(())
}

#[derive(Debug)]
pub struct Message {
    packet: DnsPacket,
    sender: SocketAddr,
}

async fn requests_handler(mut server: RecvHalf, messages_tx: UnboundedSender<Message>) {
    loop {
        let handle_request = async {
            let mut buf = [0; 512];
            let (bytes_read, sender) = server.recv_from(&mut buf).await?;
            messages_tx
                .send(Message {
                    packet: DnsPacket::new(buf, bytes_read),
                    sender,
                })
                .expect("Messages receiver dropped");
            Ok::<_, anyhow::Error>(())
        };
        if let Err(e) = handle_request.await {
            error!("Got error while handling request: {:#}", e);
        }
    }
}

async fn messages_handler(
    mut messages_rx: UnboundedReceiver<Message>,
    mut socket: SendHalf,
    mut whitelist: Whitelist,
    dns_upstream_addr: SocketAddr,
) {
    let mut senders = HashMap::new();
    let mut ips = Vec::new();
    let mut domains = Vec::new();
    loop {
        let Message { packet, sender } = messages_rx.recv().await.expect("Senders dropped");
        let handle_result = async {
            let packet_id = packet.id()?;

            if packet.is_response()? {
                if let Some(sender) = senders.remove(&packet_id) {
                    ips.clear();
                    packet.extract_ips(&mut ips)?;
                    match whitelist.whitelist(&ips).await?.as_slice() {
                        [] => {}
                        whitelisted => {
                            domains.clear();
                            packet.extract_domains(&mut domains)?;
                            info!(
                                "Whitelisted: domains - {:?}, ips - {:?}",
                                domains, whitelisted
                            );
                        }
                    }
                    socket.send_to(&packet.as_slice(), &sender).await?;
                }
                Ok::<(), anyhow::Error>(())
            } else {
                senders.insert(packet_id, sender);
                socket
                    .send_to(packet.as_slice(), &dns_upstream_addr)
                    .await?;
                Ok(())
            }
        };
        if let Err(err) = handle_result.await {
            error!("Got error while sending response: {:#}", err);
        }
    }
}
