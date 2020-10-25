use anyhow::{anyhow, Context, Result};
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

mod packet;

pub async fn start_server(
    bind_addr: SocketAddr,
    dns_upstream_addr: SocketAddr,
    whitelist: Whitelist,
) -> Result<()> {
    let client_addr: SocketAddr = "0.0.0.0:0".parse()?;
    let server = UdpSocket::bind(bind_addr).await?;
    let client = UdpSocket::bind(client_addr).await?;
    client.connect(dns_upstream_addr).await?;
    let (client_recv, client_send) = client.split();
    let (server_recv, server_send) = server.split();
    let (messages_tx, messages_rx) = tokio::sync::mpsc::unbounded_channel();
    let messages_handler = tokio::spawn(messages_handler(
        messages_rx,
        server_send,
        client_send,
        whitelist,
    ));
    let dns_responses_handler = tokio::spawn(responses_receiver(client_recv, messages_tx.clone()));
    let requests_handler = tokio::spawn(requests_handler(server_recv, messages_tx));
    tokio::try_join!(messages_handler, dns_responses_handler, requests_handler)?;
    Ok(())
}

#[derive(Debug)]
struct ArraySlice {
    buf: [u8; 512],
    size: usize,
}

impl ArraySlice {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[0..self.size]
    }
}

#[derive(Debug)]
enum DnsMessage {
    Request {
        packet: ArraySlice,
        sender: SocketAddr,
    },
    Response {
        packet: ArraySlice,
    },
}

async fn requests_handler(mut server: RecvHalf, messages_tx: UnboundedSender<DnsMessage>) {
    loop {
        let handle_request = async {
            let mut buf = [0; 512];
            let (bytes_read, sender) = server.recv_from(&mut buf).await?;
            messages_tx
                .send(DnsMessage::Request {
                    packet: ArraySlice {
                        buf,
                        size: bytes_read,
                    },
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

async fn responses_receiver(mut dns_upstream: RecvHalf, messages_tx: UnboundedSender<DnsMessage>) {
    loop {
        let recv_message = async {
            let mut buf = [0; 512];
            let bytes_read = dns_upstream.recv(&mut buf).await?;
            messages_tx
                .send(DnsMessage::Response {
                    packet: ArraySlice {
                        buf,
                        size: bytes_read,
                    },
                })
                .expect("Messages receiver dropped");
            Ok::<_, anyhow::Error>(())
        };
        if let Err(err) = recv_message.await {
            error!(
                "Got error while receiving response from upstream: {:#}",
                err
            )
        }
    }
}

async fn messages_handler(
    mut messages_rx: UnboundedReceiver<DnsMessage>,
    mut dns_server: SendHalf,
    mut dns_client: SendHalf,
    mut whitelist: Whitelist,
) {
    let mut senders = HashMap::new();
    let mut ips = Vec::new();
    let mut domains = Vec::new();

    while let Some(message) = messages_rx.recv().await {
        let handle_result = match message {
            DnsMessage::Request { packet, sender } => {
                async {
                    let packet_id = packet::get_id(packet.as_slice())?;
                    senders.insert(packet_id, sender);
                    dns_client.send(packet.as_slice()).await?;
                    Ok(())
                }
                .await
            }
            DnsMessage::Response { packet } => {
                async {
                    let id = packet::get_id(packet.as_slice())?;
                    let sender = senders
                        .remove(&id)
                        .ok_or_else(|| anyhow!("Sender for request with id ({}) missing", id))?;
                    ips.clear();
                    packet::extract_ips(&packet.as_slice(), &mut ips)
                        .with_context(|| format!("Received packet: {:x?}", packet.as_slice()))?;
                    match whitelist.whitelist(&ips).await?.as_slice() {
                        [] => {}
                        [whitelisted @ ..] => {
                            domains.clear();
                            packet::extract_domains(&packet.as_slice(), &mut domains)?;
                            info!(
                                "Whitelisted: domains - {:?}, ips - {:?}",
                                domains, whitelisted
                            );
                        }
                    }
                    dns_server.send_to(&packet.as_slice(), &sender).await?;
                    Ok::<(), anyhow::Error>(())
                }
                .await
            }
        };
        if let Err(err) = handle_result {
            error!("Got error while sending response {:#}", err);
        }
    }
}
