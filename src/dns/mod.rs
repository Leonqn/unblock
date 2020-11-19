use anyhow::Result;
use bytes::Bytes;
use futures_util::stream::Stream;
use log::error;
use std::{collections::HashMap, future::Future, net::SocketAddr};
use tokio::{
    net::{
        udp::{RecvHalf, SendHalf},
        UdpSocket,
    },
    stream::StreamExt,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

use crate::unblock::{UnblockRequest, UnblockResponse};

use self::message::{Header, MessageType};

pub mod client;
pub mod message;
pub mod server;

fn create_udp_dns_stream(
    socket: RecvHalf,
) -> impl Stream<Item = Result<(SocketAddr, Bytes), tokio::io::Error>> {
    let buf = vec![0; 512];
    futures_util::stream::unfold((socket, buf), |(mut socket, mut buf)| async move {
        let recv = async {
            let (read, sender) = socket.recv_from(&mut buf).await?;
            Ok((sender, Bytes::copy_from_slice(&buf[0..read])))
        };
        Some((recv.await, (socket, buf)))
    })
}

#[derive(Debug)]
enum Message {
    DnsPacket(Result<(Vec<u8>, SocketAddr), tokio::io::Error>),
    UnblockResponse(UnblockResponse),
}

pub async fn create_server(
    bind_addr: SocketAddr,
    dns_upstream_addr: SocketAddr,
    unblock_requests: UnboundedSender<UnblockRequest>,
    unblock_responses: UnboundedReceiver<UnblockResponse>,
) -> Result<impl Future<Output = ()>> {
    let (recv, send) = UdpSocket::bind(bind_addr).await?.split();
    let udp_stream = Box::pin(create_udp_dns_stream(recv));
    let messages = udp_stream
        .map(|r| r.map(|(s, b)| (b.to_vec(), s)))
        .map(Message::DnsPacket)
        .merge(unblock_responses.map(Message::UnblockResponse));
    let messages_handler = messages_handler(messages, send, dns_upstream_addr, unblock_requests);
    Ok(messages_handler)
}

async fn messages_handler(
    mut messages: impl Stream<Item = Message> + Unpin,
    mut socket: SendHalf,
    dns_upstream_addr: SocketAddr,
    unblock_requests: UnboundedSender<UnblockRequest>,
) {
    let mut senders = HashMap::new();
    loop {
        let handle_message = async {
            match messages.next().await.expect("Must be infinite") {
                Message::DnsPacket(dns_packet) => {
                    let (dns_packet, sender) = dns_packet?;
                    let header = Header::from_packet(&dns_packet)?;
                    match header.flags.message_type {
                        MessageType::Query => {
                            senders.insert(header.id, sender);
                            socket.send_to(&dns_packet, &dns_upstream_addr).await?;
                        }
                        MessageType::Response => {
                            if let Some(sender) = senders.remove(&header.id) {
                                unblock_requests
                                    .send(UnblockRequest {
                                        dns_response: dns_packet,
                                        sender,
                                    })
                                    .expect("Receiver dropped");
                            }
                        }
                    }
                }
                Message::UnblockResponse(UnblockResponse::Completed(request)) => {
                    socket
                        .send_to(&request.dns_response, &request.sender)
                        .await?;
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        if let Err(e) = handle_message.await {
            error!("Got error while handling dns message: {:#}", e);
        }
    }
}
