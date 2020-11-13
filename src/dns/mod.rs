use anyhow::Result;
use log::error;
use std::{collections::HashMap, future::Future, net::SocketAddr};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

use crate::unblock::{UnblockRequest, UnblockResponse};

use self::message::{Header, MessageType};

pub mod message;

pub async fn create_server(
    bind_addr: SocketAddr,
    dns_upstream_addr: SocketAddr,
    unblock_requests: UnboundedSender<UnblockRequest>,
    unblock_responses: UnboundedReceiver<UnblockResponse>,
) -> Result<impl Future<Output = ()>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    let send_socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let messages_handler = messages_handler(socket, dns_upstream_addr, unblock_requests);
    let unblock_responses_handler = unblock_responses_handler(send_socket, unblock_responses);
    Ok(async {
        tokio::join!(messages_handler, unblock_responses_handler);
    })
}

async fn messages_handler(
    mut socket: UdpSocket,
    dns_upstream_addr: SocketAddr,
    unblock_requests: UnboundedSender<UnblockRequest>,
) {
    let mut senders = HashMap::new();
    let mut buf = [0; 512];
    loop {
        let handle_message = async {
            let (bytes_read, sender) = socket.recv_from(&mut buf).await?;
            let dns_packet = &buf[0..bytes_read];
            let header = Header::from_packet(dns_packet)?;
            match header.flags.message_type {
                MessageType::Query => {
                    senders.insert(header.id, sender);
                    socket.send_to(dns_packet, &dns_upstream_addr).await?;
                }
                MessageType::Response => {
                    if let Some(sender) = senders.remove(&header.id) {
                        unblock_requests
                            .send(UnblockRequest {
                                dns_response: Vec::from(dns_packet),
                                sender,
                            })
                            .expect("Receiver dropped");
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        if let Err(e) = handle_message.await {
            error!("Got error while handling dns message: {:#}", e);
        }
    }
}

async fn unblock_responses_handler(
    mut socket: UdpSocket,
    mut unblock_responses: UnboundedReceiver<UnblockResponse>,
) {
    let message = unblock_responses.recv().await.expect("Sender dropped");
    let handle_message = async {
        match message {
            UnblockResponse::Completed(request) => {
                socket
                    .send_to(&request.dns_response, &request.sender)
                    .await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    if let Err(e) = handle_message.await {
        error!("Got error while sending dns response: {:#}", e);
    }
}
