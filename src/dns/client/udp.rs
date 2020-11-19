use std::{collections::HashMap, net::SocketAddr};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::Stream;
use log::error;
use tokio::{
    net::{udp::RecvHalf, UdpSocket},
    stream::StreamExt,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
};

use crate::dns::message::Header;

use super::{DnsClient, DnsRequest, DnsResponse};

pub struct UdpClient {
    responses: UnboundedSender<ResponseWaiter>,
}

impl UdpClient {
    pub async fn new(server_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
        let (tx, rx) = unbounded_channel();
        socket.connect(server_addr).await?;
        tokio::spawn(responses_handler(socket, rx));

        Ok(Self { responses: tx })
    }
}

#[async_trait]
impl DnsClient for UdpClient {
    async fn send(&self, request: &DnsRequest) -> Result<DnsResponse> {
        let (response_tx, response_rx) = oneshot::channel();
        self.responses
            .send(ResponseWaiter {
                request: request.clone(),
                waiter: response_tx,
            })
            .expect("Receiver dropped");
        DnsResponse::from_bytes(response_rx.await.expect("Should always receive response")?)
    }
}

#[derive(Debug)]
enum ClientMessage {
    Waiter(ResponseWaiter),
    Response(Result<Bytes, tokio::io::Error>),
}

#[derive(Debug)]
struct ResponseWaiter {
    request: DnsRequest,
    waiter: oneshot::Sender<Result<Bytes>>,
}

async fn responses_handler(socket: UdpSocket, waiters: UnboundedReceiver<ResponseWaiter>) {
    let (recv, mut send) = socket.split();
    let mut msgs = Box::pin(create_udp_dns_stream(recv).map(ClientMessage::Response))
        .merge(waiters.map(ClientMessage::Waiter));
    let mut waiters = HashMap::new();
    loop {
        let handle_response = async {
            match msgs.next().await.expect("Should be infinite") {
                ClientMessage::Waiter(waiter) => {
                    if let Some(prev_waiter) =
                        waiters.insert(waiter.request.header().id, waiter.waiter)
                    {
                        let _ = prev_waiter.send(Err(anyhow!("Dublicate request id")));
                    }

                    send.send(&waiter.request.bytes()).await?;
                }
                ClientMessage::Response(response) => {
                    let response = response?;
                    let header = Header::from_packet(&response)?;
                    if let Some(waiter) = waiters.remove(&header.id) {
                        let _ = waiter.send(Ok(response));
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        if let Err(err) = handle_response.await {
            error!("Got error while handling dns message: {:#}", err);
        }
    }
}

fn create_udp_dns_stream(socket: RecvHalf) -> impl Stream<Item = Result<Bytes, tokio::io::Error>> {
    let buf = vec![0; 512];
    futures_util::stream::unfold((socket, buf), |(mut socket, mut buf)| async move {
        let recv = async {
            let read = socket.recv(&mut buf).await?;
            Ok(Bytes::copy_from_slice(&buf[0..read]))
        };
        Some((recv.await, (socket, buf)))
    })
}

#[cfg(test)]
mod tests {
    use super::UdpClient;
    use crate::dns::{
        client::{DnsClient, DnsRequest},
        message::Message,
    };
    use anyhow::Result;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_google_udp() -> Result<()> {
        let request = include_bytes!("../../../test/dns_packets/q_api.browser.yandex.com.bin");
        let request_message = Message::from_packet(request.as_ref())?;
        let addr = "8.8.8.8:53".parse().unwrap();
        let udp = UdpClient::new(addr).await?;
        let request = DnsRequest::from_bytes(Bytes::from_static(request))?;
        let response = udp.send(&request).await?;
        let response_message = Message::from_packet(&response.bytes())?;

        assert_eq!(request_message.header.id, response_message.header.id);
        assert_eq!(request_message.questions, response_message.questions);
        Ok(())
    }
}
