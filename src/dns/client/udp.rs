use std::{collections::HashMap, net::SocketAddr};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use log::error;
use tokio::{
    net::UdpSocket,
    stream::StreamExt,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
};

use crate::dns::{
    create_udp_dns_stream,
    message::{Header, Query, Response},
};

use super::DnsClient;

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
    async fn send(&self, query: Query) -> Result<Response> {
        let (response_tx, response_rx) = oneshot::channel();
        self.responses
            .send(ResponseWaiter {
                request: query,
                waiter: response_tx,
            })
            .expect("Receiver dropped");
        Response::from_bytes(response_rx.await.expect("Should always receive response")?)
    }
}

#[derive(Debug)]
enum ClientMessage {
    Waiter(ResponseWaiter),
    Response(Result<Bytes, tokio::io::Error>),
}

#[derive(Debug)]
struct ResponseWaiter {
    request: Query,
    waiter: oneshot::Sender<Result<Bytes>>,
}

async fn responses_handler(socket: UdpSocket, waiters: UnboundedReceiver<ResponseWaiter>) {
    let (recv, mut send) = socket.split();
    let mut msgs = Box::pin(
        create_udp_dns_stream(recv)
            .map(|r| r.map(|(_, b)| b))
            .map(ClientMessage::Response),
    )
    .merge(waiters.map(ClientMessage::Waiter));
    let mut waiters = HashMap::new();
    loop {
        let handle_response = async {
            match msgs.next().await.expect("Should be infinite") {
                ClientMessage::Waiter(waiter) => {
                    let request = waiter.request.clone();
                    if let Some(prev_waiter) = waiters.insert(waiter.request.header().id, waiter) {
                        let _ = prev_waiter.waiter.send(Err(anyhow!("Dublicate request id")
                            .context(format!("prev: {:?}", prev_waiter.request.parse()))
                            .context(format!("cur: {:?}", request.parse()))));
                    }

                    send.send(&request.bytes()).await?;
                }
                ClientMessage::Response(response) => {
                    let response = response?;
                    let header = Header::from_packet(&response)?;
                    if let Some(waiter) = waiters.remove(&header.id) {
                        let _ = waiter.waiter.send(Ok(response));
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

#[cfg(test)]
mod tests {
    use super::UdpClient;
    use crate::dns::{client::DnsClient, message::Query};
    use anyhow::Result;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_google_udp() -> Result<()> {
        let request = include_bytes!("../../../test/dns_packets/q_api.browser.yandex.com.bin");
        let request = Query::from_bytes(Bytes::from_static(request))?;
        let request_message = request.parse()?;
        let addr = "8.8.8.8:53".parse().unwrap();
        let udp = UdpClient::new(addr).await?;

        let response = udp.send(request.clone()).await?;
        let response_message = response.parse()?;

        assert_eq!(request_message.header.id, response_message.header.id);
        assert_eq!(request_message.questions, response_message.questions);
        Ok(())
    }
}
