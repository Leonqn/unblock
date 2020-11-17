use std::{collections::HashMap, net::SocketAddr};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_util::stream::Stream;
use log::error;
use tokio::{
    net::{
        udp::{RecvHalf, SendHalf},
        UdpSocket,
    },
    stream::StreamExt,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
};

use crate::dns::message::Header;

pub struct UdpResponse {
    pub response: Vec<u8>,
}

pub struct UdpClient {
    socket: SendHalf,
    responses: UnboundedSender<ResponseWaiter>,
}

impl UdpClient {
    pub async fn new(server_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
        let (tx, rx) = unbounded_channel();
        socket.connect(server_addr).await?;
        let (recv, send) = socket.split();
        tokio::spawn(Self::responses_handler(recv, rx));

        Ok(Self {
            socket: send,
            responses: tx,
        })
    }

    pub async fn send(&mut self, request: &[u8]) -> Result<UdpResponse> {
        let header = Header::from_packet(&request)?;
        let (response_tx, response_rx) = oneshot::channel();
        self.responses
            .send(ResponseWaiter {
                id: header.id,
                waiter: response_tx,
            })
            .expect("Receiver dropped");
        self.socket.send(&request).await?;
        Ok(UdpResponse {
            response: response_rx
                .await
                .map_err(|_| anyhow!("Got multiple requests with the same id"))?,
        })
    }

    async fn responses_handler(socket: RecvHalf, waiters: UnboundedReceiver<ResponseWaiter>) {
        let mut msgs = Box::pin(create_udp_dns_stream(socket).map(WaiterOrResponse::Response))
            .merge(waiters.map(WaiterOrResponse::Waiter));
        let mut waiters = HashMap::new();
        loop {
            match msgs.next().await.expect("Should be infinite") {
                WaiterOrResponse::Waiter(waiter) => {
                    waiters.insert(waiter.id, waiter.waiter);
                }
                WaiterOrResponse::Response(response) => {
                    let handle_response = async {
                        let response = response?;
                        let header = Header::from_packet(&response)?;
                        if let Some(waiter) = waiters.remove(&header.id) {
                            let _ = waiter.send(response);
                        }
                        Ok::<_, anyhow::Error>(())
                    };
                    if let Err(err) = handle_response.await {
                        error!("Got error while handling dns message: {:#}", err);
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum WaiterOrResponse {
    Waiter(ResponseWaiter),
    Response(Result<Vec<u8>, tokio::io::Error>),
}

#[derive(Debug)]
struct ResponseWaiter {
    id: u16,
    waiter: oneshot::Sender<Vec<u8>>,
}

fn create_udp_dns_stream(
    socket: RecvHalf,
) -> impl Stream<Item = Result<Vec<u8>, tokio::io::Error>> {
    let buf = vec![0; 512];
    futures_util::stream::unfold((socket, buf), |(mut socket, mut buf)| async move {
        let recv = async {
            let read = socket.recv(&mut buf).await?;
            Ok(Vec::from(&buf[0..read]))
        };
        Some((recv.await, (socket, buf)))
    })
}

#[cfg(test)]
mod tests {
    use super::UdpClient;
    use crate::dns::message::Message;
    use anyhow::Result;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test() -> Result<()> {
        let request = include_bytes!("../../../test/dns_packets/q_api.browser.yandex.com.bin");
        let request_message = Message::from_packet(request.as_ref())?;
        let addr = "8.8.8.8:53".parse().unwrap();
        let mut udp = UdpClient::new(addr).await?;

        let response = udp.send(request).await?;
        let response_message = Message::from_packet(&response.response)?;

        assert_eq!(request_message.header.id, response_message.header.id);
        assert_eq!(request_message.questions, response_message.questions);
        Ok(())
    }
}
