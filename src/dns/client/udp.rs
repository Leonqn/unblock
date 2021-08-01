use std::{
    collections::{hash_map::Entry, HashMap},
    net::SocketAddr,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::error;
use tokio::{
    net::UdpSocket,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
};
use tokio_stream::StreamExt;

use crate::dns::{
    create_udp_dns_stream,
    message::{Message, Query, Response},
};

use super::DnsClient;

pub struct UdpClient {
    responses: UnboundedSender<Request>,
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
            .send(Request {
                query,
                waiter: response_tx,
            })
            .expect("Receiver dropped");
        response_rx.await.expect("Should always receive response")
    }
}

#[derive(Debug)]
struct Request {
    query: Query,
    waiter: oneshot::Sender<Result<Response>>,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct RequestId {
    id: u16,
    addr: Vec<String>,
}

impl RequestId {
    fn from_message(message: &Message) -> Self {
        Self {
            id: message.header.id,
            addr: message.domains().collect(),
        }
    }
}

async fn responses_handler(socket: UdpSocket, mut requests: UnboundedReceiver<Request>) {
    let socket = Arc::new(socket);
    let mut udp_stream = Box::pin(create_udp_dns_stream(socket.clone()));
    let mut waiting_requests = HashMap::new();

    loop {
        let handler = async {
            tokio::select! {
                    Some(request) = requests.recv() => {
                        process_request(&mut waiting_requests, &socket, request).await;
                    }
                    Some(response) = udp_stream.next() => {
                        let (_, response) = response?;
                        let response = Response::from_bytes(response)?;
                        process_response(&mut waiting_requests, response).await;

                }
            }
            Ok::<_, anyhow::Error>(())
        };
        if let Err(err) = handler.await {
            error!("Got error while handling dns message: {:#}", err);
        }
    }
}

async fn process_request(
    waiting_requests: &mut HashMap<RequestId, Request>,
    socket: &UdpSocket,
    request: Request,
) {
    let send_and_parse = async {
        let message = request.query.parse()?;
        socket.send(request.query.bytes()).await?;
        Ok(message)
    };
    match send_and_parse.await {
        Ok(message) => match waiting_requests.entry(RequestId::from_message(&message)) {
            Entry::Occupied(mut prev_request) => {
                let err = Err(anyhow!(
                    "Dublicate request id. Previous query: {:?}. Current query: {:?}",
                    prev_request.get().query.parse(),
                    message
                ));
                let prev_request = prev_request.insert(request);
                let _ = prev_request.waiter.send(err);
            }
            Entry::Vacant(x) => {
                x.insert(request);
            }
        },
        Err(err) => {
            let _ = request.waiter.send(Err(err));
        }
    }
}

async fn process_response(waiting_requests: &mut HashMap<RequestId, Request>, response: Response) {
    let message = response.parse();
    match message {
        Ok(message) => {
            if let Some(request) = waiting_requests.remove(&RequestId::from_message(&message)) {
                let _ = request.waiter.send(Ok(response));
            } else {
                error!("Request from response {:?} missing", message);
            }
        }
        Err(err) => {
            error!("Bad dns response: {:?}", err)
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
