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
    message::{Query, Response},
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
    waiting_requests: &mut HashMap<u16, Request>,
    socket: &UdpSocket,
    request: Request,
) {
    if let Err(err) = socket.send(&request.query.bytes()).await {
        let _ = request.waiter.send(Err(err.into()));
    } else {
        match waiting_requests.entry(request.query.header().id) {
            Entry::Occupied(mut prev_request) => {
                let err = Err(anyhow!(
                    "Dublicate request id. Previous query: {:?}. Current query: {:?}",
                    prev_request.get().query.parse(),
                    request.query.parse()
                ));
                let prev_request = prev_request.insert(request);
                let _ = prev_request.waiter.send(err);
            }
            Entry::Vacant(x) => {
                x.insert(request);
            }
        }
    }
}

async fn process_response(waiting_requests: &mut HashMap<u16, Request>, response: Response) {
    if let Some(request) = waiting_requests.remove(&response.header().id) {
        let response = (|| {
            let parsed_query = request.query.parse()?;
            let query_domains = parsed_query.domains();
            let parsed_response = response.parse()?;
            let response_domains = parsed_response.domains();
            if query_domains.eq(response_domains) {
                Ok(response)
            } else {
                Err(anyhow!(
                    "Request and response domains don't match. Query: {:?}. Response: {:?}",
                    parsed_query,
                    parsed_response
                ))
            }
        })();
        let _ = request.waiter.send(response);
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
