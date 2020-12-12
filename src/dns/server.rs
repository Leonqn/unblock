use anyhow::Result;
use log::error;
use std::{future::Future, net::SocketAddr};
use tokio::{
    net::{udp::SendHalf, UdpSocket},
    stream::StreamExt,
    sync::mpsc::{unbounded_channel, UnboundedReceiver},
};

use super::{
    create_udp_dns_stream,
    message::{Query, Response},
};

pub async fn create_udp_server<Handler, HandlerResp>(
    bind_addr: SocketAddr,
    request_handler: Handler,
) -> Result<impl Future<Output = ()> + Send + 'static>
where
    Handler: Fn(Query) -> HandlerResp + Send + Sync + 'static,
    HandlerResp: Future<Output = Result<Response>> + Send + 'static,
{
    let (recv, send) = UdpSocket::bind(bind_addr).await?.split();
    let (responses_tx, responses_rx) = unbounded_channel();
    let mut requests = Box::pin(create_udp_dns_stream(recv));

    let requests_receiver = async move {
        loop {
            let request = requests.next().await.expect("Should be infinite");
            let handler = async {
                let (sender, request) = request?;
                let responses_tx = responses_tx.clone();
                let query = Query::from_bytes(request)?;
                let handler_fut = request_handler(query);
                tokio::spawn(async move {
                    let response = handler_fut.await;
                    responses_tx
                        .send((sender, response))
                        .expect("Receiver dropped");
                });
                Ok::<_, anyhow::Error>(())
            };
            if let Err(err) = handler.await {
                error!("Error occured while receiving dns request: {:#}", err)
            }
        }
    };

    let server = async {
        let responses_sender = responses_sender(send, responses_rx);
        tokio::join!(requests_receiver, responses_sender);
    };

    Ok(server)
}

async fn responses_sender(
    mut send_half: SendHalf,
    mut responses: UnboundedReceiver<(SocketAddr, Result<Response>)>,
) {
    loop {
        let (sender, response) = responses.recv().await.expect("Sender dropped");
        let send_response = async {
            send_half.send_to(response?.bytes(), &sender).await?;
            Ok::<_, anyhow::Error>(())
        };
        if let Err(err) = send_response.await {
            error!("Error occured while sending response: {:#}", err)
        }
    }
}