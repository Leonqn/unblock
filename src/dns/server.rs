use anyhow::Result;
use log::error;
use std::{future::Future, net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tokio_stream::StreamExt;

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
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let mut requests = Box::pin(create_udp_dns_stream(socket.clone()));

    let requests_receiver = async move {
        loop {
            let request = requests.next().await.expect("Should be infinite");
            let handler = || {
                let (sender, request) = request?;
                let query = Query::from_bytes(request)?;
                let handler_fut = request_handler(query);
                let socket = socket.clone();
                tokio::spawn(async move {
                    let handle_and_send = async {
                        let response = handler_fut.await?;
                        socket.send_to(response.bytes(), &sender).await?;
                        Ok::<_, anyhow::Error>(())
                    };
                    if let Err(err) = handle_and_send.await {
                        error!("Error occured while sending response: {:#}", err);
                    }
                });
                Ok::<_, anyhow::Error>(())
            };
            if let Err(err) = handler() {
                error!("Error occured while receiving dns request: {:?}", err)
            }
        }
    };

    Ok(requests_receiver)
}
