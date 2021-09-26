use anyhow::Result;
use bytes::Bytes;
use log::error;
use once_cell::sync::Lazy;
use prometheus::{register_histogram, register_int_counter, Histogram, IntCounter};
use std::{future::Future, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tokio_stream::StreamExt;

use super::{
    create_udp_dns_stream,
    message::{Query, Response},
};

pub async fn create_tcp_server<Handler, HandlerResp>(
    bind_addr: SocketAddr,
    request_handler: Handler,
) -> Result<impl Future<Output = ()> + Send + 'static>
where
    Handler: Fn(Query) -> HandlerResp + Clone + Send + Sync + 'static,
    HandlerResp: Future<Output = Result<Response>> + Send + 'static,
{
    let listener = Arc::new(TcpListener::bind(bind_addr).await?);
    let requests_loop = async move {
        loop {
            let accept_result = listener.accept().await;
            let request_handler = request_handler.clone();
            let handle_request = async move {
                let (mut socket, _) = accept_result?;
                let mut buf = vec![];
                socket.read_to_end(&mut buf).await?;
                let bytes = Bytes::copy_from_slice(&buf);
                let query = Query::from_bytes(bytes)?;
                let response = request_handler(query).await?;
                socket.write_all(response.bytes()).await?;
                Ok::<_, anyhow::Error>(())
            };
            tokio::spawn(async move {
                if let Err(err) = handle_request.await {
                    error!("Error occured while receiving dns tcp request: {:#}", err);
                }
            });
        }
    };
    Ok(requests_loop)
}

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
            let timer = METRICS.response_time.start_timer();
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
                        METRICS.handling_errors.inc();
                        error!("Error occured while sending response: {:#}", err);
                    }
                    timer.observe_duration();
                });
                Ok::<_, anyhow::Error>(())
            };
            if let Err(err) = handler() {
                METRICS.requests_errors.inc();
                error!("Error occured while receiving dns request: {:#}", err)
            }
        }
    };

    Ok(requests_receiver)
}

static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);

struct Metrics {
    requests_errors: IntCounter,
    handling_errors: IntCounter,
    response_time: Histogram,
}

impl Metrics {
    fn new() -> Self {
        Metrics {
            requests_errors: register_int_counter!("requests_errors", "request_errors").unwrap(),
            handling_errors: register_int_counter!("handling_errors", "handling_errors").unwrap(),
            response_time: register_histogram!("response_time", "response_time").unwrap(),
        }
    }
}
