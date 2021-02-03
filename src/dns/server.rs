use anyhow::Result;
use log::error;
use prometheus::{register_histogram, register_int_counter, Histogram, IntCounter};
use std::{future::Future, net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tokio_stream::StreamExt;

use super::{
    create_udp_dns_stream,
    message::{Query, Response},
    metrics::PerDomainCounter,
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
    let metrics = Arc::new(Metrics::new());
    let requests_receiver = async move {
        loop {
            let request = requests.next().await.expect("Should be infinite");
            let timer = metrics.response_time.start_timer();
            let handler = || {
                let (sender, request) = request?;
                let query = Query::from_bytes(request)?;
                for domain in query.parse()?.domains() {
                    metrics.requests_count.inc(&domain);
                }
                let handler_fut = request_handler(query);
                let socket = socket.clone();
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    let handle_and_send = async {
                        let response = handler_fut.await?;
                        socket.send_to(response.bytes(), &sender).await?;
                        Ok::<_, anyhow::Error>(())
                    };
                    if let Err(err) = handle_and_send.await {
                        metrics.handling_errors.inc();
                        error!("Error occured while sending response: {:#}", err);
                    }
                    timer.observe_duration();
                });
                Ok::<_, anyhow::Error>(())
            };
            if let Err(err) = handler() {
                metrics.requests_errors.inc();
                error!("Error occured while receiving dns request: {:#}", err)
            }
        }
    };

    Ok(requests_receiver)
}

struct Metrics {
    requests_count: PerDomainCounter,
    requests_errors: IntCounter,
    handling_errors: IntCounter,
    response_time: Histogram,
}

impl Metrics {
    fn new() -> Self {
        Metrics {
            requests_count: PerDomainCounter::new("requests_count"),
            requests_errors: register_int_counter!("request_errors", "request_errors").unwrap(),
            handling_errors: register_int_counter!("handling_errors", "handling_errors").unwrap(),
            response_time: register_histogram!("response_time", "response_time").unwrap(),
        }
    }
}
