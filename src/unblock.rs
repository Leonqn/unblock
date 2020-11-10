use std::{collections::HashSet, future::Future, net::Ipv4Addr};

use anyhow::Result;
use log::{error, info};
use tokio::{
    stream::{Stream, StreamExt},
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

use crate::router_client::RouterClient;

#[derive(Debug)]
pub enum UnblockResponse {
    Unblocked(Vec<Ipv4Addr>),
    Skipped,
}

#[derive(Debug)]
pub struct UnblockRequest {
    pub ips: Vec<Ipv4Addr>,
    pub reply: tokio::sync::oneshot::Sender<UnblockResponse>,
}

pub async fn create_unblocker(
    blaklist_rx: UnboundedReceiver<HashSet<Ipv4Addr>>,
    unblock_requests_rx: UnboundedReceiver<UnblockRequest>,
    router_client: RouterClient,
) -> Result<impl Future<Output = ()>> {
    let unblocked = router_client.get_routed().await?;
    let (router_requests_tx, router_requests_rx) = tokio::sync::mpsc::unbounded_channel();
    let (router_responses_tx, router_responses_rx) = tokio::sync::mpsc::unbounded_channel();
    let messages = merge_rxs(unblock_requests_rx, blaklist_rx, router_responses_rx);

    let router_handler = router_handler(router_client, router_requests_rx, router_responses_tx);
    let unblocker = unblocker(messages, router_requests_tx, unblocked);
    Ok(async move {
        tokio::join!(router_handler, unblocker);
    })
}

enum Message {
    UnblockRequest(UnblockRequest),
    Blacklist(HashSet<Ipv4Addr>),
    RouterResponse(RouterResponse),
}

async fn unblocker(
    mut messages: impl Stream<Item = Message> + Unpin,
    router_requests_tx: UnboundedSender<RouterRequest>,
    mut unblocked: HashSet<Ipv4Addr>,
) {
    let mut blacklist = HashSet::new();
    loop {
        let handle_message = async {
            match messages.next().await.expect("Senders dropped") {
                Message::UnblockRequest(request) => {
                    let blocked = request
                        .ips
                        .iter()
                        .filter(|ip| blacklist.contains(*ip) && !unblocked.contains(&ip))
                        .copied()
                        .collect::<Vec<_>>();
                    if !blocked.is_empty() {
                        router_requests_tx
                            .send(RouterRequest::Add(request))
                            .expect("Receiver dropped");
                    } else {
                        let _ = request.reply.send(UnblockResponse::Skipped);
                    }
                }
                Message::Blacklist(new_blacklist) => {
                    info!("Received blacklist with {} items", new_blacklist.len());
                    blacklist = new_blacklist;
                    let removed = unblocked
                        .difference(&blacklist)
                        .copied()
                        .collect::<Vec<_>>();
                    if !removed.is_empty() {
                        router_requests_tx
                            .send(RouterRequest::Remove(removed))
                            .expect("Receiver dropped");
                    }
                }

                Message::RouterResponse(RouterResponse::Added(request)) => {
                    unblocked.extend(request.ips.iter().copied());
                    let _ = request.reply.send(UnblockResponse::Unblocked(request.ips));
                }
                Message::RouterResponse(RouterResponse::Removed(addrs)) => {
                    for ip in addrs {
                        unblocked.remove(&ip);
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        if let Err(e) = handle_message.await {
            error!("Got error while handling message: {:#}", e);
        }
    }
}

#[derive(Debug)]
enum RouterRequest {
    Add(UnblockRequest),
    Remove(Vec<Ipv4Addr>),
}

#[derive(Debug)]
enum RouterResponse {
    Added(UnblockRequest),
    Removed(Vec<Ipv4Addr>),
}

async fn router_handler(
    router_client: RouterClient,
    mut requests_rx: UnboundedReceiver<RouterRequest>,
    responses_tx: UnboundedSender<RouterResponse>,
) {
    loop {
        let handle_message = async {
            match requests_rx.recv().await.expect("Senders dropped") {
                RouterRequest::Add(request) => {
                    router_client.add_routes(&request.ips).await?;
                    responses_tx
                        .send(RouterResponse::Added(request))
                        .expect("Receiver dropped")
                }
                RouterRequest::Remove(addrs) => {
                    router_client.remove_routes(&addrs).await?;
                    responses_tx
                        .send(RouterResponse::Removed(addrs))
                        .expect("Receiver dropped");
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        if let Err(e) = handle_message.await {
            error!("Got error while handling router request: {:#}", e);
        }
    }
}

fn merge_rxs(
    unblock_requests_rx: UnboundedReceiver<UnblockRequest>,
    blaklists_rx: UnboundedReceiver<HashSet<Ipv4Addr>>,
    router_responses_rx: UnboundedReceiver<RouterResponse>,
) -> impl Stream<Item = Message> + Unpin {
    unblock_requests_rx
        .map(Message::UnblockRequest)
        .merge(blaklists_rx.map(Message::Blacklist))
        .merge(router_responses_rx.map(Message::RouterResponse))
}
