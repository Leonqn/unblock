use std::{
    collections::HashMap,
    collections::{hash_map::Entry, HashSet},
    future::Future,
    net::Ipv4Addr,
};

use anyhow::Result;
use log::{error, info};
use tokio::{
    stream::{Stream, StreamExt},
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

use crate::router_client::RouterClient;

#[derive(Debug, Eq, PartialEq)]
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
    let mut waiters = HashMap::new();
    loop {
        let message = messages.next().await.expect("Senders dropped");
        if let Err(e) = handle_message(
            message,
            &router_requests_tx,
            &mut unblocked,
            &mut blacklist,
            &mut waiters,
        )
        .await
        {
            error!("Got error while handling message: {:#}", e);
        }
    }
}

async fn handle_message(
    message: Message,
    router_requests_tx: &UnboundedSender<RouterRequest>,
    unblocked: &mut HashSet<Ipv4Addr>,
    blacklist: &mut HashSet<Ipv4Addr>,
    waiters: &mut HashMap<Vec<Ipv4Addr>, Vec<tokio::sync::oneshot::Sender<UnblockResponse>>>,
) -> Result<()> {
    match message {
        Message::UnblockRequest(request) => {
            let blocked = request
                .ips
                .iter()
                .filter(|ip| blacklist.contains(*ip) && !unblocked.contains(&ip))
                .copied()
                .collect::<Vec<_>>();
            if !blocked.is_empty() {
                match waiters.entry(blocked.clone()) {
                    Entry::Occupied(mut waiters) => waiters.get_mut().push(request.reply),
                    Entry::Vacant(v) => {
                        v.insert(vec![request.reply]);
                        router_requests_tx
                            .send(RouterRequest::Add(blocked))
                            .expect("Receiver dropped");
                    }
                }
            } else {
                let _ = request.reply.send(UnblockResponse::Skipped);
            }
        }
        Message::Blacklist(new_blacklist) => {
            info!("Received blacklist with {} items", new_blacklist.len());
            *blacklist = new_blacklist;
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

        Message::RouterResponse(RouterResponse::Added(addrs)) => {
            unblocked.extend(addrs.iter().copied());
            for waiter in waiters.remove(&addrs).into_iter().flatten() {
                let _ = waiter.send(UnblockResponse::Unblocked(addrs.clone()));
            }
        }

        Message::RouterResponse(RouterResponse::AddError(addrs)) => {
            waiters.remove(&addrs);
        }
        Message::RouterResponse(RouterResponse::Removed(addrs)) => {
            for ip in addrs {
                unblocked.remove(&ip);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum RouterRequest {
    Add(Vec<Ipv4Addr>),
    Remove(Vec<Ipv4Addr>),
}

#[derive(Debug)]
enum RouterResponse {
    Added(Vec<Ipv4Addr>),
    Removed(Vec<Ipv4Addr>),
    AddError(Vec<Ipv4Addr>),
}

async fn router_handler(
    router_client: RouterClient,
    mut requests_rx: UnboundedReceiver<RouterRequest>,
    responses_tx: UnboundedSender<RouterResponse>,
) {
    loop {
        let msg = requests_rx.recv().await.expect("Senders dropped");
        let handle_message = async {
            match msg {
                RouterRequest::Add(addrs) => {
                    if let Err(err) = router_client.add_routes(&addrs).await {
                        responses_tx
                            .send(RouterResponse::AddError(addrs))
                            .expect("Receiver dropped");
                        return Err(err);
                    } else {
                        responses_tx
                            .send(RouterResponse::Added(addrs))
                            .expect("Receiver dropped");
                    }
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

#[cfg(test)]
mod tests {
    use super::{
        handle_message, Message, RouterRequest, RouterResponse, UnblockRequest, UnblockResponse,
    };
    use anyhow::Result;
    use pretty_assertions::assert_eq;
    use std::collections::{HashMap, HashSet};
    use tokio::sync::{
        mpsc::unbounded_channel,
        oneshot::{self, error::TryRecvError},
    };

    #[tokio::test]
    async fn should_send_add_routes_when_ips_are_blocked() -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let ip = "127.0.0.1".parse().unwrap();
        let (reply, _) = oneshot::channel();
        let mut blacklist = [ip].iter().copied().collect();
        let message = Message::UnblockRequest(UnblockRequest {
            ips: vec![ip],
            reply,
        });

        handle_message(
            message,
            &router_tx,
            &mut HashSet::new(),
            &mut blacklist,
            &mut HashMap::new(),
        )
        .await?;

        assert_eq!(router_rx.try_recv().unwrap(), RouterRequest::Add(vec![ip]));
        Ok(())
    }

    #[tokio::test]
    async fn should_not_send_add_routes_when_ips_are_unblocked() -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let ip = "127.0.0.1".parse().unwrap();
        let (reply, _) = oneshot::channel();
        let mut blacklist = [ip].iter().copied().collect();
        let mut unblocked = [ip].iter().copied().collect();
        let message = Message::UnblockRequest(UnblockRequest {
            ips: vec![ip],
            reply,
        });

        handle_message(
            message,
            &router_tx,
            &mut unblocked,
            &mut blacklist,
            &mut HashMap::new(),
        )
        .await?;

        assert!(router_rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn should_not_send_add_routes_when_ips_arent_in_blacklist() -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let ip = "127.0.0.1".parse().unwrap();
        let (reply, _) = oneshot::channel();
        let message = Message::UnblockRequest(UnblockRequest {
            ips: vec![ip],
            reply,
        });

        handle_message(
            message,
            &router_tx,
            &mut HashSet::new(),
            &mut HashSet::new(),
            &mut HashMap::new(),
        )
        .await?;

        assert!(router_rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn should_not_send_add_routes_when_there_is_pending_request() -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let ip = "127.0.0.1".parse().unwrap();
        let (reply, _) = oneshot::channel();
        let mut blacklist = [ip].iter().copied().collect();
        let mut pending_requests = HashMap::new();
        pending_requests.insert(vec![ip], vec![oneshot::channel().0]);
        let message = Message::UnblockRequest(UnblockRequest {
            ips: vec![ip],
            reply,
        });

        handle_message(
            message,
            &router_tx,
            &mut HashSet::new(),
            &mut blacklist,
            &mut pending_requests,
        )
        .await?;

        assert!(router_rx.try_recv().is_err());
        assert_eq!(pending_requests[[ip].as_ref()].len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn should_send_remove_routes_when_new_blacklist_does_not_contains_previously_unblocked(
    ) -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let ip = "127.0.0.1".parse().unwrap();
        let mut blacklist = [ip].iter().copied().collect();
        let mut unblocked = [ip].iter().copied().collect();
        let message =
            Message::Blacklist(["192.168.1.1".parse().unwrap()].iter().copied().collect());

        handle_message(
            message,
            &router_tx,
            &mut unblocked,
            &mut blacklist,
            &mut HashMap::new(),
        )
        .await?;

        assert_eq!(
            router_rx.try_recv().unwrap(),
            RouterRequest::Remove(vec![ip])
        );
        Ok(())
    }

    #[tokio::test]
    async fn should_not_send_remove_routes_when_new_blacklist_contains_all_previous_ips(
    ) -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let ip = "127.0.0.1".parse().unwrap();
        let mut blacklist: HashSet<_> = [ip].iter().copied().collect();
        let mut unblocked = [ip].iter().copied().collect();
        let message = Message::Blacklist(blacklist.clone());

        handle_message(
            message,
            &router_tx,
            &mut unblocked,
            &mut blacklist,
            &mut HashMap::new(),
        )
        .await?;

        assert!(router_rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn should_update_unblocked_and_notify_waiters_when_routes_added() -> Result<()> {
        let (router_tx, _) = unbounded_channel();
        let ip = "127.0.0.1".parse().unwrap();
        let (reply1, mut reply1_rx) = oneshot::channel();
        let (reply2, mut reply2_rx) = oneshot::channel();
        let mut blacklist = [ip].iter().copied().collect();
        let mut pending_requests = HashMap::new();
        let mut unblocked = HashSet::new();
        pending_requests.insert(vec![ip], vec![reply1, reply2]);
        let message = Message::RouterResponse(RouterResponse::Added(vec![ip]));

        handle_message(
            message,
            &router_tx,
            &mut unblocked,
            &mut blacklist,
            &mut pending_requests,
        )
        .await?;

        assert_eq!(
            reply1_rx.try_recv().unwrap(),
            UnblockResponse::Unblocked(vec![ip])
        );
        assert_eq!(
            reply2_rx.try_recv().unwrap(),
            UnblockResponse::Unblocked(vec![ip])
        );
        assert!(unblocked.contains(&ip));
        Ok(())
    }

    #[tokio::test]
    async fn should_update_blacklist_when_routes_removed() -> Result<()> {
        let (router_tx, _) = unbounded_channel();
        let ip = "127.0.0.1".parse().unwrap();
        let mut blacklist = [ip].iter().copied().collect();
        let mut pending_requests = HashMap::new();
        let mut unblocked = [ip].iter().copied().collect();
        let message = Message::RouterResponse(RouterResponse::Removed(vec![ip]));

        handle_message(
            message,
            &router_tx,
            &mut unblocked,
            &mut blacklist,
            &mut pending_requests,
        )
        .await?;

        assert!(!unblocked.contains(&ip));
        Ok(())
    }

    #[tokio::test]
    async fn should_drop_waiters_when_routes_add_failed() -> Result<()> {
        let (router_tx, _) = unbounded_channel();
        let ip = "127.0.0.1".parse().unwrap();
        let (reply1, mut reply1_rx) = oneshot::channel();
        let (reply2, mut reply2_rx) = oneshot::channel();
        let mut blacklist = [ip].iter().copied().collect();
        let mut pending_requests = HashMap::new();
        let mut unblocked = HashSet::new();
        pending_requests.insert(vec![ip], vec![reply1, reply2]);
        let message = Message::RouterResponse(RouterResponse::AddError(vec![ip]));

        handle_message(
            message,
            &router_tx,
            &mut unblocked,
            &mut blacklist,
            &mut pending_requests,
        )
        .await?;

        assert_eq!(reply1_rx.try_recv(), Err(TryRecvError::Closed));
        assert_eq!(reply2_rx.try_recv(), Err(TryRecvError::Closed));
        assert!(!unblocked.contains(&ip));
        Ok(())
    }
}
