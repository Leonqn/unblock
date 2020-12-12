use std::{
    collections::HashMap,
    collections::{hash_map::Entry, HashSet},
    net::Ipv4Addr,
};

use crate::routers::RouterClient;

use anyhow::{anyhow, Result};
use log::{error, info};
use tokio::{
    stream::{Stream, StreamExt},
    sync::{
        mpsc::unbounded_channel,
        mpsc::{UnboundedReceiver, UnboundedSender},
        oneshot,
    },
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UnblockResponse {
    Unblocked(Vec<Ipv4Addr>),
    Skipped,
}

pub struct Unblocker {
    unblocker_requests: UnboundedSender<UnblockerMessage>,
}

impl Unblocker {
    pub async fn new(
        blacklists: impl Stream<Item = HashSet<Ipv4Addr>> + Send + 'static,
        router_client: impl RouterClient + Send + Sync + 'static,
    ) -> Result<Self> {
        let unblocked = router_client.get_routed().await?;
        let (messages_tx, messages_rx) = unbounded_channel();
        let (router_requests_tx, router_requests_rx) = unbounded_channel();
        let blacklist_messages = blacklists.map(UnblockerMessage::Blacklist);
        let messages = Box::pin(blacklist_messages.merge(messages_rx));
        let router_handler = router_handler(router_client, router_requests_rx, messages_tx.clone());
        let unblocker = unblocker(messages, router_requests_tx, unblocked);
        tokio::spawn(async move {
            tokio::join!(router_handler, unblocker);
        });
        Ok(Self {
            unblocker_requests: messages_tx,
        })
    }

    pub async fn unblock(&self, ips: Vec<Ipv4Addr>) -> Result<UnblockResponse> {
        let (response_tx, response_rx) = oneshot::channel();
        self.unblocker_requests
            .send(UnblockerMessage::UnblockRequest(UnblockRequest {
                ips,
                response_waiter: response_tx,
            }))
            .expect("Receiver dropped");

        response_rx.await.expect("Should receive response")
    }
}

#[derive(Debug)]
struct UnblockRequest {
    ips: Vec<Ipv4Addr>,
    response_waiter: oneshot::Sender<Result<UnblockResponse>>,
}

#[derive(Debug)]
enum UnblockerMessage {
    UnblockRequest(UnblockRequest),
    Blacklist(HashSet<Ipv4Addr>),
    RouterResponse(RouterResponse),
}

async fn unblocker(
    mut messages: impl Stream<Item = UnblockerMessage> + Unpin,
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
        ) {
            error!("Got error while handling message: {:#}", e);
        }
    }
}

fn handle_message(
    message: UnblockerMessage,
    router_requests_tx: &UnboundedSender<RouterRequest>,
    unblocked: &mut HashSet<Ipv4Addr>,
    blacklist: &mut HashSet<Ipv4Addr>,
    waiting_responses: &mut HashMap<Vec<Ipv4Addr>, Vec<oneshot::Sender<Result<UnblockResponse>>>>,
) -> Result<()> {
    match message {
        UnblockerMessage::UnblockRequest(request) => {
            let blocked = request
                .ips
                .into_iter()
                .filter(|ip| blacklist.contains(ip) && !unblocked.contains(ip))
                .collect::<Vec<_>>();
            if !blocked.is_empty() {
                match waiting_responses.entry(blocked) {
                    Entry::Occupied(mut waiters) => waiters.get_mut().push(request.response_waiter),
                    Entry::Vacant(v) => {
                        router_requests_tx
                            .send(RouterRequest::Add(v.key().clone()))
                            .expect("Receiver dropped");
                        v.insert(vec![request.response_waiter]);
                    }
                }
            } else {
                let _ = request.response_waiter.send(Ok(UnblockResponse::Skipped));
            }
        }
        UnblockerMessage::Blacklist(new_blacklist) => {
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

        UnblockerMessage::RouterResponse(RouterResponse::AddResult { ips, add_result }) => {
            if add_result.is_ok() {
                unblocked.extend(ips.iter().copied());
            }
            for waiter in waiting_responses.remove(&ips).into_iter().flatten() {
                match &add_result {
                    Ok(_) => {
                        let _ = waiter.send(Ok(UnblockResponse::Unblocked(ips.clone())));
                    }
                    Err(err) => {
                        let _ = waiter.send(Err(anyhow!("{:#}", err)));
                    }
                }
            }
        }
        UnblockerMessage::RouterResponse(RouterResponse::Removed(ips)) => {
            for ip in ips {
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
    AddResult {
        ips: Vec<Ipv4Addr>,
        add_result: Result<()>,
    },
    Removed(Vec<Ipv4Addr>),
}

async fn router_handler(
    router_client: impl RouterClient,
    mut requests: UnboundedReceiver<RouterRequest>,
    responses: UnboundedSender<UnblockerMessage>,
) {
    loop {
        let msg = requests.recv().await.expect("Senders dropped");
        let handle_message = async {
            match msg {
                RouterRequest::Add(ips) => {
                    let add_result = router_client.add_routes(&ips).await;
                    responses
                        .send(UnblockerMessage::RouterResponse(
                            RouterResponse::AddResult { ips, add_result },
                        ))
                        .expect("Receiver dropped");
                }
                RouterRequest::Remove(ips) => {
                    router_client.remove_routes(&ips).await?;
                    responses
                        .send(UnblockerMessage::RouterResponse(RouterResponse::Removed(
                            ips,
                        )))
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

#[cfg(test)]
mod tests {
    use crate::routers::RouterClient;

    use super::{UnblockResponse, Unblocker};
    use anyhow::Result;
    use async_trait::async_trait;
    use futures_util::{
        future::{BoxFuture, Shared},
        FutureExt,
    };
    use pretty_assertions::assert_eq;
    use std::{
        collections::HashSet,
        net::Ipv4Addr,
        sync::atomic::AtomicUsize,
        sync::Arc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        },
    };
    use tokio::sync::{mpsc::unbounded_channel, oneshot};

    #[derive(Clone)]
    struct RouterMock {
        add_calls: Arc<AtomicUsize>,
        get_caled: Arc<AtomicBool>,
        remove_called: Arc<AtomicBool>,
        add_hung: Arc<Mutex<Option<Shared<BoxFuture<'static, ()>>>>>,
    }

    impl RouterMock {
        fn new() -> Self {
            Self {
                add_calls: Arc::new(AtomicUsize::new(0)),
                get_caled: Arc::new(AtomicBool::new(false)),
                remove_called: Arc::new(AtomicBool::new(false)),
                add_hung: Arc::new(Mutex::new(None)),
            }
        }

        fn hung_add_routes(&self) -> oneshot::Sender<()> {
            let (tx, rx) = oneshot::channel();
            self.add_hung.lock().unwrap().replace(
                async move {
                    rx.await.unwrap();
                }
                .boxed()
                .shared(),
            );
            tx
        }
    }

    #[async_trait]
    impl RouterClient for RouterMock {
        async fn get_routed(&self) -> Result<HashSet<Ipv4Addr>> {
            self.get_caled.store(true, Ordering::Relaxed);
            Ok(HashSet::new())
        }

        async fn add_routes(&self, _ips: &[Ipv4Addr]) -> Result<()> {
            self.add_calls.fetch_add(1, Ordering::Relaxed);
            let hung = {
                let guard = self.add_hung.lock().unwrap();
                guard.as_ref().cloned()
            };
            if let Some(hung) = hung {
                hung.await
            }
            Ok(())
        }

        async fn remove_routes(&self, _ips: &[Ipv4Addr]) -> Result<()> {
            self.remove_called.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn should_add_routes_when_ips_are_blocked() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Unblocker::new(
            tokio::stream::once(vec![blacklisted_ip].into_iter().collect()),
            router_mock.clone(),
        )
        .await?;

        let response = unblocker.unblock(vec![blacklisted_ip]).await?;

        assert_eq!(response, UnblockResponse::Unblocked(vec![blacklisted_ip]));
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_routes_when_ips_are_unblocked() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Unblocker::new(
            tokio::stream::once(vec![blacklisted_ip].into_iter().collect()),
            router_mock.clone(),
        )
        .await?;
        unblocker.unblock(vec![blacklisted_ip]).await?;

        let response = unblocker.unblock(vec![blacklisted_ip]).await?;

        assert_eq!(response, UnblockResponse::Skipped);
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_routes_when_ips_not_in_blacklist() -> Result<()> {
        let blacklisted_ip = "65.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Unblocker::new(
            tokio::stream::once(vec![blacklisted_ip].into_iter().collect()),
            router_mock.clone(),
        )
        .await?;

        let response = unblocker
            .unblock(vec!["127.0.0.1".parse().unwrap()])
            .await?;

        assert_eq!(response, UnblockResponse::Skipped);
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_same_router_in_parallel() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Arc::new(
            Unblocker::new(
                tokio::stream::once(vec![blacklisted_ip].into_iter().collect()),
                router_mock.clone(),
            )
            .await?,
        );
        let hunger = router_mock.hung_add_routes();

        let t1 = tokio::spawn({
            let unblocker = unblocker.clone();
            async move { unblocker.unblock(vec![blacklisted_ip]).await.unwrap() }
        });
        tokio::task::yield_now().await;
        let t2 = tokio::spawn({
            let unblocker = unblocker.clone();
            async move { unblocker.unblock(vec![blacklisted_ip]).await.unwrap() }
        });
        tokio::task::yield_now().await;
        hunger.send(()).unwrap();
        let (t1, t2) = tokio::try_join!(t1, t2)?;

        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        assert_eq!(t1, UnblockResponse::Unblocked(vec![blacklisted_ip]));
        assert_eq!(t2, UnblockResponse::Unblocked(vec![blacklisted_ip]));

        Ok(())
    }

    #[tokio::test]
    async fn should_remove_routes_when_new_blacklist_does_not_contain_previously_unblocked(
    ) -> Result<()> {
        let (blacklists_tx, blacklists_rx) = unbounded_channel();
        let blacklisted_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        blacklists_tx
            .send({
                let mut h = HashSet::new();
                h.insert(blacklisted_ip);
                h
            })
            .unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Unblocker::new(blacklists_rx, router_mock.clone()).await?;
        unblocker.unblock(vec![blacklisted_ip]).await?;

        blacklists_tx.send(HashSet::new()).unwrap();
        tokio::task::yield_now().await;

        assert!(router_mock.remove_called.load(Ordering::Relaxed),);
        Ok(())
    }

    #[tokio::test]
    async fn should_not_remove_routes_when_new_blacklist_contains_all_previous_ips() -> Result<()> {
        let (blacklists_tx, blacklists_rx) = unbounded_channel();
        let blacklisted_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let blacklist = {
            let mut h = HashSet::new();
            h.insert(blacklisted_ip);
            h
        };
        blacklists_tx.send(blacklist.clone()).unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Unblocker::new(blacklists_rx, router_mock.clone()).await?;
        unblocker.unblock(vec![blacklisted_ip]).await?;

        blacklists_tx.send(blacklist).unwrap();
        tokio::task::yield_now().await;

        assert!(!router_mock.remove_called.load(Ordering::Relaxed),);
        Ok(())
    }
}
