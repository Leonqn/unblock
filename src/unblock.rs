use std::{collections::HashSet, net::Ipv4Addr, time::Duration};

use crate::{last_item::LastItem, routers::RouterClient};

use anyhow::Result;
use log::error;
use tokio::{
    sync::{
        mpsc::UnboundedSender,
        mpsc::{unbounded_channel, UnboundedReceiver},
        oneshot,
    },
    time::{interval_at, Instant},
};
use tokio_stream::Stream;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UnblockResponse {
    Unblocked(Vec<Ipv4Addr>),
    Skipped,
}

pub struct Unblocker {
    blacklist: LastItem<HashSet<Ipv4Addr>>,
    router_requests: UnboundedSender<AddRoutesRequest>,
}

impl Unblocker {
    pub fn new(
        blacklist: impl Stream<Item = HashSet<Ipv4Addr>> + Send + 'static,
        router_client: impl RouterClient,
        clear_interval: Duration,
    ) -> Self {
        let (router_requests_tx, router_requests_rx) = unbounded_channel();
        let router_handler =
            router_requests_handler_handler(router_client, clear_interval, router_requests_rx);
        let blacklist = LastItem::new(blacklist);

        tokio::spawn(router_handler);
        Self {
            router_requests: router_requests_tx,
            blacklist,
        }
    }

    pub async fn unblock(&self, ips: &[Ipv4Addr]) -> Result<UnblockResponse> {
        let blacklisted = self.blacklist.item().map_or_else(Vec::new, |blacklist| {
            ips.iter()
                .filter(|ip| blacklist.contains(ip))
                .copied()
                .collect::<Vec<_>>()
        });
        if !blacklisted.is_empty() {
            let (response_tx, response_rx) = oneshot::channel();
            self.router_requests
                .send(AddRoutesRequest {
                    ips: blacklisted,
                    waiter: response_tx,
                })
                .expect("Receiver dropped");

            response_rx.await.expect("Should receive response")
        } else {
            Ok(UnblockResponse::Skipped)
        }
    }
}

#[derive(Debug)]
struct AddRoutesRequest {
    ips: Vec<Ipv4Addr>,
    waiter: oneshot::Sender<Result<UnblockResponse>>,
}

async fn router_requests_handler_handler(
    router_client: impl RouterClient,
    clear_interval: Duration,
    mut requests: UnboundedReceiver<AddRoutesRequest>,
) {
    let mut unblocked = load_routed(&router_client).await;
    let mut clear_tick = interval_at(Instant::now() + clear_interval, clear_interval);
    loop {
        tokio::select! {
            Some(request) = requests.recv() => {
                let blocked = request
                    .ips
                    .iter()
                    .filter(|ip| !unblocked.contains(ip))
                    .collect::<Vec<_>>();
                if !blocked.is_empty() {
                    let add_result = router_client.add_routes(&request.ips).await;
                    match add_result {
                        Ok(_) => {
                            unblocked.extend(request.ips.iter().copied());
                            let _ = request
                                .waiter
                                .send(Ok(UnblockResponse::Unblocked(request.ips)));
                        }
                        Err(err) => {
                            let _ = request.waiter.send(Err(err));
                        }
                    }
                } else {
                    let _ = request.waiter.send(Ok(UnblockResponse::Skipped));
                }
            }
            _ = clear_tick.tick() => {
                if !unblocked.is_empty() {
                    let to_clear = unblocked.iter().copied().collect::<Vec<_>>();
                    if let Err(err) = router_client.remove_routes(&to_clear).await {
                        error!("Error occured while clearing routes: {:#}", err);
                    }
                    unblocked.clear();
                }
            }
        }
    }
}

async fn load_routed(router_client: &impl RouterClient) -> HashSet<Ipv4Addr> {
    loop {
        match router_client.get_routed().await {
            Ok(unblocked) => break unblocked,
            Err(err) => {
                error!(
                    "Got error while receiving routed table from router: {:#}",
                    err
                );
            }
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
        time::Duration,
    };
    use tokio::{sync::oneshot, time::sleep};

    #[derive(Clone)]
    struct RouterMock {
        add_calls: Arc<AtomicUsize>,
        get_called: Arc<AtomicBool>,
        remove_called: Arc<AtomicBool>,
        add_hung: Arc<Mutex<Option<Shared<BoxFuture<'static, ()>>>>>,
    }

    impl RouterMock {
        fn new() -> Self {
            Self {
                add_calls: Arc::new(AtomicUsize::new(0)),
                get_called: Arc::new(AtomicBool::new(false)),
                add_hung: Arc::new(Mutex::new(None)),
                remove_called: Arc::new(AtomicBool::new(false)),
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
            self.get_called.store(true, Ordering::Relaxed);
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
            tokio_stream::once(vec![blacklisted_ip].into_iter().collect()),
            router_mock.clone(),
            Duration::from_secs(1),
        );
        tokio::task::yield_now().await;

        let response = unblocker.unblock(&vec![blacklisted_ip]).await?;

        assert_eq!(response, UnblockResponse::Unblocked(vec![blacklisted_ip]));
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_routes_when_ips_are_unblocked() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Unblocker::new(
            tokio_stream::once(vec![blacklisted_ip].into_iter().collect()),
            router_mock.clone(),
            Duration::from_secs(1),
        );
        tokio::task::yield_now().await;
        unblocker.unblock(&vec![blacklisted_ip]).await?;

        let response = unblocker.unblock(&vec![blacklisted_ip]).await?;

        assert_eq!(response, UnblockResponse::Skipped);
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_routes_when_ips_not_in_blacklist() -> Result<()> {
        let blacklisted_ip = "65.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Unblocker::new(
            tokio_stream::once(vec![blacklisted_ip].into_iter().collect()),
            router_mock.clone(),
            Duration::from_secs(1),
        );
        tokio::task::yield_now().await;

        let response = unblocker
            .unblock(&vec!["127.0.0.1".parse().unwrap()])
            .await?;

        assert_eq!(response, UnblockResponse::Skipped);
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[tokio::test]
    async fn should_remove_routes_after_specified_duration() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Arc::new(Unblocker::new(
            tokio_stream::once(vec![blacklisted_ip].into_iter().collect()),
            router_mock.clone(),
            Duration::from_millis(1),
        ));
        tokio::task::yield_now().await;

        unblocker.unblock(&vec![blacklisted_ip]).await?;
        sleep(Duration::from_millis(10)).await;

        assert!(router_mock.remove_called.load(Ordering::Relaxed));
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_same_router_in_parallel() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Arc::new(Unblocker::new(
            tokio_stream::once(vec![blacklisted_ip].into_iter().collect()),
            router_mock.clone(),
            Duration::from_secs(1),
        ));
        tokio::task::yield_now().await;
        let hunger = router_mock.hung_add_routes();

        let t1 = tokio::spawn({
            let unblocker = unblocker.clone();
            async move { unblocker.unblock(&vec![blacklisted_ip]).await.unwrap() }
        });
        tokio::task::yield_now().await;
        let t2 = tokio::spawn({
            let unblocker = unblocker.clone();
            async move { unblocker.unblock(&vec![blacklisted_ip]).await.unwrap() }
        });
        tokio::task::yield_now().await;
        hunger.send(()).unwrap();
        let (t1, t2) = tokio::try_join!(t1, t2)?;

        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        assert_eq!(t1, UnblockResponse::Unblocked(vec![blacklisted_ip]));
        assert_eq!(t2, UnblockResponse::Skipped);

        Ok(())
    }
}
