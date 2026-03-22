use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    time::Duration,
};

use crate::routers::RouterClient;

use anyhow::Result;
use log::{error, info};
use tokio::{
    sync::{
        mpsc::UnboundedSender,
        mpsc::{unbounded_channel, UnboundedReceiver},
        oneshot,
    },
    time::Instant,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UnblockResponse {
    Unblocked(Vec<Ipv4Addr>),
    Skipped,
}

pub struct Unblocker {
    router_requests: UnboundedSender<AddRoutesRequest>,
}

impl Unblocker {
    pub fn new(router_client: impl RouterClient, route_ttl: Option<Duration>) -> Self {
        let (router_requests_tx, router_requests_rx) = unbounded_channel();
        let router_handler = router_requests_handler(router_client, route_ttl, router_requests_rx);
        tokio::spawn(router_handler);
        Self {
            router_requests: router_requests_tx,
        }
    }

    pub async fn unblock(
        &self,
        ips: impl IntoIterator<Item = Ipv4Addr>,
        comment: &str,
    ) -> Result<UnblockResponse> {
        let ips = ips.into_iter().collect::<HashSet<_>>();
        if ips.is_empty() {
            return Ok(UnblockResponse::Skipped);
        }
        let (response_tx, response_rx) = oneshot::channel();
        self.router_requests
            .send(AddRoutesRequest {
                ips,
                waiter: response_tx,
                comment: comment.to_owned(),
            })
            .expect("Receiver dropped");

        response_rx.await.expect("Should receive response")
    }
}

#[derive(Debug)]
struct AddRoutesRequest {
    ips: HashSet<Ipv4Addr>,
    waiter: oneshot::Sender<Result<UnblockResponse>>,
    comment: String,
}

async fn router_requests_handler(
    router_client: impl RouterClient,
    route_ttl: Option<Duration>,
    mut requests: UnboundedReceiver<AddRoutesRequest>,
) {
    let loaded = load_routed(&router_client).await;
    let now = Instant::now();
    let mut unblocked: HashMap<Ipv4Addr, Instant> =
        loaded.into_iter().map(|ip| (ip, now)).collect();

    while let Some(request) = requests.recv().await {
        let now = Instant::now();
        // Touch all requested IPs to refresh their TTL
        for &ip in &request.ips {
            if let Some(last_seen) = unblocked.get_mut(&ip) {
                *last_seen = now;
            }
        }
        let blocked = request
            .ips
            .iter()
            .filter(|ip| !unblocked.contains_key(ip))
            .copied()
            .collect::<Vec<_>>();
        if !blocked.is_empty() {
            let add_result = router_client.add_routes(&blocked, &request.comment).await;
            match add_result {
                Ok(_) => {
                    for &ip in &request.ips {
                        unblocked.insert(ip, now);
                    }
                    let _ = request.waiter.send(Ok(UnblockResponse::Unblocked(blocked)));
                }
                Err(err) => {
                    let _ = request.waiter.send(Err(err));
                }
            }
        } else {
            let _ = request.waiter.send(Ok(UnblockResponse::Skipped));
        }
        // Remove up to 5 expired routes on each request
        if let Some(ttl) = route_ttl {
            let expired: Vec<Ipv4Addr> = unblocked
                .iter()
                .filter(|(_, last_seen)| now.duration_since(**last_seen) > ttl)
                .map(|(ip, _)| *ip)
                .take(5)
                .collect();
            for ip in expired {
                match router_client.remove_route(ip).await {
                    Ok(_) => {
                        unblocked.remove(&ip);
                        info!("Removed expired route {}", ip);
                    }
                    Err(err) => {
                        error!("Error removing expired route {}: {:?}", ip, err);
                    }
                }
            }
        }
    }
}

async fn load_routed(router_client: &impl RouterClient) -> HashSet<Ipv4Addr> {
    use fure::backoff::fixed;
    use fure::policies::{backoff, cond};
    let policy = cond(backoff(fixed(Duration::from_secs(5))), |result| {
        if let Some(Err(err)) = result {
            error!(
                "Got error while receiving routed table from router: {:#}",
                err
            );
            true
        } else {
            false
        }
    });

    fure::retry(|| router_client.get_routed(), policy)
        .await
        .expect("Must be something")
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

        async fn add_routes(&self, _ips: &[Ipv4Addr], _comment: &str) -> Result<()> {
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

        async fn remove_route(&self, _ip: Ipv4Addr) -> Result<()> {
            self.remove_called.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn should_add_routes_when_ips_are_not_unblocked() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Unblocker::new(router_mock.clone(), Some(Duration::from_secs(1)));
        tokio::task::yield_now().await;

        let response = unblocker.unblock(vec![blacklisted_ip], "").await?;

        assert_eq!(response, UnblockResponse::Unblocked(vec![blacklisted_ip]));
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_routes_when_ips_are_unblocked() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Unblocker::new(router_mock.clone(), Some(Duration::from_secs(1)));
        tokio::task::yield_now().await;
        unblocker.unblock(vec![blacklisted_ip], "").await?;

        let response = unblocker.unblock(vec![blacklisted_ip], "").await?;

        assert_eq!(response, UnblockResponse::Skipped);
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn should_remove_expired_routes_on_next_request() -> Result<()> {
        let expired_ip: Ipv4Addr = "64.233.162.103".parse().unwrap();
        let new_ip: Ipv4Addr = "64.233.162.104".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Arc::new(Unblocker::new(
            router_mock.clone(),
            Some(Duration::from_millis(1)),
        ));
        tokio::task::yield_now().await;

        unblocker.unblock(vec![expired_ip], "").await?;
        sleep(Duration::from_millis(10)).await;
        // Next request triggers cleanup of expired routes
        unblocker.unblock(vec![new_ip], "").await?;

        assert!(router_mock.remove_called.load(Ordering::Relaxed));
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_same_router_in_parallel() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let unblocker = Arc::new(Unblocker::new(
            router_mock.clone(),
            Some(Duration::from_secs(1)),
        ));
        tokio::task::yield_now().await;
        let hunger = router_mock.hung_add_routes();

        let t1 = tokio::spawn({
            let unblocker = unblocker.clone();
            async move { unblocker.unblock(vec![blacklisted_ip], "").await.unwrap() }
        });
        tokio::task::yield_now().await;
        let t2 = tokio::spawn({
            let unblocker = unblocker.clone();
            async move { unblocker.unblock(vec![blacklisted_ip], "").await.unwrap() }
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
