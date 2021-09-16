use std::time::Duration;

use super::DnsClient;
use crate::dns::message::{Query, Response};
use anyhow::Result;
use async_trait::async_trait;
use futures_util::{future::select_all, Future, FutureExt};
use tokio::time::sleep;

pub struct RetryClient<C> {
    client: C,
    attempts_count: usize,
    next_attempt_delay: Duration,
}

impl<C> RetryClient<C> {
    pub fn new(client: C, attempts_count: usize, next_attempt_delay: Duration) -> Self {
        Self {
            client,
            attempts_count,
            next_attempt_delay,
        }
    }
}

#[async_trait]
impl<C: DnsClient> DnsClient for RetryClient<C> {
    async fn send(&self, query: Query) -> Result<Response> {
        retry(
            || self.client.send(query.clone()),
            self.attempts_count,
            self.next_attempt_delay,
        )
        .await
    }
}

async fn retry<F, T, E>(
    create_f: impl Fn() -> F + Send + Sync,
    mut attempts: usize,
    next_attempt_delay: Duration,
) -> std::result::Result<T, E>
where
    F: Future<Output = std::result::Result<T, E>> + Send,
{
    let send_req = || async { Some(create_f().await) }.boxed();
    let timeout = || {
        async {
            sleep(next_attempt_delay).await;
            None
        }
        .boxed()
    };

    let mut query_futures = vec![send_req(), timeout()];
    let mut last_error = None;
    let mut timeout_removed = false;
    loop {
        attempts -= 1;
        match select_all(query_futures).await {
            (Some(Ok(result)), _, _) => return Ok(result),
            (Some(Err(err)), _, rest) => {
                query_futures = rest;
                if attempts > 0 {
                    last_error = Some(err);
                    query_futures.push(send_req());
                } else if query_futures.is_empty() || (!timeout_removed && query_futures.len() == 1)
                {
                    return Err(err);
                }
            }
            (None, _, rest) => {
                query_futures = rest;
                if attempts > 0 {
                    query_futures.push(send_req());
                    query_futures.push(timeout());
                } else {
                    timeout_removed = true;
                    if query_futures.is_empty() {
                        return Err(last_error.expect("Last error must be set at least once"));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::time::sleep;

    use crate::dns::client::retry::retry;

    #[tokio::test]
    async fn should_retry_when_failed() {
        let call_count = Arc::new(Mutex::new(0));
        let create_fut = || {
            let call_count = call_count.clone();
            async move {
                let mut mutex_guard = call_count.lock().unwrap();
                *mutex_guard += 1;
                if *mutex_guard == 1 {
                    Err(())
                } else {
                    Ok(())
                }
            }
        };

        let result = retry(create_fut, 2, Duration::from_secs(10000)).await;

        let guard = call_count.lock().unwrap();
        assert_eq!(*guard, 2);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn should_return_second_error_when_all_failed() {
        let call_count = Arc::new(Mutex::new(0));
        let create_fut = || {
            let call_count = call_count.clone();
            async move {
                let mut mutex_guard = call_count.lock().unwrap();
                *mutex_guard += 1;
                if *mutex_guard == 1 {
                    Err::<(), _>(*mutex_guard)
                } else {
                    Err(*mutex_guard)
                }
            }
        };

        let result = retry(create_fut, 2, Duration::from_secs(10000)).await;

        let guard = call_count.lock().unwrap();
        assert_eq!(*guard, 2);
        assert_eq!(result, Err(2));
    }

    #[tokio::test]
    async fn should_retry_after_delay() {
        let call_count = Arc::new(Mutex::new(0));
        let create_fut = || {
            let call_count = call_count.clone();
            async move {
                let call_count = {
                    let mut mutex_guard = call_count.lock().unwrap();
                    *mutex_guard += 1;
                    *mutex_guard
                };
                if call_count == 1 {
                    sleep(Duration::from_secs(10000000)).await;
                    Ok::<_, ()>(())
                } else {
                    Ok(())
                }
            }
        };

        let result = retry(create_fut, 2, Duration::from_millis(1)).await;

        let guard = call_count.lock().unwrap();
        assert_eq!(*guard, 2);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn should_not_retry_when_ok() {
        let call_count = Arc::new(Mutex::new(0));
        let create_fut = || {
            let call_count = call_count.clone();
            async move {
                let call_count = {
                    let mut mutex_guard = call_count.lock().unwrap();
                    *mutex_guard += 1;
                    *mutex_guard
                };
                if call_count == 1 {
                    Ok::<_, ()>(())
                } else {
                    Ok(())
                }
            }
        };

        let result = retry(create_fut, 2, Duration::from_millis(1)).await;

        let guard = call_count.lock().unwrap();
        assert_eq!(*guard, 1);
        assert!(result.is_ok());
    }
}
