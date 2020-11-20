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

#[derive(Debug)]
pub struct UnblockRequest {
    pub ips: Vec<Ipv4Addr>,
    pub response_waiter: oneshot::Sender<Result<UnblockResponse>>,
}

pub struct Unblocker {
    unblocker_requests: UnboundedSender<UnblockerMessage>,
}

impl Unblocker {
    pub async fn new(
        blacklists: impl Stream<Item = HashSet<Ipv4Addr>> + Send + 'static,
        router_client: RouterClient,
    ) -> Result<Self> {
        let unblocked = router_client.get_routed().await?;
        let (messages_tx, messages_rx) = unbounded_channel();
        let (router_requests_tx, router_requests_rx) = unbounded_channel();
        let blacklist_messages = blacklists.map(UnblockerMessage::Blacklist);
        let messages = Box::pin(messages_rx.merge(blacklist_messages));
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
    router_client: RouterClient,
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

// #[cfg(test)]
// mod tests {
//     use super::{
//         handle_message, UnblockerMessage, RouterRequest, RouterResponse, UnblockRequest, UnblockResponse,
//     };
//     use anyhow::Result;
//     use pretty_assertions::assert_eq;
//     use std::collections::{HashMap, HashSet};
//     use tokio::sync::mpsc::unbounded_channel;

//     static DNS_RESPONSE: &[u8] = include_bytes!("../test/dns_packets/a_www.google.com.bin");

//     #[test]
//     fn should_send_add_routes_when_ips_are_blocked() -> Result<()> {
//         let (router_tx, mut router_rx) = unbounded_channel();
//         let (responses, _req) = unbounded_channel();
//         let blacklisted_ip = "64.233.162.103".parse().unwrap();
//         let mut blacklist = [blacklisted_ip].iter().copied().collect();
//         let message = UnblockerMessage::UnblockRequest(UnblockRequest {
//             dns_response: Vec::from(DNS_RESPONSE),
//             sender: "127.0.0.1:1234".parse().unwrap(),
//         });

//         handle_message(
//             message,
//             &router_tx,
//             &responses,
//             &mut HashSet::new(),
//             &mut blacklist,
//             &mut HashMap::new(),
//         )?;

//         assert_eq!(
//             router_rx.try_recv().unwrap(),
//             RouterRequest::Add(vec![blacklisted_ip])
//         );
//         Ok(())
//     }

//     #[test]
//     fn should_not_send_add_routes_when_ips_are_unblocked() -> Result<()> {
//         let (router_tx, mut router_rx) = unbounded_channel();
//         let (responses, _req) = unbounded_channel();
//         let blacklisted_ip = "64.233.162.103".parse().unwrap();
//         let mut blacklist = [blacklisted_ip].iter().copied().collect();
//         let mut unblocked = [blacklisted_ip].iter().copied().collect();
//         let message = UnblockerMessage::UnblockRequest(UnblockRequest {
//             dns_response: Vec::from(DNS_RESPONSE),
//             sender: "127.0.0.1:1234".parse().unwrap(),
//         });

//         handle_message(
//             message,
//             &router_tx,
//             &responses,
//             &mut unblocked,
//             &mut blacklist,
//             &mut HashMap::new(),
//         )?;

//         assert!(router_rx.try_recv().is_err());
//         Ok(())
//     }

//     #[test]
//     fn should_not_send_add_routes_when_ips_arent_in_blacklist() -> Result<()> {
//         let (router_tx, mut router_rx) = unbounded_channel();
//         let (responses, _req) = unbounded_channel();
//         let blacklisted_ip = "65.233.162.103".parse().unwrap();
//         let mut blacklist = [blacklisted_ip].iter().copied().collect();
//         let message = UnblockerMessage::UnblockRequest(UnblockRequest {
//             dns_response: Vec::from(DNS_RESPONSE),
//             sender: "127.0.0.1:1234".parse().unwrap(),
//         });

//         handle_message(
//             message,
//             &router_tx,
//             &responses,
//             &mut HashSet::new(),
//             &mut blacklist,
//             &mut HashMap::new(),
//         )?;

//         assert!(router_rx.try_recv().is_err());
//         Ok(())
//     }

//     #[test]
//     fn should_not_send_add_routes_and_insert_waiter_when_there_is_pending_request() -> Result<()> {
//         let (router_tx, mut router_rx) = unbounded_channel();
//         let (responses, _req) = unbounded_channel();
//         let mut pending_requests = HashMap::new();
//         let blacklisted_ip = "64.233.162.103".parse().unwrap();
//         let mut blacklist = [blacklisted_ip].iter().copied().collect();
//         let request = UnblockRequest {
//             dns_response: Vec::from(DNS_RESPONSE),
//             sender: "127.0.0.1:1234".parse().unwrap(),
//         };
//         let message = UnblockerMessage::UnblockRequest(request.clone());
//         pending_requests.insert(vec![blacklisted_ip], vec![request]);

//         handle_message(
//             message,
//             &router_tx,
//             &responses,
//             &mut HashSet::new(),
//             &mut blacklist,
//             &mut pending_requests,
//         )?;

//         assert!(router_rx.try_recv().is_err());
//         assert_eq!(pending_requests[[blacklisted_ip].as_ref()].len(), 2);
//         Ok(())
//     }

//     #[test]
//     fn should_send_remove_routes_when_new_blacklist_does_not_contains_previously_unblocked(
//     ) -> Result<()> {
//         let (router_tx, mut router_rx) = unbounded_channel();
//         let (responses, _req) = unbounded_channel();
//         let blacklisted_ip = "127.0.0.1".parse().unwrap();
//         let mut blacklist = [blacklisted_ip].iter().copied().collect();
//         let mut unblocked = [blacklisted_ip].iter().copied().collect();
//         let message =
//             UnblockerMessage::Blacklist(["192.168.1.1".parse().unwrap()].iter().copied().collect());

//         handle_message(
//             message,
//             &router_tx,
//             &responses,
//             &mut unblocked,
//             &mut blacklist,
//             &mut HashMap::new(),
//         )?;

//         assert_eq!(
//             router_rx.try_recv().unwrap(),
//             RouterRequest::Remove(vec![blacklisted_ip])
//         );
//         Ok(())
//     }

//     #[test]
//     fn should_not_send_remove_routes_when_new_blacklist_contains_all_previous_ips() -> Result<()> {
//         let (router_tx, mut router_rx) = unbounded_channel();
//         let (responses, _req) = unbounded_channel();
//         let blacklisted_ip = "64.233.162.103".parse().unwrap();
//         let mut blacklist: HashSet<_> = [blacklisted_ip].iter().copied().collect();
//         let mut unblocked = [blacklisted_ip].iter().copied().collect();
//         let message = UnblockerMessage::Blacklist(blacklist.clone());

//         handle_message(
//             message,
//             &router_tx,
//             &responses,
//             &mut unblocked,
//             &mut blacklist,
//             &mut HashMap::new(),
//         )?;

//         assert!(router_rx.try_recv().is_err());
//         Ok(())
//     }

//     #[test]
//     fn should_update_unblocked_and_notify_waiters_when_routes_added() -> Result<()> {
//         let (router_tx, _req) = unbounded_channel();
//         let (responses, mut requests) = unbounded_channel();
//         let mut pending_requests = HashMap::new();
//         let blacklisted_ip = "64.233.162.103".parse().unwrap();
//         let mut blacklist = [blacklisted_ip].iter().copied().collect();
//         let request = UnblockRequest {
//             dns_response: Vec::from(DNS_RESPONSE),
//             sender: "127.0.0.1:1234".parse().unwrap(),
//         };
//         let mut unblocked = HashSet::new();
//         pending_requests.insert(vec![blacklisted_ip], vec![request.clone(), request.clone()]);
//         let message = UnblockerMessage::RouterResponse(RouterResponse::Added(vec![blacklisted_ip]));

//         handle_message(
//             message,
//             &router_tx,
//             &responses,
//             &mut unblocked,
//             &mut blacklist,
//             &mut pending_requests,
//         )?;

//         assert_eq!(
//             requests.try_recv().unwrap(),
//             UnblockResponse::Completed(request.clone())
//         );
//         assert_eq!(
//             requests.try_recv().unwrap(),
//             UnblockResponse::Completed(request.clone())
//         );
//         assert!(unblocked.contains(&blacklisted_ip));
//         Ok(())
//     }

//     #[test]
//     fn should_remove_ip_from_unblocked_when_routes_removed() -> Result<()> {
//         let (router_tx, _req) = unbounded_channel();
//         let (responses, __req) = unbounded_channel();
//         let blacklisted_ip = "64.233.162.103".parse().unwrap();
//         let mut blacklist = [blacklisted_ip].iter().copied().collect();
//         let mut unblocked = [blacklisted_ip].iter().copied().collect();
//         let mut pending_requests = HashMap::new();
//         let message = UnblockerMessage::RouterResponse(RouterResponse::Removed(vec![blacklisted_ip]));

//         handle_message(
//             message,
//             &router_tx,
//             &responses,
//             &mut unblocked,
//             &mut blacklist,
//             &mut pending_requests,
//         )?;

//         assert!(!unblocked.contains(&blacklisted_ip));
//         Ok(())
//     }

//     #[test]
//     fn should_remove_waiters_and_ignore_unblocked_when_routes_add_failed() -> Result<()> {
//         let (router_tx, _req) = unbounded_channel();
//         let (responses, __req) = unbounded_channel();
//         let blacklisted_ip = "64.233.162.103".parse().unwrap();
//         let mut blacklist = [blacklisted_ip].iter().copied().collect();
//         let request = UnblockRequest {
//             dns_response: Vec::from(DNS_RESPONSE),
//             sender: "127.0.0.1:1234".parse().unwrap(),
//         };
//         let mut pending_requests = HashMap::new();
//         let mut unblocked = HashSet::new();
//         pending_requests.insert(vec![blacklisted_ip], vec![request.clone(), request]);
//         let message = UnblockerMessage::RouterResponse(RouterResponse::AddError(vec![blacklisted_ip]));

//         handle_message(
//             message,
//             &router_tx,
//             &responses,
//             &mut unblocked,
//             &mut blacklist,
//             &mut pending_requests,
//         )?;

//         assert!(pending_requests.is_empty());
//         assert!(!unblocked.contains(&blacklisted_ip));
//         Ok(())
//     }
// }
