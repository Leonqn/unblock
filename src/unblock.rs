use std::{
    collections::HashMap,
    collections::{hash_map::Entry, HashSet},
    future::Future,
    net::{Ipv4Addr, SocketAddr},
};

use crate::dns::message::Message as DnsMessage;
use crate::router_client::RouterClient;
use anyhow::Result;
use log::{error, info};
use tokio::{
    stream::{Stream, StreamExt},
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

#[derive(Debug, Eq, PartialEq)]
pub enum UnblockResponse {
    Completed(UnblockRequest),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnblockRequest {
    pub dns_response: Vec<u8>,
    pub sender: SocketAddr,
}

pub async fn create_unblocker(
    blacklists: UnboundedReceiver<HashSet<Ipv4Addr>>,
    requests: UnboundedReceiver<UnblockRequest>,
    responses: UnboundedSender<UnblockResponse>,
    router_client: RouterClient,
) -> Result<impl Future<Output = ()>> {
    let unblocked = router_client.get_routed().await?;
    let (router_requests_tx, router_requests_rx) = tokio::sync::mpsc::unbounded_channel();
    let (router_responses_tx, router_responses_rx) = tokio::sync::mpsc::unbounded_channel();
    let messages = merge_rxs(requests, blacklists, router_responses_rx);
    
    let router_handler = router_handler(router_client, router_requests_rx, router_responses_tx);
    let unblocker = unblocker(messages, router_requests_tx, responses, unblocked);
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
    unblock_responses_tx: UnboundedSender<UnblockResponse>,
    mut unblocked: HashSet<Ipv4Addr>,
) {
    let mut blacklist = HashSet::new();
    let mut waiters = HashMap::new();
    loop {
        let message = messages.next().await.expect("Senders dropped");
        if let Err(e) = handle_message(
            message,
            &router_requests_tx,
            &unblock_responses_tx,
            &mut unblocked,
            &mut blacklist,
            &mut waiters,
        ) {
            error!("Got error while handling message: {:#}", e);
        }
    }
}

fn handle_message(
    message: Message,
    router_requests_tx: &UnboundedSender<RouterRequest>,
    unblock_responses_tx: &UnboundedSender<UnblockResponse>,
    unblocked: &mut HashSet<Ipv4Addr>,
    blacklist: &mut HashSet<Ipv4Addr>,
    waiting_responses: &mut HashMap<Vec<Ipv4Addr>, Vec<UnblockRequest>>,
) -> Result<()> {
    match message {
        Message::UnblockRequest(request) => {
            let message = DnsMessage::from_packet(&request.dns_response)?;
            let blocked = message
                .ips()
                .filter(|ip| blacklist.contains(ip) && !unblocked.contains(ip))
                .collect::<Vec<_>>();
            if !blocked.is_empty() {
                info!("Unblocking {:?} from {:?}", blocked, message);
                match waiting_responses.entry(blocked) {
                    Entry::Occupied(mut waiters) => waiters.get_mut().push(request),
                    Entry::Vacant(v) => {
                        router_requests_tx
                            .send(RouterRequest::Add(v.key().clone()))
                            .expect("Receiver dropped");
                        v.insert(vec![request]);
                    }
                }
            } else {
                unblock_responses_tx
                    .send(UnblockResponse::Completed(request))
                    .expect("Receiver dropped");
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
            for request in waiting_responses.remove(&addrs).into_iter().flatten() {
                unblock_responses_tx
                    .send(UnblockResponse::Completed(request))
                    .expect("Receiver dropped")
            }
        }

        Message::RouterResponse(RouterResponse::AddError(addrs)) => {
            waiting_responses.remove(&addrs);
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
    mut requests: UnboundedReceiver<RouterRequest>,
    responses: UnboundedSender<RouterResponse>,
) {
    loop {
        let msg = requests.recv().await.expect("Senders dropped");
        let handle_message = async {
            match msg {
                RouterRequest::Add(addrs) => {
                    if let Err(err) = router_client.add_routes(&addrs).await {
                        responses
                            .send(RouterResponse::AddError(addrs))
                            .expect("Receiver dropped");
                        return Err(err);
                    } else {
                        responses
                            .send(RouterResponse::Added(addrs))
                            .expect("Receiver dropped");
                    }
                }
                RouterRequest::Remove(addrs) => {
                    router_client.remove_routes(&addrs).await?;
                    responses
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
    use tokio::sync::mpsc::unbounded_channel;

    static DNS_RESPONSE: &[u8] = include_bytes!("../test/dns_packets/a_www.google.com.bin");

    #[test]
    fn should_send_add_routes_when_ips_are_blocked() -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let (responses, _req) = unbounded_channel();
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let mut blacklist = [blacklisted_ip].iter().copied().collect();
        let message = Message::UnblockRequest(UnblockRequest {
            dns_response: Vec::from(DNS_RESPONSE),
            sender: "127.0.0.1:1234".parse().unwrap(),
        });

        handle_message(
            message,
            &router_tx,
            &responses,
            &mut HashSet::new(),
            &mut blacklist,
            &mut HashMap::new(),
        )?;

        assert_eq!(
            router_rx.try_recv().unwrap(),
            RouterRequest::Add(vec![blacklisted_ip])
        );
        Ok(())
    }

    #[test]
    fn should_not_send_add_routes_when_ips_are_unblocked() -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let (responses, _req) = unbounded_channel();
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let mut blacklist = [blacklisted_ip].iter().copied().collect();
        let mut unblocked = [blacklisted_ip].iter().copied().collect();
        let message = Message::UnblockRequest(UnblockRequest {
            dns_response: Vec::from(DNS_RESPONSE),
            sender: "127.0.0.1:1234".parse().unwrap(),
        });

        handle_message(
            message,
            &router_tx,
            &responses,
            &mut unblocked,
            &mut blacklist,
            &mut HashMap::new(),
        )?;

        assert!(router_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn should_not_send_add_routes_when_ips_arent_in_blacklist() -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let (responses, _req) = unbounded_channel();
        let blacklisted_ip = "65.233.162.103".parse().unwrap();
        let mut blacklist = [blacklisted_ip].iter().copied().collect();
        let message = Message::UnblockRequest(UnblockRequest {
            dns_response: Vec::from(DNS_RESPONSE),
            sender: "127.0.0.1:1234".parse().unwrap(),
        });

        handle_message(
            message,
            &router_tx,
            &responses,
            &mut HashSet::new(),
            &mut blacklist,
            &mut HashMap::new(),
        )?;

        assert!(router_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn should_not_send_add_routes_and_insert_waiter_when_there_is_pending_request() -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let (responses, _req) = unbounded_channel();
        let mut pending_requests = HashMap::new();
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let mut blacklist = [blacklisted_ip].iter().copied().collect();
        let request = UnblockRequest {
            dns_response: Vec::from(DNS_RESPONSE),
            sender: "127.0.0.1:1234".parse().unwrap(),
        };
        let message = Message::UnblockRequest(request.clone());
        pending_requests.insert(vec![blacklisted_ip], vec![request]);

        handle_message(
            message,
            &router_tx,
            &responses,
            &mut HashSet::new(),
            &mut blacklist,
            &mut pending_requests,
        )?;

        assert!(router_rx.try_recv().is_err());
        assert_eq!(pending_requests[[blacklisted_ip].as_ref()].len(), 2);
        Ok(())
    }

    #[test]
    fn should_send_remove_routes_when_new_blacklist_does_not_contains_previously_unblocked(
    ) -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let (responses, _req) = unbounded_channel();
        let blacklisted_ip = "127.0.0.1".parse().unwrap();
        let mut blacklist = [blacklisted_ip].iter().copied().collect();
        let mut unblocked = [blacklisted_ip].iter().copied().collect();
        let message =
            Message::Blacklist(["192.168.1.1".parse().unwrap()].iter().copied().collect());

        handle_message(
            message,
            &router_tx,
            &responses,
            &mut unblocked,
            &mut blacklist,
            &mut HashMap::new(),
        )?;

        assert_eq!(
            router_rx.try_recv().unwrap(),
            RouterRequest::Remove(vec![blacklisted_ip])
        );
        Ok(())
    }

    #[test]
    fn should_not_send_remove_routes_when_new_blacklist_contains_all_previous_ips() -> Result<()> {
        let (router_tx, mut router_rx) = unbounded_channel();
        let (responses, _req) = unbounded_channel();
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let mut blacklist: HashSet<_> = [blacklisted_ip].iter().copied().collect();
        let mut unblocked = [blacklisted_ip].iter().copied().collect();
        let message = Message::Blacklist(blacklist.clone());

        handle_message(
            message,
            &router_tx,
            &responses,
            &mut unblocked,
            &mut blacklist,
            &mut HashMap::new(),
        )?;

        assert!(router_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn should_update_unblocked_and_notify_waiters_when_routes_added() -> Result<()> {
        let (router_tx, _req) = unbounded_channel();
        let (responses, mut requests) = unbounded_channel();
        let mut pending_requests = HashMap::new();
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let mut blacklist = [blacklisted_ip].iter().copied().collect();
        let request = UnblockRequest {
            dns_response: Vec::from(DNS_RESPONSE),
            sender: "127.0.0.1:1234".parse().unwrap(),
        };
        let mut unblocked = HashSet::new();
        pending_requests.insert(vec![blacklisted_ip], vec![request.clone(), request.clone()]);
        let message = Message::RouterResponse(RouterResponse::Added(vec![blacklisted_ip]));

        handle_message(
            message,
            &router_tx,
            &responses,
            &mut unblocked,
            &mut blacklist,
            &mut pending_requests,
        )?;

        assert_eq!(
            requests.try_recv().unwrap(),
            UnblockResponse::Completed(request.clone())
        );
        assert_eq!(
            requests.try_recv().unwrap(),
            UnblockResponse::Completed(request.clone())
        );
        assert!(unblocked.contains(&blacklisted_ip));
        Ok(())
    }

    #[test]
    fn should_remove_ip_from_unblocked_when_routes_removed() -> Result<()> {
        let (router_tx, _req) = unbounded_channel();
        let (responses, __req) = unbounded_channel();
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let mut blacklist = [blacklisted_ip].iter().copied().collect();
        let mut unblocked = [blacklisted_ip].iter().copied().collect();
        let mut pending_requests = HashMap::new();
        let message = Message::RouterResponse(RouterResponse::Removed(vec![blacklisted_ip]));

        handle_message(
            message,
            &router_tx,
            &responses,
            &mut unblocked,
            &mut blacklist,
            &mut pending_requests,
        )?;

        assert!(!unblocked.contains(&blacklisted_ip));
        Ok(())
    }

    #[test]
    fn should_remove_waiters_and_ignore_unblocked_when_routes_add_failed() -> Result<()> {
        let (router_tx, _req) = unbounded_channel();
        let (responses, __req) = unbounded_channel();
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let mut blacklist = [blacklisted_ip].iter().copied().collect();
        let request = UnblockRequest {
            dns_response: Vec::from(DNS_RESPONSE),
            sender: "127.0.0.1:1234".parse().unwrap(),
        };
        let mut pending_requests = HashMap::new();
        let mut unblocked = HashSet::new();
        pending_requests.insert(vec![blacklisted_ip], vec![request.clone(), request]);
        let message = Message::RouterResponse(RouterResponse::AddError(vec![blacklisted_ip]));

        handle_message(
            message,
            &router_tx,
            &responses,
            &mut unblocked,
            &mut blacklist,
            &mut pending_requests,
        )?;

        assert!(pending_requests.is_empty());
        assert!(!unblocked.contains(&blacklisted_ip));
        Ok(())
    }
}
