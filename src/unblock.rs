use std::{collections::HashSet, future::Future, net::Ipv4Addr};

use anyhow::Result;
use log::{error, info};
use tokio::{
    stream::{Stream, StreamExt},
    sync::mpsc::UnboundedReceiver,
};

use crate::router_client::RouterClient;

pub async fn create_unblocker(
    blaklist_receiver: UnboundedReceiver<HashSet<Ipv4Addr>>,
    ips_receiver: UnboundedReceiver<Vec<Ipv4Addr>>,
    router_client: RouterClient,
) -> Result<impl Future<Output = ()>> {
    let mut unblocked = router_client.get_routed().await?;
    let mut messages = merge_receivers(ips_receiver, blaklist_receiver);
    let mut blacklist = HashSet::new();
    Ok(async move {
        loop {
            let message = messages.next().await.expect("Senders dropped");
            let process_message =
                handle_message(message, &router_client, &mut blacklist, &mut unblocked);
            if let Err(e) = process_message.await {
                error!("Got error while handling whitelist request: {:#}", e);
            }
        }
    })
}

enum Message {
    Unblock(Vec<Ipv4Addr>),
    NewBlacklist(HashSet<Ipv4Addr>),
}

async fn handle_message(
    message: Message,
    router_client: &RouterClient,
    blacklist: &mut HashSet<Ipv4Addr>,
    unblocked: &mut HashSet<Ipv4Addr>,
) -> Result<()> {
    match message {
        Message::Unblock(ips) => {
            let blocked = ips
                .iter()
                .filter(|ip| blacklist.contains(&ip) && !unblocked.contains(&ip))
                .copied()
                .collect::<Vec<_>>();
            if !blocked.is_empty() {
                info!("Unblocking {:?}", ips);
                router_client.add_routes(&blocked).await?;
                unblocked.extend(blocked);
            }
        }
        Message::NewBlacklist(new_blacklist) => {
            info!("Received blacklist with {} items", new_blacklist.len());
            *blacklist = new_blacklist;
            let removed = unblocked
                .difference(&blacklist)
                .copied()
                .collect::<Vec<_>>();
            if !removed.is_empty() {
                info!("Ips {:?} were removed from blacklist", removed);
                router_client.remove_routes(&removed).await?;
                for ip in removed {
                    unblocked.remove(&ip);
                }
            }
        }
    }
    Ok(())
}

fn merge_receivers(
    ips_receiver: UnboundedReceiver<Vec<Ipv4Addr>>,
    blaklists_receiver: UnboundedReceiver<HashSet<Ipv4Addr>>,
) -> impl Stream<Item = Message> + Unpin {
    ips_receiver
        .map(Message::Unblock)
        .merge(blaklists_receiver.map(Message::NewBlacklist))
}
