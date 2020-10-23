use anyhow::{Context, Result};
use log::error;
use std::time::Duration;
use tokio::{net::UdpSocket, time::timeout};

use crate::whitelist::Whitelist;

mod packet;

pub async fn start(
    mut server: UdpSocket,
    mut client: UdpSocket,
    request_timeout: Duration,
    whitelist: Whitelist,
) {
    let mut packet_buf = [0; 576];
    let mut ips = Vec::new();
    loop {
        let handle_fut = async {
            let (bytes_read, sender) = server.recv_from(&mut packet_buf).await?;
            let response = timeout(
                request_timeout,
                handle_request(&mut client, &mut packet_buf, bytes_read),
            )
            .await??;

            ips.clear();
            packet::extract_ips(response, &mut ips)
                .with_context(|| format!("Received packet: {:x?}", response))?;
            whitelist.whitelist_if_needed(&ips).await?;
            server.send_to(response, sender).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;

        if let Err(e) = handle_fut {
            error!("got error while handling request: {:?}", e);
        }
    }
}

async fn handle_request<'buf>(
    client: &mut UdpSocket,
    packet_buf: &'buf mut [u8],
    request_size: usize,
) -> Result<&'buf [u8]> {
    client.send(&packet_buf[0..request_size]).await?;
    let read = client.recv(packet_buf).await?;
    Ok(&packet_buf[0..read])
}
