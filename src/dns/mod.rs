use anyhow::Result;
use bytes::Bytes;
use futures_util::stream::Stream;
use std::net::SocketAddr;
use tokio::net::udp::RecvHalf;

pub mod client;
pub mod message;
pub mod server;

fn create_udp_dns_stream(
    socket: RecvHalf,
) -> impl Stream<Item = Result<(SocketAddr, Bytes), tokio::io::Error>> {
    let buf = vec![0; 512];
    futures_util::stream::unfold((socket, buf), |(mut socket, mut buf)| async move {
        let recv = async {
            let (read, sender) = socket.recv_from(&mut buf).await?;
            Ok((sender, Bytes::copy_from_slice(&buf[0..read])))
        };
        Some((recv.await, (socket, buf)))
    })
}
