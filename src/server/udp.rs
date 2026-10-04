//! Plain DNS over UDP.

use crate::acl::Acl;
use crate::dns::{MAX_MSG, Query};
use crate::upstream::Resolver;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tracing::debug;

pub async fn serve(sock: UdpSocket, acl: Acl, resolver: Arc<Resolver>, max_inflight: usize) {
    let sock = Arc::new(sock);
    let inflight = Arc::new(Semaphore::new(max_inflight));
    let mut buf = vec![0u8; MAX_MSG];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                debug!(error = %e, "udp recv");
                continue;
            }
        };
        if !acl.allows(peer.ip()) {
            continue;
        }
        // Invalid queries are dropped silently: answering garbage only
        // helps reflection attacks.
        let Ok(q) = Query::parse(&buf[..n]) else {
            continue;
        };
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            debug!("udp: too many queries in flight, dropping");
            continue;
        };
        let sock = sock.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut resp = resolver.resolve(&q).await;
            // Never send more than the client can take (also caps
            // amplification); TC makes it retry over TCP.
            if resp.len() > q.udp_size {
                resp = q.truncated();
            }
            if let Err(e) = sock.send_to(&resp, peer).await {
                debug!(error = %e, "udp send");
            }
        });
    }
}
