pub mod doh;
pub mod stream;
pub mod udp;

use crate::acl::Acl;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::debug;

/// Accepts TCP connections, enforcing the allowlist and the connection
/// limit before any byte is read, and hands them to `handle`.
pub async fn accept_loop<F, Fut>(listener: TcpListener, acl: Acl, max_conns: usize, handle: F)
where
    F: Fn(TcpStream, SocketAddr, OwnedSemaphorePermit) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let conns = Arc::new(Semaphore::new(max_conns));
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // E.g. EMFILE: back off instead of spinning.
                debug!(error = %e, "accept");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !acl.allows(peer.ip()) {
            continue;
        }
        let Ok(permit) = conns.clone().try_acquire_owned() else {
            debug!("connection limit reached, closing");
            continue;
        };
        let _ = tcp.set_nodelay(true);
        tokio::spawn(handle(tcp, peer, permit));
    }
}
