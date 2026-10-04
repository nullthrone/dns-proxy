//! Plain DNS over TCP and DNS over TLS (RFC 7858). Queries on one
//! connection are processed concurrently (RFC 7766 pipelining), bounded
//! per connection.

use crate::dns::Query;
use crate::frame::{read_frame, write_frame};
use crate::upstream::Resolver;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;

pub struct Params {
    pub resolver: Arc<Resolver>,
    pub idle: Duration,
    pub max_inflight: usize,
}

pub async fn handle<S>(stream: S, p: Arc<Params>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(p.max_inflight);
    let idle = p.idle;
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            // A client that stops reading must not pin the connection.
            if !matches!(timeout(idle, write_frame(&mut wr, &msg)).await, Ok(Ok(()))) {
                return;
            }
        }
        let _ = wr.shutdown().await;
    });

    let inflight = Arc::new(Semaphore::new(p.max_inflight));
    loop {
        // Stop reading while the per-connection limit is exhausted.
        let Ok(permit) = inflight.clone().acquire_owned().await else {
            break;
        };
        // Each message must arrive completely within the idle timeout.
        let msg = match timeout(p.idle, read_frame(&mut rd)).await {
            Ok(Ok(Some(m))) => m,
            _ => break,
        };
        let Ok(q) = Query::parse(&msg) else {
            break;
        };
        let tx = tx.clone();
        let resolver = p.resolver.clone();
        tokio::spawn(async move {
            let resp = resolver.resolve(&q).await;
            let _ = tx.send(resp).await;
            drop(permit);
        });
    }
    // Let in-flight answers drain; the writer ends once all senders are gone.
    drop(tx);
    let _ = writer.await;
}
