//! DNS over TLS client (RFC 7858) with a small pool of persistent
//! connections. Each connection carries one query at a time, which avoids
//! ID multiplexing and out-of-order handling entirely.

use super::{BoxError, connect_any};
use crate::frame::{read_frame, write_frame};
use crate::tls;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Pooled connections idle longer than this are discarded; most resolvers
/// close idle connections after ~10-30 s anyway.
const MAX_IDLE: Duration = Duration::from_secs(10);

type Conn = TlsStream<TcpStream>;

pub struct Dot {
    name: ServerName<'static>,
    addrs: Vec<SocketAddr>,
    connector: TlsConnector,
    pool: Mutex<Vec<(Conn, Instant)>>,
    pool_size: usize,
    next_addr: AtomicUsize,
}

impl Dot {
    pub fn new(
        name: &str,
        addrs: Vec<SocketAddr>,
        ca: Option<&Path>,
        pool_size: usize,
    ) -> Result<Self, String> {
        let name =
            ServerName::try_from(name.to_owned()).map_err(|e| format!("upstream dot '{name}': {e}"))?;
        // No ALPN: RFC 7858 does not require it and some servers reject
        // unknown protocols.
        let cfg = tls::client_config(ca, &[])?;
        Ok(Self {
            name,
            addrs,
            connector: TlsConnector::from(cfg),
            pool: Mutex::new(Vec::new()),
            pool_size,
            next_addr: AtomicUsize::new(0),
        })
    }

    pub async fn exchange(&self, msg: &[u8]) -> Result<Vec<u8>, BoxError> {
        // A pooled connection may have been closed by the server in the
        // meantime; on failure fall through to a fresh connection.
        if let Some(mut c) = self.checkout() {
            if let Ok(r) = roundtrip(&mut c, msg).await {
                self.checkin(c);
                return Ok(r);
            }
        }
        let mut c = self.connect().await?;
        let r = roundtrip(&mut c, msg).await?;
        self.checkin(c);
        Ok(r)
    }

    fn checkout(&self) -> Option<Conn> {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        while let Some((c, since)) = pool.pop() {
            if since.elapsed() < MAX_IDLE {
                return Some(c);
            }
        }
        None
    }

    fn checkin(&self, c: Conn) {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        if pool.len() < self.pool_size {
            pool.push((c, Instant::now()));
        }
    }

    async fn connect(&self) -> Result<Conn, BoxError> {
        connect_any(&self.addrs, &self.next_addr, |a| self.connect_one(a)).await
    }

    async fn connect_one(&self, addr: SocketAddr) -> Result<Conn, BoxError> {
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        Ok(self.connector.connect(self.name.clone(), tcp).await?)
    }
}

async fn roundtrip(c: &mut Conn, msg: &[u8]) -> Result<Vec<u8>, BoxError> {
    write_frame(c, msg).await?;
    read_frame(c).await?.ok_or_else(|| "connection closed".into())
}
