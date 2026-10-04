//! DNS over HTTPS client (RFC 8484), HTTP/2 only, one multiplexed
//! connection per upstream that is re-established on failure.

use super::{BoxError, connect_any};
use crate::dns::MAX_MSG;
use crate::tls;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::client::conn::http2::{self, SendRequest};
use hyper::header::{ACCEPT, CONTENT_TYPE};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tracing::debug;

pub const DNS_MESSAGE: &str = "application/dns-message";

type Sender = SendRequest<Full<Bytes>>;

pub struct Doh {
    uri: Uri,
    name: ServerName<'static>,
    addrs: Vec<SocketAddr>,
    connector: TlsConnector,
    /// Current connection, tagged with a generation so a failing request
    /// only tears down the connection it actually used.
    conn: Mutex<Option<(u64, Sender)>>,
    generation: AtomicU64,
    next_addr: AtomicUsize,
}

impl Doh {
    pub fn new(url: &str, addrs: Vec<SocketAddr>, ca: Option<&Path>) -> Result<Self, String> {
        let err = |m: &str| format!("upstream doh '{url}': {m}");
        let uri: Uri = url.parse().map_err(|_| err("invalid URL"))?;
        if uri.scheme_str() != Some("https") {
            return Err(err("scheme must be https"));
        }
        let auth = uri.authority().ok_or_else(|| err("missing host"))?;
        if auth.as_str().contains('@') {
            return Err(err("userinfo not allowed"));
        }
        if uri.path().is_empty() || uri.path() == "/" {
            return Err(err("missing path (e.g. /dns-query)"));
        }
        if uri.query().is_some() {
            return Err(err("query string not allowed"));
        }
        let host = auth.host().trim_start_matches('[').trim_end_matches(']');
        let name = ServerName::try_from(host.to_owned()).map_err(|e| err(&e.to_string()))?;
        let cfg = tls::client_config(ca, &[b"h2"])?;
        Ok(Self {
            uri,
            name,
            addrs,
            connector: TlsConnector::from(cfg),
            conn: Mutex::new(None),
            generation: AtomicU64::new(0),
            next_addr: AtomicUsize::new(0),
        })
    }

    pub async fn exchange(&self, msg: &[u8]) -> Result<Vec<u8>, BoxError> {
        let (generation, mut sender) = self.sender().await?;
        match self.send(&mut sender, msg).await {
            Ok(r) => Ok(r),
            Err(e) => {
                let mut slot = self.conn.lock().await;
                if matches!(&*slot, Some((g, _)) if *g == generation) {
                    *slot = None;
                }
                Err(e)
            }
        }
    }

    async fn send(&self, sender: &mut Sender, msg: &[u8]) -> Result<Vec<u8>, BoxError> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(self.uri.clone())
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .body(Full::new(Bytes::copy_from_slice(msg)))?;
        sender.ready().await?;
        let resp = sender.send_request(req).await?;
        if resp.status() != StatusCode::OK {
            return Err(format!("HTTP status {}", resp.status()).into());
        }
        let ct = resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok());
        if !ct.is_some_and(is_dns_message) {
            return Err("unexpected content-type".into());
        }
        let body = Limited::new(resp.into_body(), MAX_MSG).collect().await?;
        Ok(body.to_bytes().to_vec())
    }

    /// Returns the live connection or establishes a new one. The lock is
    /// held while connecting so concurrent queries share one handshake.
    async fn sender(&self) -> Result<(u64, Sender), BoxError> {
        let mut slot = self.conn.lock().await;
        if let Some((g, s)) = &*slot {
            if !s.is_closed() {
                return Ok((*g, s.clone()));
            }
        }
        let s = self.connect().await?;
        let g = self.generation.fetch_add(1, Ordering::Relaxed);
        *slot = Some((g, s.clone()));
        Ok((g, s))
    }

    async fn connect(&self) -> Result<Sender, BoxError> {
        connect_any(&self.addrs, &self.next_addr, |a| self.connect_one(a)).await
    }

    async fn connect_one(&self, addr: SocketAddr) -> Result<Sender, BoxError> {
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let tls = self.connector.connect(self.name.clone(), tcp).await?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err("server did not negotiate HTTP/2".into());
        }
        let (sender, conn) = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            // Detect dead connections while requests are outstanding.
            .keep_alive_interval(Duration::from_secs(10))
            .keep_alive_timeout(Duration::from_secs(5))
            .handshake(TokioIo::new(tls))
            .await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "doh upstream connection closed");
            }
        });
        Ok(sender)
    }
}

/// `application/dns-message`, ignoring parameters and case.
pub fn is_dns_message(ct: &str) -> bool {
    ct.split(';')
        .next()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case(DNS_MESSAGE))
}
