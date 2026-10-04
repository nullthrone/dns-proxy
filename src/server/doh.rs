//! DNS over HTTPS server (RFC 8484): HTTP/1.1 and HTTP/2, GET and POST on a
//! single path. Nothing else is served.

use crate::dns::{MAX_MSG, Query};
use crate::upstream::Resolver;
use crate::upstream::doh::{DNS_MESSAGE, is_dns_message};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD_INDIFFERENT;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

/// Grace period for in-flight requests after an idle shutdown starts.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

pub struct Params {
    pub resolver: Arc<Resolver>,
    pub path: String,
    pub idle: Duration,
    pub max_inflight: usize,
}

/// Tracks request activity on one connection for the idle timeout
/// (HTTP/2 connections are otherwise kept open indefinitely).
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
    inflight: AtomicUsize,
}

impl Activity {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn touch(&self) {
        self.last_ms.store(self.now_ms(), Ordering::Relaxed);
    }
    fn idle_for(&self) -> Duration {
        Duration::from_millis(self.now_ms().saturating_sub(self.last_ms.load(Ordering::Relaxed)))
    }
}

struct InflightGuard(Arc<Activity>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::Relaxed);
        self.0.touch();
    }
}

pub async fn handle<S>(stream: S, p: Arc<Params>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let activity = Arc::new(Activity {
        start: Instant::now(),
        last_ms: AtomicU64::new(0),
        inflight: AtomicUsize::new(0),
    });

    let svc = {
        let p = p.clone();
        let activity = activity.clone();
        hyper::service::service_fn(move |req| {
            let p = p.clone();
            activity.inflight.fetch_add(1, Ordering::Relaxed);
            let guard = InflightGuard(activity.clone());
            async move {
                let resp = respond(req, &p).await;
                drop(guard);
                Ok::<_, Infallible>(resp)
            }
        })
    };

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(p.idle)
        .max_buf_size(16 * 1024);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(u32::try_from(p.max_inflight).unwrap_or(u32::MAX))
        .max_header_list_size(16 * 1024)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(10));

    let conn = builder.serve_connection(TokioIo::new(stream), svc);
    tokio::pin!(conn);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = conn.as_mut() => return,
            _ = tick.tick() => {
                if activity.inflight.load(Ordering::Relaxed) == 0 && activity.idle_for() >= p.idle {
                    break;
                }
            }
        }
    }
    conn.as_mut().graceful_shutdown();
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, conn).await;
}

/// Constant-time equality (only the length may leak).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::default());
    *r.status_mut() = code;
    r
}

async fn respond(req: Request<Incoming>, p: &Params) -> Response<Full<Bytes>> {
    // The path may carry a secret token, so compare in constant time.
    if !ct_eq(req.uri().path().as_bytes(), p.path.as_bytes()) {
        return status(StatusCode::NOT_FOUND);
    }
    let msg = match *req.method() {
        Method::GET => {
            let param = req
                .uri()
                .query()
                .unwrap_or_default()
                .split('&')
                .find_map(|kv| kv.strip_prefix("dns="));
            // base64url of a 65535-byte message is at most 87380 chars.
            match param
                .filter(|s| s.len() <= 87_380)
                .map(|s| URL_SAFE_NO_PAD_INDIFFERENT.decode(s))
            {
                Some(Ok(m)) => m,
                _ => return status(StatusCode::BAD_REQUEST),
            }
        }
        Method::POST => {
            let ct = req.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok());
            if !ct.is_some_and(is_dns_message) {
                return status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            // Bounded in size and time: a slowly trickling body must not
            // hold a connection slot indefinitely.
            match tokio::time::timeout(p.idle, Limited::new(req.into_body(), MAX_MSG).collect()).await {
                Ok(Ok(b)) => b.to_bytes().to_vec(),
                Ok(Err(e)) if e.is::<LengthLimitError>() => return status(StatusCode::PAYLOAD_TOO_LARGE),
                Ok(Err(_)) => return status(StatusCode::BAD_REQUEST),
                Err(_) => return status(StatusCode::REQUEST_TIMEOUT),
            }
        }
        _ => {
            let mut r = status(StatusCode::METHOD_NOT_ALLOWED);
            r.headers_mut()
                .insert(ALLOW, "GET, POST".parse().expect("static header"));
            return r;
        }
    };
    let Ok(q) = Query::parse(&msg) else {
        return status(StatusCode::BAD_REQUEST);
    };
    let answer = p.resolver.resolve(&q).await;
    let mut r = Response::new(Full::new(Bytes::from(answer)));
    r.headers_mut()
        .insert(CONTENT_TYPE, DNS_MESSAGE.parse().expect("static header"));
    r
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"/dns-query/abc", b"/dns-query/abc"));
        assert!(!ct_eq(b"/dns-query/abd", b"/dns-query/abc"));
        assert!(!ct_eq(b"/dns-query", b"/dns-query/abc"));
        assert!(ct_eq(b"", b""));
    }
}
