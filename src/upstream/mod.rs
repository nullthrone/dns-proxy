//! Encrypted upstreams (DoT, DoH) and ordered failover between them.

pub(crate) mod doh;
mod dot;

use crate::config::{self, Limits, UpstreamKind};
use crate::dns::{self, Query};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, info, warn};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long a failed upstream is moved to the end of the try order.
const PENALTY: Duration = Duration::from_secs(30);

enum Kind {
    Dot(dot::Dot),
    Doh(doh::Doh),
}

struct Upstream {
    label: String,
    kind: Kind,
    /// Milliseconds since `Resolver::epoch` until which this upstream is
    /// deprioritised; 0 = healthy.
    penalised_until: AtomicU64,
}

impl Upstream {
    async fn exchange(&self, q: &Query) -> Result<Vec<u8>, BoxError> {
        // RFC 8484 recommends ID 0 for DoH (HTTP caching); DoT gets a fresh
        // random ID so the client's ID never leaves this host.
        let id = match self.kind {
            Kind::Dot(_) => crate::tls::random_u16(),
            Kind::Doh(_) => 0,
        };
        let msg = q.with_id(id);
        let mut resp = match &self.kind {
            Kind::Dot(d) => d.exchange(&msg).await?,
            Kind::Doh(d) => d.exchange(&msg).await?,
        };
        if dns::id(&resp) != Some(id) || !q.is_answered_by(&resp) {
            return Err("response does not match query".into());
        }
        dns::set_id(&mut resp, q.id);
        Ok(resp)
    }
}

pub struct Resolver {
    upstreams: Vec<Upstream>,
    attempt_timeout: Duration,
    deadline: Duration,
    epoch: Instant,
}

impl Resolver {
    pub fn new(cfgs: &[config::Upstream], limits: &Limits) -> Result<Self, String> {
        let mut upstreams = Vec::with_capacity(cfgs.len());
        for c in cfgs {
            let ca = c.ca_file.as_deref().map(config::expand_path).transpose()?;
            let (label, kind) = match c.kind {
                UpstreamKind::Dot => {
                    let name = c.name.clone().unwrap_or_default();
                    let d = dot::Dot::new(&name, c.addrs.clone(), ca.as_deref(), limits.dot_pool_size)?;
                    (format!("dot://{name}"), Kind::Dot(d))
                }
                UpstreamKind::Doh => {
                    let url = c.url.clone().unwrap_or_default();
                    let d = doh::Doh::new(&url, c.addrs.clone(), ca.as_deref())?;
                    (url, Kind::Doh(d))
                }
            };
            upstreams.push(Upstream {
                label,
                kind,
                penalised_until: AtomicU64::new(0),
            });
        }
        Ok(Self {
            upstreams,
            attempt_timeout: limits.upstream_timeout(),
            deadline: limits.query_timeout(),
            epoch: Instant::now(),
        })
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Resolves `q` via the first upstream that answers. Always returns a
    /// response for the client: SERVFAIL if every upstream fails.
    pub async fn resolve(&self, q: &Query) -> Vec<u8> {
        let attempts = async {
            let now = self.now_ms();
            let healthy = |u: &&Upstream| u.penalised_until.load(Ordering::Relaxed) <= now;
            // Fixed up front: penalties set during this loop must not make
            // an upstream reappear in the same resolution.
            let order: Vec<&Upstream> = self
                .upstreams
                .iter()
                .filter(healthy)
                .chain(self.upstreams.iter().filter(|u| !healthy(u)))
                .collect();
            for u in order {
                let err = match timeout(self.attempt_timeout, u.exchange(q)).await {
                    Ok(Ok(resp)) => {
                        if u.penalised_until.swap(0, Ordering::Relaxed) != 0 {
                            info!(upstream = %u.label, "upstream recovered");
                        }
                        return Some(resp);
                    }
                    Ok(Err(e)) => e.to_string(),
                    Err(_) => "timed out".to_string(),
                };
                let until = self.now_ms().saturating_add(PENALTY.as_millis() as u64);
                // Warn once per outage, not once per query.
                if u.penalised_until.swap(until, Ordering::Relaxed) <= now {
                    warn!(upstream = %u.label, error = %err, "upstream failed, deprioritised for 30 s");
                } else {
                    debug!(upstream = %u.label, error = %err, "upstream still failing");
                }
            }
            None
        };
        match timeout(self.deadline, attempts).await {
            Ok(Some(resp)) => resp,
            _ => {
                debug!("all upstreams failed, answering SERVFAIL");
                q.servfail()
            }
        }
    }
}

/// Connects to the first reachable bootstrap address, starting at a
/// rotating offset to spread load. Reports every address's error.
async fn connect_any<T, F, Fut>(addrs: &[SocketAddr], next: &AtomicUsize, connect: F) -> Result<T, BoxError>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, BoxError>>,
{
    let start = next.fetch_add(1, Ordering::Relaxed);
    let mut errors = Vec::with_capacity(addrs.len());
    for i in 0..addrs.len() {
        let addr = addrs[(start + i) % addrs.len()];
        match connect(addr).await {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(format!("{addr}: {e}")),
        }
    }
    Err(errors.join("; ").into())
}
