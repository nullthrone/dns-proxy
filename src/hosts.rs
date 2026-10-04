//! Allowlist hostnames (e.g. DynDNS): resolved in the background through
//! the encrypted upstreams, never per packet and never via the system
//! resolver. The packet path only reads the last known addresses.

use crate::config::HostAcl;
use crate::dns::{self, Lookup, Query};
use crate::upstream::Resolver;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::sleep_until;
use tracing::{info, warn};

#[derive(Debug, Default)]
struct Family {
    addrs: Vec<IpAddr>,
    /// Last definitive answer (addresses or NXDOMAIN/NODATA).
    last_ok: Option<Instant>,
    /// Currently in a failure streak (for log deduplication).
    failing: bool,
}

/// One hostname with its last known IPv4 and IPv6 addresses.
#[derive(Debug)]
pub struct HostSlot {
    name: String,
    queries: [Query; 2],
    families: [RwLock<Family>; 2],
}

const LABELS: [&str; 2] = ["A", "AAAA"];

impl HostSlot {
    fn new(name: String) -> Result<Self, String> {
        let wire = dns::encode_name(&name).map_err(|_| format!("invalid hostname {name:?}"))?;
        let q = |t| Query::build(&wire, t).map_err(|_| format!("invalid hostname {name:?}"));
        Ok(Self {
            queries: [q(dns::TYPE_A)?, q(dns::TYPE_AAAA)?],
            families: Default::default(),
            name,
        })
    }

    /// Whether `ip` lies within `prefix` of any current address of its
    /// family.
    pub fn matches(&self, ip: IpAddr, v4_prefix: u8, v6_prefix: u8) -> bool {
        let (fam, prefix) = match ip {
            IpAddr::V4(_) => (&self.families[0], v4_prefix),
            IpAddr::V6(_) => (&self.families[1], v6_prefix),
        };
        let fam = fam.read().unwrap_or_else(|e| e.into_inner());
        fam.addrs.iter().any(|a| {
            ipnet::IpNet::new(*a, prefix)
                .map(|n| n.contains(&ip))
                .unwrap_or(false)
        })
    }

    /// Applies a lookup result; returns when this family wants a refresh.
    fn apply(&self, idx: usize, lookup: Lookup, now: Instant, cfg: &HostAcl) -> Duration {
        let mut fam = self.families[idx].write().unwrap_or_else(|e| e.into_inner());
        let (name, rr) = (&self.name, LABELS[idx]);
        match lookup {
            Lookup::Found { mut addrs, ttl } => {
                addrs.sort();
                addrs.dedup();
                if fam.addrs != addrs {
                    info!(host = %name, rr, old = ?fam.addrs, new = ?addrs, "allowlist host updated");
                } else if fam.failing {
                    info!(host = %name, rr, "allowlist host resolves again");
                }
                fam.addrs = addrs;
                fam.last_ok = Some(now);
                fam.failing = false;
                Duration::from_secs(u64::from(ttl))
            }
            Lookup::NotFound => {
                if !fam.addrs.is_empty() {
                    info!(host = %name, rr, old = ?fam.addrs, "allowlist host has no addresses anymore");
                }
                fam.addrs.clear();
                fam.last_ok = Some(now);
                fam.failing = false;
                // Re-added records are picked up via the reject trigger.
                cfg.refresh_max()
            }
            Lookup::Failed => {
                if !fam.failing {
                    if fam.addrs.is_empty() {
                        warn!(host = %name, rr, "allowlist host resolution failed");
                    } else {
                        warn!(host = %name, rr, old = ?fam.addrs, "allowlist host resolution failed, keeping last known addresses");
                    }
                    fam.failing = true;
                }
                let expired = fam
                    .last_ok
                    .is_none_or(|t| now.duration_since(t) >= cfg.max_stale());
                if expired && !fam.addrs.is_empty() {
                    warn!(host = %name, rr, old = ?fam.addrs, "allowlist host addresses expired");
                    fam.addrs.clear();
                }
                cfg.refresh_min()
            }
        }
    }
}

/// All allowlist hostnames of the process, resolved by one task.
pub struct Hosts {
    slots: Vec<Arc<HostSlot>>,
    trigger: Notify,
    cfg: HostAcl,
}

impl Hosts {
    pub fn new(names: impl IntoIterator<Item = String>, cfg: &HostAcl) -> Result<Self, String> {
        let mut names: Vec<String> = names.into_iter().collect();
        names.sort();
        names.dedup();
        let slots = names
            .into_iter()
            .map(|n| HostSlot::new(n).map(Arc::new))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            slots,
            trigger: Notify::new(),
            cfg: cfg.clone(),
        })
    }

    pub fn slot(&self, name: &str) -> Option<Arc<HostSlot>> {
        self.slots.iter().find(|s| s.name == name).cloned()
    }

    /// Requests an early refresh, e.g. because a client was rejected whose
    /// DynDNS name may have just changed. Coalescing and cheap; the
    /// refresher enforces `trigger_min_interval`.
    pub fn trigger(&self) {
        self.trigger.notify_one();
    }

    /// Refresh loop; never returns.
    pub async fn run(self: Arc<Self>, resolver: Arc<Resolver>) {
        let cfg = &self.cfg;
        loop {
            let started = Instant::now();
            let deadline = tokio::time::Instant::from_std(started + self.refresh(&resolver).await);
            let earliest_trigger = tokio::time::Instant::from_std(started + cfg.trigger_min_interval());
            tokio::select! {
                _ = sleep_until(deadline) => {}
                _ = self.trigger.notified() => sleep_until(earliest_trigger.min(deadline)).await,
            }
        }
    }

    /// Resolves every slot once; returns the delay until the next refresh.
    async fn refresh(&self, resolver: &Arc<Resolver>) -> Duration {
        let cfg = &self.cfg;
        let mut tasks = JoinSet::new();
        for slot in &self.slots {
            for idx in 0..2 {
                let (slot, resolver) = (slot.clone(), resolver.clone());
                tasks.spawn(async move {
                    let q = &slot.queries[idx];
                    let lookup = q.addresses(&resolver.resolve(q).await);
                    (slot, idx, lookup)
                });
            }
        }
        let mut next = cfg.refresh_max();
        while let Some(res) = tasks.join_next().await {
            let Ok((slot, idx, lookup)) = res else { continue };
            next = next.min(slot.apply(idx, lookup, Instant::now(), cfg));
        }
        next.clamp(cfg.refresh_min(), cfg.refresh_max())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HostAcl {
        HostAcl {
            refresh_min_ms: 1_000,
            refresh_max_ms: 10_000,
            max_stale_ms: 60_000,
            trigger_min_interval_ms: 1_000,
        }
    }

    fn found(addrs: &[&str], ttl: u32) -> Lookup {
        Lookup::Found {
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            ttl,
        }
    }

    #[test]
    fn matching_with_prefixes() {
        let s = HostSlot::new("home.dyn.example".into()).unwrap();
        let now = Instant::now();
        s.apply(0, found(&["192.0.2.10"], 60), now, &cfg());
        s.apply(1, found(&["2001:db8:1:2::1"], 60), now, &cfg());
        assert!(s.matches("192.0.2.10".parse().unwrap(), 32, 64));
        assert!(!s.matches("192.0.2.11".parse().unwrap(), 32, 64));
        assert!(s.matches("192.0.2.11".parse().unwrap(), 24, 64));
        assert!(s.matches("2001:db8:1:2::abcd".parse().unwrap(), 32, 64));
        assert!(!s.matches("2001:db8:1:3::1".parse().unwrap(), 32, 64));
        assert!(s.matches("2001:db8:1:3::1".parse().unwrap(), 32, 56));
    }

    #[test]
    fn lifecycle() {
        let c = cfg();
        let s = HostSlot::new("home.dyn.example".into()).unwrap();
        let ip = "192.0.2.10".parse().unwrap();
        let t0 = Instant::now();
        // Nothing known yet: fail closed.
        assert!(!s.matches(ip, 32, 64));
        assert_eq!(s.apply(0, Lookup::Failed, t0, &c), c.refresh_min());
        assert!(!s.matches(ip, 32, 64));

        assert_eq!(
            s.apply(0, found(&["192.0.2.10"], 42), t0, &c),
            Duration::from_secs(42)
        );
        assert!(s.matches(ip, 32, 64));
        // Failure within max_stale keeps the address.
        s.apply(0, Lookup::Failed, t0 + Duration::from_secs(59), &c);
        assert!(s.matches(ip, 32, 64));
        // Beyond max_stale it is dropped.
        s.apply(0, Lookup::Failed, t0 + Duration::from_secs(60), &c);
        assert!(!s.matches(ip, 32, 64));

        // A new address replaces the old one immediately.
        s.apply(0, found(&["192.0.2.10"], 60), t0, &c);
        s.apply(0, found(&["198.51.100.1"], 60), t0, &c);
        assert!(!s.matches(ip, 32, 64));
        // NXDOMAIN/NODATA clears at once.
        s.apply(0, Lookup::NotFound, t0, &c);
        assert!(!s.matches("198.51.100.1".parse().unwrap(), 32, 64));
    }
}
