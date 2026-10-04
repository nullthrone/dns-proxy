//! Client allowlist: static networks plus hostnames whose current
//! addresses are kept up to date by [`crate::hosts`].

use crate::hosts::{HostSlot, Hosts};
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

#[derive(Clone)]
pub struct HostRule {
    slot: Arc<HostSlot>,
    v4_prefix: u8,
    v6_prefix: u8,
}

impl HostRule {
    pub fn new(slot: Arc<HostSlot>, v4_prefix: u8, v6_prefix: u8) -> Self {
        Self {
            slot,
            v4_prefix,
            v6_prefix,
        }
    }
}

#[derive(Clone)]
pub struct Acl {
    nets: Vec<IpNet>,
    hosts: Vec<HostRule>,
    /// Notified when a client is rejected and host rules exist.
    registry: Option<Arc<Hosts>>,
}

impl Acl {
    pub fn new(nets: Vec<IpNet>, hosts: Vec<HostRule>, registry: Option<Arc<Hosts>>) -> Self {
        Self {
            nets,
            hosts,
            registry,
        }
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        // IPv4-mapped IPv6 (dual-stack sockets) is matched as IPv4.
        let ip = ip.to_canonical();
        if self.nets.iter().any(|n| n.contains(&ip))
            || self
                .hosts
                .iter()
                .any(|h| h.slot.matches(ip, h.v4_prefix, h.v6_prefix))
        {
            return true;
        }
        debug!(%ip, "client not allowed");
        // The client's DynDNS name may have just moved to this address.
        if !self.hosts.is_empty() {
            if let Some(r) = &self.registry {
                r.trigger();
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let acl = Acl::new(
            vec!["127.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()],
            vec![],
            None,
        );
        assert!(acl.allows("127.0.0.1".parse().unwrap()));
        assert!(acl.allows("::ffff:127.0.0.1".parse().unwrap()));
        assert!(acl.allows("fd12::1".parse().unwrap()));
        assert!(!acl.allows("10.0.0.1".parse().unwrap()));
        assert!(!acl.allows("::1".parse().unwrap()));
        assert!(!Acl::new(vec![], vec![], None).allows("127.0.0.1".parse().unwrap()));
    }
}
