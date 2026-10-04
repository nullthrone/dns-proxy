//! Client allowlist.

use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Acl(Vec<IpNet>);

impl Acl {
    pub fn new(nets: Vec<IpNet>) -> Self {
        Self(nets)
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        // IPv4-mapped IPv6 (dual-stack sockets) is matched as IPv4.
        let ip = ip.to_canonical();
        self.0.iter().any(|n| n.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let acl = Acl::new(vec!["127.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()]);
        assert!(acl.allows("127.0.0.1".parse().unwrap()));
        assert!(acl.allows("::ffff:127.0.0.1".parse().unwrap()));
        assert!(acl.allows("fd12::1".parse().unwrap()));
        assert!(!acl.allows("10.0.0.1".parse().unwrap()));
        assert!(!acl.allows("::1".parse().unwrap()));
        assert!(!Acl::new(vec![]).allows("127.0.0.1".parse().unwrap()));
    }
}
