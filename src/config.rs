//! Configuration file (TOML). Everything is validated up front; anything
//! ambiguous or missing is an error rather than a silent default.

use ipnet::IpNet;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub limits: Limits,
    #[serde(rename = "listen", default)]
    pub listeners: Vec<Listener>,
    #[serde(rename = "upstream", default)]
    pub upstreams: Vec<Upstream>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Concurrent UDP queries per listener; excess queries are dropped.
    pub udp_max_inflight: usize,
    /// Concurrent TCP/DoT/DoH connections per listener.
    pub tcp_max_connections: usize,
    /// Concurrent queries per TCP/DoT connection or DoH (HTTP/2) connection.
    pub tcp_max_inflight_per_conn: usize,
    pub tcp_idle_timeout_ms: u64,
    pub tls_handshake_timeout_ms: u64,
    /// Timeout of a single attempt against one upstream.
    pub upstream_timeout_ms: u64,
    /// Overall deadline for answering a query (all failover attempts).
    pub query_timeout_ms: u64,
    /// Idle connections kept per DoT upstream.
    pub dot_pool_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            udp_max_inflight: 1024,
            tcp_max_connections: 256,
            tcp_max_inflight_per_conn: 16,
            tcp_idle_timeout_ms: 10_000,
            tls_handshake_timeout_ms: 5_000,
            upstream_timeout_ms: 2_000,
            query_timeout_ms: 5_000,
            dot_pool_size: 8,
        }
    }
}

impl Limits {
    pub fn tcp_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.tcp_idle_timeout_ms)
    }
    pub fn tls_handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.tls_handshake_timeout_ms)
    }
    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_millis(self.upstream_timeout_ms)
    }
    pub fn query_timeout(&self) -> Duration {
        Duration::from_millis(self.query_timeout_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Udp,
    Tcp,
    Dot,
    Doh,
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
            Proto::Dot => "dot",
            Proto::Doh => "doh",
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub proto: Proto,
    pub addr: SocketAddr,
    /// Client networks allowed to use this listener. Mandatory.
    pub allow: Vec<IpNet>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// DoH only: request path (default `/dns-query`).
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamKind {
    Dot,
    Doh,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    #[serde(rename = "type")]
    pub kind: UpstreamKind,
    /// DoT only: TLS server name (SNI and certificate verification).
    pub name: Option<String>,
    /// DoH only: `https://host/path`.
    pub url: Option<String>,
    /// Bootstrap socket addresses. Upstream hostnames are never resolved.
    pub addrs: Vec<SocketAddr>,
    /// PEM file with trust anchors replacing the built-in Mozilla roots.
    pub ca_file: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let cfg: Config = toml::from_str(text).map_err(|e| format!("config: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        let l = &self.limits;
        for (name, v) in [
            ("udp_max_inflight", l.udp_max_inflight as u64),
            ("tcp_max_connections", l.tcp_max_connections as u64),
            ("tcp_max_inflight_per_conn", l.tcp_max_inflight_per_conn as u64),
            ("tcp_idle_timeout_ms", l.tcp_idle_timeout_ms),
            ("tls_handshake_timeout_ms", l.tls_handshake_timeout_ms),
            ("upstream_timeout_ms", l.upstream_timeout_ms),
            ("query_timeout_ms", l.query_timeout_ms),
        ] {
            if v == 0 {
                return Err(format!("limits.{name} must be > 0"));
            }
        }
        if l.tcp_max_inflight_per_conn > u32::MAX as usize {
            return Err("limits.tcp_max_inflight_per_conn too large".into());
        }

        if self.listeners.is_empty() {
            return Err("no [[listen]] configured".into());
        }
        if self.upstreams.is_empty() {
            return Err("no [[upstream]] configured".into());
        }

        for li in &self.listeners {
            let ctx = format!("listen {} {}", li.proto, li.addr);
            if li.allow.is_empty() {
                return Err(format!(
                    "{ctx}: 'allow' must not be empty (use \"0.0.0.0/0\" and \"::/0\" to deliberately run an open resolver)"
                ));
            }
            let tls = matches!(li.proto, Proto::Dot | Proto::Doh);
            if tls != (li.cert.is_some() && li.key.is_some()) || li.cert.is_some() != li.key.is_some() {
                return Err(if tls {
                    format!("{ctx}: 'cert' and 'key' are required")
                } else {
                    format!("{ctx}: 'cert'/'key' are only valid for dot/doh")
                });
            }
            match (&li.path, li.proto) {
                (Some(p), Proto::Doh) if !p.starts_with('/') || p.contains(['?', '#']) => {
                    return Err(format!("{ctx}: 'path' must start with '/' and contain no query"));
                }
                (Some(_), p) if p != Proto::Doh => {
                    return Err(format!("{ctx}: 'path' is only valid for doh"));
                }
                _ => {}
            }
        }

        for up in &self.upstreams {
            if up.addrs.is_empty() {
                return Err("upstream: 'addrs' must list at least one IP:port".into());
            }
            match up.kind {
                UpstreamKind::Dot => {
                    if up.name.is_none() || up.url.is_some() {
                        return Err("upstream dot: requires 'name' and no 'url'".into());
                    }
                }
                UpstreamKind::Doh => {
                    if up.url.is_none() || up.name.is_some() {
                        return Err("upstream doh: requires 'url' and no 'name'".into());
                    }
                }
            }
        }
        Ok(())
    }
}

/// Expands `${CREDENTIALS_DIRECTORY}` (systemd `LoadCredential=`) in a path.
/// No other variables are supported.
pub fn expand_path(p: &Path) -> Result<PathBuf, String> {
    const VAR: &str = "${CREDENTIALS_DIRECTORY}";
    let s = p
        .to_str()
        .ok_or_else(|| format!("non-UTF-8 path {}", p.display()))?;
    if !s.contains(VAR) {
        return Ok(p.to_path_buf());
    }
    let dir = std::env::var("CREDENTIALS_DIRECTORY")
        .map_err(|_| format!("{s}: CREDENTIALS_DIRECTORY is not set"))?;
    Ok(PathBuf::from(s.replace(VAR, &dir)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPSTREAM: &str = r#"
        [[upstream]]
        type = "dot"
        name = "dns.example"
        addrs = ["192.0.2.1:853"]
    "#;

    fn parse(listen: &str) -> Result<Config, String> {
        Config::parse(&format!("{listen}\n{UPSTREAM}"))
    }

    #[test]
    fn minimal_ok() {
        let c = parse(
            r#"[[listen]]
            proto = "udp"
            addr = "127.0.0.1:53"
            allow = ["127.0.0.0/8"]"#,
        )
        .unwrap();
        assert_eq!(c.listeners.len(), 1);
        assert_eq!(c.limits.udp_max_inflight, 1024);
    }

    #[test]
    fn rejects_missing_or_empty_allow() {
        assert!(parse("[[listen]]\nproto = \"udp\"\naddr = \"127.0.0.1:53\"").is_err());
        assert!(parse("[[listen]]\nproto = \"udp\"\naddr = \"127.0.0.1:53\"\nallow = []").is_err());
    }

    #[test]
    fn tls_listeners_need_cert_and_key() {
        let base = "[[listen]]\nproto = \"dot\"\naddr = \"127.0.0.1:853\"\nallow = [\"::1/128\"]\n";
        assert!(parse(base).is_err());
        assert!(parse(&format!("{base}cert = \"c\"")).is_err());
        assert!(parse(&format!("{base}cert = \"c\"\nkey = \"k\"")).is_ok());
        let udp = "[[listen]]\nproto = \"udp\"\naddr = \"127.0.0.1:53\"\nallow = [\"::1/128\"]\ncert = \"c\"\nkey = \"k\"";
        assert!(parse(udp).is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_bad_upstreams() {
        let li = "[[listen]]\nproto = \"udp\"\naddr = \"127.0.0.1:53\"\nallow = [\"::1/128\"]\n";
        assert!(Config::parse(&format!("{li}{UPSTREAM}\nbogus = 1")).is_err());
        assert!(Config::parse(li).is_err());
        let doh_without_url = "[[upstream]]\ntype = \"doh\"\naddrs = [\"192.0.2.1:443\"]";
        assert!(Config::parse(&format!("{li}{doh_without_url}")).is_err());
        let no_addrs = "[[upstream]]\ntype = \"dot\"\nname = \"x\"\naddrs = []";
        assert!(Config::parse(&format!("{li}{no_addrs}")).is_err());
        let hostname_addr = "[[upstream]]\ntype = \"dot\"\nname = \"x\"\naddrs = [\"dns.example:853\"]";
        assert!(Config::parse(&format!("{li}{hostname_addr}")).is_err());
    }

    #[test]
    fn credentials_expansion() {
        let p = Path::new("/etc/x.pem");
        assert_eq!(expand_path(p).unwrap(), p);
    }
}
