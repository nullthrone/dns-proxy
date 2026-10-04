//! Minimal DNS proxy: plain DNS (UDP/TCP), DoT and DoH in; DoT and DoH out.

#![forbid(unsafe_code)]

mod acl;
pub mod config;
mod dns;
mod frame;
mod hosts;
mod server;
mod tls;
mod upstream;

use acl::{Acl, HostRule};
use config::{Config, Proto};
use hosts::Hosts;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use upstream::Resolver;

/// Running proxy. Dropping it stops all listeners.
pub struct Proxy {
    /// Bound address per listener, in configuration order.
    pub bound: Vec<(Proto, SocketAddr)>,
    tasks: JoinSet<()>,
}

impl Proxy {
    /// Waits until a listener task ends (which only happens on panic).
    pub async fn join(mut self) {
        self.tasks.join_next().await;
    }
}

struct Prepared {
    proto: Proto,
    addr: SocketAddr,
    acl: Acl,
    tls: Option<TlsAcceptor>,
    path: String,
    has_hosts: bool,
}

struct Plan {
    resolver: Arc<Resolver>,
    hosts: Option<Arc<Hosts>>,
    listeners: Vec<Prepared>,
}

/// Validates everything that can fail without binding sockets: upstream
/// URLs/names, CA files, listener certificates and keys.
fn prepare(cfg: &Config) -> Result<Plan, String> {
    let resolver = Arc::new(Resolver::new(&cfg.upstreams, &cfg.limits)?);

    // One registry for all allowlist hostnames, shared by the listeners.
    let mut names = Vec::new();
    for li in &cfg.listeners {
        for h in &li.allow_hosts {
            names.push(h.normalized()?);
        }
    }
    let hosts = if names.is_empty() {
        None
    } else {
        Some(Arc::new(Hosts::new(names, &cfg.host_acl)?))
    };

    let mut out = Vec::with_capacity(cfg.listeners.len());
    for li in &cfg.listeners {
        let mut rules = Vec::with_capacity(li.allow_hosts.len());
        if let Some(hosts) = &hosts {
            for h in &li.allow_hosts {
                let slot = hosts
                    .slot(&h.normalized()?)
                    .ok_or("allow_hosts: missing host slot")?;
                rules.push(HostRule::new(slot, h.v4_prefix(), h.v6_prefix()));
            }
        }
        let tls = match (li.proto, &li.cert, &li.key) {
            (Proto::Dot | Proto::Doh, Some(cert), Some(key)) => {
                let alpn: &[&[u8]] = if li.proto == Proto::Dot {
                    &[b"dot"]
                } else {
                    &[b"h2", b"http/1.1"]
                };
                let sc = tls::server_config(&config::expand_path(cert)?, &config::expand_path(key)?, alpn)?;
                Some(TlsAcceptor::from(sc))
            }
            _ => None,
        };
        out.push(Prepared {
            proto: li.proto,
            addr: li.addr,
            acl: Acl::new(li.allow.clone(), rules, hosts.clone()),
            tls,
            path: li.path.clone().unwrap_or_else(|| "/dns-query".into()),
            has_hosts: !li.allow_hosts.is_empty(),
        });
    }
    Ok(Plan {
        resolver,
        hosts,
        listeners: out,
    })
}

/// Checks the configuration including certificates, without binding.
pub fn check(cfg: &Config) -> Result<(), String> {
    prepare(cfg).map(|_| ())
}

/// Binds all listeners and starts serving.
pub async fn start(cfg: Config) -> Result<Proxy, String> {
    let Plan {
        resolver,
        hosts,
        listeners,
    } = prepare(&cfg)?;
    let limits = &cfg.limits;
    let mut tasks = JoinSet::new();
    let mut bound = Vec::with_capacity(listeners.len());

    if let Some(hosts) = hosts {
        tasks.spawn(hosts.run(resolver.clone()));
    }

    for l in listeners {
        if l.has_hosts && matches!(l.proto, Proto::Udp | Proto::Tcp) {
            warn!(
                proto = %l.proto,
                addr = %l.addr,
                "allow_hosts on a plain DNS listener: traffic is unencrypted{}; prefer dot/doh",
                if l.proto == Proto::Udp { " and source addresses can be spoofed" } else { "" }
            );
        }
        let bind_err = |e: std::io::Error| format!("bind {} {}: {e}", l.proto, l.addr);
        if l.proto == Proto::Udp {
            let sock = UdpSocket::bind(l.addr).await.map_err(bind_err)?;
            let local = sock.local_addr().map_err(bind_err)?;
            info!(proto = %l.proto, addr = %local, "listening");
            bound.push((l.proto, local));
            tasks.spawn(server::udp::serve(
                sock,
                l.acl,
                resolver.clone(),
                limits.udp_max_inflight,
            ));
            continue;
        }

        let listener = TcpListener::bind(l.addr).await.map_err(bind_err)?;
        let local = listener.local_addr().map_err(bind_err)?;
        info!(proto = %l.proto, addr = %local, "listening");
        bound.push((l.proto, local));
        let hs_timeout = limits.tls_handshake_timeout();
        let max_conns = limits.tcp_max_connections;

        match l.proto {
            Proto::Tcp | Proto::Dot => {
                let params = Arc::new(server::stream::Params {
                    resolver: resolver.clone(),
                    idle: limits.tcp_idle_timeout(),
                    max_inflight: limits.tcp_max_inflight_per_conn,
                });
                let tls = l.tls;
                tasks.spawn(server::accept_loop(
                    listener,
                    l.acl,
                    max_conns,
                    move |tcp, peer, permit| {
                        let params = params.clone();
                        let tls = tls.clone();
                        async move {
                            let _permit = permit;
                            match tls {
                                None => server::stream::handle(tcp, params).await,
                                Some(acc) => match timeout(hs_timeout, acc.accept(tcp)).await {
                                    Ok(Ok(s)) => server::stream::handle(s, params).await,
                                    _ => debug!(%peer, "dot handshake failed"),
                                },
                            }
                        }
                    },
                ));
            }
            Proto::Doh => {
                let params = Arc::new(server::doh::Params {
                    resolver: resolver.clone(),
                    path: l.path,
                    idle: limits.tcp_idle_timeout(),
                    max_inflight: limits.tcp_max_inflight_per_conn,
                });
                let Some(acc) = l.tls else {
                    return Err("doh listener without TLS".into());
                };
                tasks.spawn(server::accept_loop(
                    listener,
                    l.acl,
                    max_conns,
                    move |tcp, peer, permit| {
                        let params = params.clone();
                        let acc = acc.clone();
                        async move {
                            let _permit = permit;
                            match timeout(hs_timeout, acc.accept(tcp)).await {
                                Ok(Ok(s)) => server::doh::handle(s, params).await,
                                _ => debug!(%peer, "doh handshake failed"),
                            }
                        }
                    },
                ));
            }
            Proto::Udp => unreachable!(),
        }
    }
    Ok(Proxy { bound, tasks })
}
