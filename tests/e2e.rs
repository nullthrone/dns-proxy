//! End-to-end tests: fake DoT/DoH upstreams with a test CA, the proxy in
//! between, and clients for every inbound protocol.

use dns_proxy::config::{Config, Proto};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ---------------------------------------------------------------- PKI

struct Pki {
    dir: PathBuf,
    ca_params: CertificateParams,
    ca_key: KeyPair,
    ca_file: PathBuf,
}

impl Pki {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "dns-proxy-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_file = dir.join("ca.pem");
        std::fs::write(&ca_file, ca.pem()).unwrap();
        Self {
            dir,
            ca_params,
            ca_key,
            ca_file,
        }
    }

    /// Leaf certificate for `name`, returns (cert path, key path).
    fn leaf(&self, name: &str) -> (PathBuf, PathBuf) {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![name.to_string()]).unwrap();
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        let c = self.dir.join(format!("{name}.crt"));
        let k = self.dir.join(format!("{name}.key"));
        std::fs::write(&c, cert.pem()).unwrap();
        std::fs::write(&k, key.serialize_pem()).unwrap();
        (c, k)
    }

    fn acceptor(&self, name: &str, alpn: &[&[u8]]) -> TlsAcceptor {
        let (c, k) = self.leaf(name);
        let certs = CertificateDer::pem_file_iter(&c)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let key = PrivateKeyDer::from_pem_file(&k).unwrap();
        let mut cfg =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsAcceptor::from(Arc::new(cfg))
    }

    fn connector(&self, alpn: &[&[u8]]) -> TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_file_iter(&self.ca_file).unwrap() {
            roots.add(c.unwrap()).unwrap();
        }
        let mut cfg =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsConnector::from(Arc::new(cfg))
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------- DNS helpers

fn query(id: u16, name: &str, edns: Option<u16>) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(edns.is_some())]);
    for l in name.split('.') {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    if let Some(size) = edns {
        m.extend_from_slice(&[0, 0, 41]);
        m.extend_from_slice(&size.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    m
}

/// Fake authoritative answer: 1.2.3.4, or 60 A records for names
/// starting with "big" (≈ 1 KB, beyond the 512-byte UDP default).
fn answer(q: &[u8]) -> Vec<u8> {
    let mut off = 12;
    while q[off] != 0 {
        off += 1 + q[off] as usize;
    }
    let qend = off + 5;
    let big = q[13..16] == *b"big";
    let n: u16 = if big { 60 } else { 1 };
    let mut r = Vec::new();
    r.extend_from_slice(&q[0..2]);
    r.extend_from_slice(&[0x81, 0x80, 0, 1]);
    r.extend_from_slice(&n.to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(&q[12..qend]);
    for i in 0..n {
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3]);
        r.push(if big { i as u8 } else { 4 });
    }
    r
}

fn rcode(r: &[u8]) -> u8 {
    r[3] & 0x0F
}

fn ancount(r: &[u8]) -> u16 {
    u16::from_be_bytes([r[6], r[7]])
}

fn assert_answer(r: &[u8], id: u16) {
    assert_eq!(u16::from_be_bytes([r[0], r[1]]), id, "client ID restored");
    assert_eq!(rcode(r), 0);
    assert_eq!(ancount(r), 1);
    assert_eq!(&r[r.len() - 4..], &[1, 2, 3, 4]);
}

// ---------------------------------------------------------------- fake upstreams

async fn fake_dot(pki: &Pki, name: &str) -> SocketAddr {
    let acc = pki.acceptor(name, &[]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let acc = acc.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acc.accept(tcp).await else { return };
                loop {
                    let Ok(len) = s.read_u16().await else { return };
                    let mut q = vec![0; len as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    let a = answer(&q);
                    let mut out = (a.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&a);
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn fake_doh(pki: &Pki, name: &str) -> SocketAddr {
    let acc = pki.acceptor(name, &[b"h2"]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let acc = acc.clone();
            tokio::spawn(async move {
                let Ok(s) = acc.accept(tcp).await else { return };
                let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    let ok = req.method() == hyper::Method::POST
                        && req.uri().path() == "/dns-query"
                        && req.headers()["content-type"] == "application/dns-message";
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    // RFC 8484: the proxy must send ID 0.
                    let mut resp = if ok && body[0..2] == [0, 0] {
                        let mut r = Response::new(Full::new(Bytes::from(answer(&body))));
                        r.headers_mut()
                            .insert("content-type", "application/dns-message".parse().unwrap());
                        r
                    } else {
                        Response::new(Full::default())
                    };
                    if !ok {
                        *resp.status_mut() = StatusCode::BAD_REQUEST;
                    }
                    Ok::<_, std::convert::Infallible>(resp)
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    addr
}

/// Accepts TCP connections and closes them at once, counting attempts.
async fn closing_upstream(count: Arc<AtomicUsize>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            drop(tcp);
        }
    });
    addr
}

async fn dead_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

// ---------------------------------------------------------------- proxy + clients

struct Running {
    _proxy: dns_proxy::Proxy,
    udp: SocketAddr,
    tcp: SocketAddr,
    dot: SocketAddr,
    doh: SocketAddr,
}

async fn start_proxy(pki: &Pki, upstreams: &str, allow: &str) -> Running {
    let (c, k) = pki.leaf("localhost");
    let (c, k) = (c.display(), k.display());
    let toml = format!(
        r#"
        [limits]
        upstream_timeout_ms = 1000
        query_timeout_ms = 3000

        [[listen]]
        proto = "udp"
        addr = "127.0.0.1:0"
        allow = [{allow}]

        [[listen]]
        proto = "tcp"
        addr = "127.0.0.1:0"
        allow = [{allow}]

        [[listen]]
        proto = "dot"
        addr = "127.0.0.1:0"
        allow = [{allow}]
        cert = "{c}"
        key = "{k}"

        [[listen]]
        proto = "doh"
        addr = "127.0.0.1:0"
        allow = [{allow}]
        cert = "{c}"
        key = "{k}"

        {upstreams}
        "#
    );
    let cfg = Config::parse(&toml).unwrap();
    let proxy = dns_proxy::start(cfg).await.unwrap();
    let get = |p: Proto| proxy.bound.iter().find(|(x, _)| *x == p).unwrap().1;
    Running {
        udp: get(Proto::Udp),
        tcp: get(Proto::Tcp),
        dot: get(Proto::Dot),
        doh: get(Proto::Doh),
        _proxy: proxy,
    }
}

fn dot_upstream(pki: &Pki, name: &str, addr: SocketAddr) -> String {
    format!(
        "[[upstream]]\ntype = \"dot\"\nname = \"{name}\"\naddrs = [\"{addr}\"]\nca_file = \"{}\"\n",
        pki.ca_file.display()
    )
}

fn doh_upstream(pki: &Pki, name: &str, addr: SocketAddr) -> String {
    format!(
        "[[upstream]]\ntype = \"doh\"\nurl = \"https://{name}/dns-query\"\naddrs = [\"{addr}\"]\nca_file = \"{}\"\n",
        pki.ca_file.display()
    )
}

const LOCAL: &str = "\"127.0.0.0/8\"";

async fn udp_query(addr: SocketAddr, msg: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(msg, addr).await.unwrap();
    let mut buf = vec![0; 65535];
    let n = timeout(wait, s.recv(&mut buf)).await.ok()?.unwrap();
    buf.truncate(n);
    Some(buf)
}

async fn framed<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, msg: &[u8]) -> Option<Vec<u8>> {
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    s.write_all(&out).await.ok()?;
    let len = timeout(Duration::from_secs(5), s.read_u16()).await.ok()?.ok()?;
    let mut buf = vec![0; len as usize];
    s.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

async fn tcp_query(addr: SocketAddr, msg: &[u8]) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect(addr).await.ok()?;
    framed(&mut s, msg).await
}

async fn dot_query(pki: &Pki, addr: SocketAddr, msg: &[u8]) -> Option<Vec<u8>> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut s = pki
        .connector(&[b"dot"])
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    framed(&mut s, msg).await
}

/// Sends one DoH request over HTTP/2; returns status and body.
async fn doh(pki: &Pki, addr: SocketAddr, req: Request<Full<Bytes>>) -> (StatusCode, Vec<u8>) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = pki
        .connector(&[b"h2"])
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = send.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, body)
}

fn post(path: &str, ct: &str, body: Vec<u8>) -> Request<Full<Bytes>> {
    Request::post(format!("https://localhost{path}"))
        .header("content-type", ct)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn get(query: &str) -> Request<Full<Bytes>> {
    Request::get(format!("https://localhost/dns-query?{query}"))
        .body(Full::default())
        .unwrap()
}

fn b64url(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

const WAIT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn all_inbound_protocols_via_dot_upstream() {
    let pki = Pki::new();
    let up = fake_dot(&pki, "upstream.test").await;
    let p = start_proxy(&pki, &dot_upstream(&pki, "upstream.test", up), LOCAL).await;

    assert_answer(
        &udp_query(p.udp, &query(0x1001, "example.com", None), WAIT)
            .await
            .unwrap(),
        0x1001,
    );
    assert_answer(
        &tcp_query(p.tcp, &query(0x1002, "example.com", None))
            .await
            .unwrap(),
        0x1002,
    );
    assert_answer(
        &dot_query(&pki, p.dot, &query(0x1003, "example.com", None))
            .await
            .unwrap(),
        0x1003,
    );
    let (st, body) = doh(
        &pki,
        p.doh,
        post(
            "/dns-query",
            "application/dns-message",
            query(0, "example.com", None),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_answer(&body, 0);
    let (st, body) = doh(
        &pki,
        p.doh,
        get(&format!("dns={}", b64url(&query(0, "example.com", None)))),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_answer(&body, 0);
}

#[tokio::test]
async fn via_doh_upstream() {
    let pki = Pki::new();
    let up = fake_doh(&pki, "upstream.test").await;
    let p = start_proxy(&pki, &doh_upstream(&pki, "upstream.test", up), LOCAL).await;
    for id in [0x2001, 0x2002, 0x2003] {
        assert_answer(
            &udp_query(p.udp, &query(id, "example.com", None), WAIT)
                .await
                .unwrap(),
            id,
        );
    }
    assert_answer(
        &dot_query(&pki, p.dot, &query(0x2004, "example.com", None))
            .await
            .unwrap(),
        0x2004,
    );
}

#[tokio::test]
async fn pipelined_tcp_queries() {
    let pki = Pki::new();
    let up = fake_dot(&pki, "upstream.test").await;
    let p = start_proxy(&pki, &dot_upstream(&pki, "upstream.test", up), LOCAL).await;
    let mut s = TcpStream::connect(p.tcp).await.unwrap();
    let mut out = Vec::new();
    for id in 1..=10u16 {
        let q = query(id, "example.com", None);
        out.extend_from_slice(&(q.len() as u16).to_be_bytes());
        out.extend_from_slice(&q);
    }
    s.write_all(&out).await.unwrap();
    let mut ids = Vec::new();
    for _ in 0..10 {
        let len = s.read_u16().await.unwrap();
        let mut buf = vec![0; len as usize];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(ancount(&buf), 1);
        ids.push(u16::from_be_bytes([buf[0], buf[1]]));
    }
    ids.sort();
    assert_eq!(ids, (1..=10).collect::<Vec<_>>());
}

#[tokio::test]
async fn failover_to_second_upstream() {
    let pki = Pki::new();
    let up = fake_dot(&pki, "upstream.test").await;
    let dead = dead_addr().await;
    let ups = dot_upstream(&pki, "upstream.test", dead) + &dot_upstream(&pki, "upstream.test", up);
    let p = start_proxy(&pki, &ups, LOCAL).await;
    assert_answer(
        &udp_query(p.udp, &query(0x3001, "example.com", None), WAIT)
            .await
            .unwrap(),
        0x3001,
    );
    // Second query skips the penalised upstream.
    assert_answer(
        &udp_query(p.udp, &query(0x3002, "example.com", None), WAIT)
            .await
            .unwrap(),
        0x3002,
    );
}

#[tokio::test]
async fn servfail_when_all_upstreams_fail() {
    let pki = Pki::new();
    let dead = dead_addr().await;
    let p = start_proxy(&pki, &doh_upstream(&pki, "upstream.test", dead), LOCAL).await;
    let r = udp_query(p.udp, &query(0x4001, "example.com", None), WAIT)
        .await
        .unwrap();
    assert_eq!(u16::from_be_bytes([r[0], r[1]]), 0x4001);
    assert_eq!(rcode(&r), 2);
}

#[tokio::test]
async fn each_upstream_tried_once_per_query() {
    let pki = Pki::new();
    let count = Arc::new(AtomicUsize::new(0));
    let a = closing_upstream(count.clone()).await;
    let b = closing_upstream(count.clone()).await;
    let ups = dot_upstream(&pki, "upstream.test", a) + &dot_upstream(&pki, "upstream.test", b);
    let p = start_proxy(&pki, &ups, LOCAL).await;
    let r = udp_query(p.udp, &query(0x4101, "example.com", None), WAIT)
        .await
        .unwrap();
    assert_eq!(rcode(&r), 2);
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn upstream_certificate_is_verified() {
    let pki = Pki::new();
    // Upstream presents a certificate for a different name.
    let up = fake_dot(&pki, "evil.test").await;
    let p = start_proxy(&pki, &dot_upstream(&pki, "upstream.test", up), LOCAL).await;
    let r = udp_query(p.udp, &query(0x5001, "example.com", None), WAIT)
        .await
        .unwrap();
    assert_eq!(rcode(&r), 2);
    // Same for a CA the proxy does not trust.
    let other = Pki::new();
    let up = fake_doh(&other, "upstream.test").await;
    let p = start_proxy(&pki, &doh_upstream(&pki, "upstream.test", up), LOCAL).await;
    let r = udp_query(p.udp, &query(0x5002, "example.com", None), WAIT)
        .await
        .unwrap();
    assert_eq!(rcode(&r), 2);
}

#[tokio::test]
async fn acl_rejects_other_clients() {
    let pki = Pki::new();
    let up = fake_dot(&pki, "upstream.test").await;
    let p = start_proxy(&pki, &dot_upstream(&pki, "upstream.test", up), "\"10.0.0.0/8\"").await;
    assert!(
        udp_query(p.udp, &query(1, "example.com", None), Duration::from_millis(500))
            .await
            .is_none()
    );
    assert!(tcp_query(p.tcp, &query(1, "example.com", None)).await.is_none());
}

#[tokio::test]
async fn udp_truncation() {
    let pki = Pki::new();
    let up = fake_dot(&pki, "upstream.test").await;
    let p = start_proxy(&pki, &dot_upstream(&pki, "upstream.test", up), LOCAL).await;

    let r = udp_query(p.udp, &query(0x6001, "big.example", None), WAIT)
        .await
        .unwrap();
    assert!(r.len() <= 512);
    assert_ne!(r[2] & 0x02, 0, "TC set");
    assert_eq!(ancount(&r), 0);

    let r = udp_query(p.udp, &query(0x6002, "big.example", Some(1232)), WAIT)
        .await
        .unwrap();
    assert_eq!(r[2] & 0x02, 0);
    assert_eq!(ancount(&r), 60);

    let r = tcp_query(p.tcp, &query(0x6003, "big.example", None))
        .await
        .unwrap();
    assert_eq!(ancount(&r), 60);
}

#[tokio::test]
async fn invalid_queries_are_dropped() {
    let pki = Pki::new();
    let up = fake_dot(&pki, "upstream.test").await;
    let p = start_proxy(&pki, &dot_upstream(&pki, "upstream.test", up), LOCAL).await;
    let mut resp = query(1, "example.com", None);
    resp[2] |= 0x80; // QR set: a response, not a query
    assert!(
        udp_query(p.udp, &resp, Duration::from_millis(500))
            .await
            .is_none()
    );
    assert!(
        udp_query(p.udp, &[0; 5], Duration::from_millis(500))
            .await
            .is_none()
    );
}

#[tokio::test]
async fn doh_request_errors() {
    let pki = Pki::new();
    let up = fake_dot(&pki, "upstream.test").await;
    let p = start_proxy(&pki, &dot_upstream(&pki, "upstream.test", up), LOCAL).await;
    let q = query(0, "example.com", None);

    let (st, _) = doh(&pki, p.doh, post("/other", "application/dns-message", q.clone())).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = doh(&pki, p.doh, post("/dns-query", "text/plain", q.clone())).await;
    assert_eq!(st, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (st, _) = doh(
        &pki,
        p.doh,
        post("/dns-query", "application/dns-message", vec![1, 2, 3]),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = doh(
        &pki,
        p.doh,
        post("/dns-query", "application/dns-message", vec![0; 70_000]),
    )
    .await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    let (st, _) = doh(&pki, p.doh, get("dns=!!!")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = doh(&pki, p.doh, get("foo=bar")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let put = Request::put("https://localhost/dns-query")
        .body(Full::default())
        .unwrap();
    let (st, _) = doh(&pki, p.doh, put).await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn doh_over_http1() {
    let pki = Pki::new();
    let up = fake_dot(&pki, "upstream.test").await;
    let p = start_proxy(&pki, &dot_upstream(&pki, "upstream.test", up), LOCAL).await;
    let tcp = TcpStream::connect(p.doh).await.unwrap();
    let tls = pki
        .connector(&[b"http/1.1"])
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::post("/dns-query")
        .header("host", "localhost")
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(query(0x7001, "example.com", None))))
        .unwrap();
    let resp = send.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_answer(&body, 0x7001);
}

#[tokio::test]
async fn check_rejects_missing_certificate() {
    let cfg = Config::parse(
        r#"
        [[listen]]
        proto = "dot"
        addr = "127.0.0.1:0"
        allow = ["127.0.0.0/8"]
        cert = "/nonexistent/cert.pem"
        key = "/nonexistent/key.pem"

        [[upstream]]
        type = "dot"
        name = "dns.example"
        addrs = ["192.0.2.1:853"]
        "#,
    )
    .unwrap();
    assert!(dns_proxy::check(&cfg).is_err());
}
