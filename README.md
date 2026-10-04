# dns-proxy

A small, no-frills DNS forwarder written in Rust.

```
clients ── plain DNS (UDP/TCP) ─┐
        ── DoT (RFC 7858) ──────┼──► dns-proxy ──► DoT / DoH upstreams (failover)
        ── DoH (RFC 8484) ──────┘
```

- **Inbound:** plain DNS over UDP and TCP, DNS over TLS, DNS over HTTPS (HTTP/1.1 and HTTP/2, GET and POST).
- **Outbound:** encrypted only (DoT or DoH). Upstreams are tried in order. One that fails is deprioritised for 30 s.
- **Not included:** no cache, no filtering, no ACME, no HTTP/3, no DNSSEC validation, no statistics endpoint.

## Security properties

- **Closed by default.** Every listener requires an explicit `allow` CIDR list. An open resolver needs a deliberate `"0.0.0.0/0"` / `"::/0"`.
- **No plain-DNS bootstrap.** Upstream hostnames are never resolved. You configure their IPs (`addrs`). The hostname is used only for SNI and certificate verification, so nothing goes in circles and nothing leaks.
- **Verified TLS.** Uses rustls (ring provider, TLS 1.2/1.3, AEAD suites only). Upstream certificates are verified against the built-in Mozilla roots (`webpki-roots`) or a `ca_file` you supply.
- **Validated responses.** Upstream responses must match the query's question and ID.
  - DoT queries get a fresh random ID, so the client's ID never leaves the host.
  - DoH uses ID 0, as RFC 8484 recommends.
- **UDP limits.** UDP responses are capped at the client's EDNS0 size, with an upper bound of 1232 bytes. Larger answers come back truncated (TC), and the client retries over TCP. This also limits amplification.
- **Malformed input is dropped.** Invalid queries are dropped without a reply over UDP and close the connection over TCP/DoT. Over DoH they get HTTP 400.
- **Bounded resources.**
  - Concurrent UDP queries, connections, and queries per connection are all capped.
  - Handshake, idle, header, and body timeouts apply, so slow clients can't hold slots.
  - Message size is capped at 65535 bytes.
- **Private logs.** Query names are never logged.
- `#![forbid(unsafe_code)]`. The DNS wire handling is a small, bounds-checked parser with tests, including a random-input test that checks it never panics.

## Build

```sh
cargo build --release --locked
install -m 0755 target/release/dns-proxy /usr/local/bin/
```

## Configure

```sh
install -d /etc/dns-proxy
install -m 0644 config.example.toml /etc/dns-proxy/config.toml
dns-proxy --config /etc/dns-proxy/config.toml --check
```

See [`config.example.toml`](config.example.toml) for all options. Summary:

| Section | Keys |
|---|---|
| `[[listen]]` | `proto` (`udp` \| `tcp` \| `dot` \| `doh`), `addr`, `allow`. For `dot`/`doh` also `cert`, `key`; for `doh` optionally `path` (default `/dns-query`). |
| `[[upstream]]` | `type = "dot"`: `name`, `addrs`. `type = "doh"`: `url`, `addrs`. Optional `ca_file`. |
| `[limits]` | Concurrency limits and timeouts (all optional). |

Notes:

- **Listening on IPv6.** Whether `[::]:53` also accepts IPv4 depends on `net.ipv6.bindv6only`. Configure separate IPv4 and IPv6 listeners to be explicit.
- **Certificate paths.** In certificate paths, `${CREDENTIALS_DIRECTORY}` is expanded (systemd `LoadCredential=`). No other variables are.
- **Logging.** Set the log level with `RUST_LOG` (default `info`), e.g. `RUST_LOG=debug`.

## Run with systemd

[`dist/dns-proxy.service`](dist/dns-proxy.service) runs the proxy as a transient unprivileged user (`DynamicUser=`). Its only capability is `CAP_NET_BIND_SERVICE`. It also enables a strict sandbox: read-only filesystem, a syscall filter, no new privileges, and more.

```sh
install -m 0644 dist/dns-proxy.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dns-proxy
systemd-analyze security dns-proxy
```

For DoT/DoH listeners:

1. Uncomment the `LoadCredential=` lines in the unit.
2. Point `cert`/`key` at `${CREDENTIALS_DIRECTORY}/cert.pem` and `${CREDENTIALS_DIRECTORY}/key.pem`.

The private key can stay readable by root only, because systemd hands the service a private copy. Since that copy is made at start, restart the service after a certificate renewal. With certbot, for example:

```sh
certbot renew --deploy-hook "systemctl restart dns-proxy"
```

## Test

```sh
cargo test
```

The end-to-end tests start fake DoT and DoH upstreams with a throwaway CA and query the proxy over all four inbound protocols. They cover:

- failover, and SERVFAIL when every upstream fails
- certificate verification
- the allowlist
- UDP truncation
- TCP pipelining
- DoH error handling

## License

MIT
