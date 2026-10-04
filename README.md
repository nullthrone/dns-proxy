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

- **Closed by default.** Every listener requires an explicit `allow` CIDR list and/or `allow_hosts` hostnames. An open resolver needs a deliberate `"0.0.0.0/0"` / `"::/0"`.
- **No plain-DNS bootstrap.** Upstream hostnames are never resolved. You configure their IPs (`addrs`). The hostname is used only for SNI and certificate verification, so nothing goes in circles and nothing leaks.
- **No system resolver.** `allow_hosts` names are resolved through the encrypted upstreams, in the background. The packet path only reads addresses that are already known.
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
| `[[listen]]` | `proto` (`udp` \| `tcp` \| `dot` \| `doh`), `addr`, `allow` and/or `allow_hosts`. For `dot`/`doh` also `cert`, `key`; for `doh` optionally `path` (default `/dns-query`). |
| `[[upstream]]` | `type = "dot"`: `name`, `addrs`. `type = "doh"`: `url`, `addrs`. Optional `ca_file`. |
| `[limits]` | Concurrency limits and timeouts (all optional). |
| `[host_acl]` | Refresh timing for `allow_hosts` (all optional). |

Notes:

- **Listening on IPv6.** Whether `[::]:53` also accepts IPv4 depends on `net.ipv6.bindv6only`. Configure separate IPv4 and IPv6 listeners to be explicit.
- **Certificate paths.** In certificate paths, `${CREDENTIALS_DIRECTORY}` is expanded (systemd `LoadCredential=`). No other variables are.
- **Logging.** Set the log level with `RUST_LOG` (default `info`), e.g. `RUST_LOG=debug`.

## Dynamic client IPs

A typical deployment: clients on networks with a dynamic public IP (home, branch office) use the proxy over the internet. The upstreams then see only the proxy's static IP, which they may use for policy (filtering profiles, allowlists, logging).

There are two ways to admit such clients.

### `allow_hosts`: admission by DynDNS name

```toml
allow_hosts = ["home.dyndns.example", { name = "office.dyndns.example", v6_prefix = 56 }]
```

How resolution works:

- **Background refresh.** Names are resolved through the configured upstreams, with an A and an AAAA query each.
- **Refresh interval.** It follows the record TTL, clamped to `[host_acl] refresh_min_ms`/`refresh_max_ms`.
- **Refresh on reject.** A rejected client triggers an early refresh, at most every `trigger_min_interval_ms`. This shortens the window after an IP change.
- **Fail closed.** Until the first successful lookup, a name admits nobody.
- **Answers replace state.** A new address replaces the old one immediately. NXDOMAIN or an empty answer removes the addresses at once.
- **Lookup failures.** If lookups fail (SERVFAIL, timeouts), the last known addresses stay valid for `max_stale_ms` (default 1 h).
- **Prefixes.** IPv4 addresses match exactly by default (`v4_prefix = 32`). IPv6 addresses match their /64 (`v6_prefix = 64`).

What you are trusting:

- **The DynDNS account is now the credential.** Whoever can update the record can admit any address. Protect the account (strong password, 2FA, a per-host update token).
- **CGNAT / DS-Lite:** if the client's public IPv4 is shared, you admit everyone behind it. Don't use `allow_hosts` for such connections, or only for their IPv6.
- **IPv6:** the AAAA record must lie in the prefix the clients use. Many routers publish their WAN address instead, which may sit in a different /64 than the LAN. Check before relying on it, and widen `v6_prefix` (e.g. 56) only as far as your delegated prefix.
- **Timing:** after an IP change, the client is rejected until the DynDNS record is updated and the proxy has refreshed. Meanwhile, the old address stays admitted until the next refresh. It may already belong to someone else.
- **Integrity:** the proxy does not validate DNSSEC. It relies on the upstream resolver, which it reaches over authenticated TLS. Upstreams such as Quad9 and Cloudflare validate DNSSEC, which protects signed DynDNS zones.
- **Use DoT/DoH for such listeners.** On plain UDP, an attacker can spoof the admitted address and reflect responses to it. Plain DNS across the internet is also readable by every network in between, which defeats the purpose of encrypted upstreams. The proxy logs a warning at startup for `allow_hosts` on `udp`/`tcp` listeners.

### Secret DoH path: admission by token

IP-based admission is weak authentication. If the clients speak DoH (browsers, Apple/Android profiles, many routers), a secret path works regardless of the client's address:

```toml
[[listen]]
proto = "doh"
addr = "0.0.0.0:443"
allow = ["0.0.0.0/0", "::/0"]
cert = "${CREDENTIALS_DIRECTORY}/cert.pem"
key = "${CREDENTIALS_DIRECTORY}/key.pem"
path = "/dns-query/<random token, e.g. openssl rand -hex 16>"
```

How the token is protected:

- **In transit:** the path travels inside TLS.
- **On the server:** the proxy compares it in constant time and does not log it.
- **Wrong token:** a request with a wrong path gets a plain 404.
- **Its weak spot:** the client configuration. Treat it like a password.

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
- the allowlist, including `allow_hosts`: address changes, refresh on reject, stale handling and NXDOMAIN
- the secret DoH path
- UDP truncation
- TCP pipelining
- DoH error handling

## License

MIT
