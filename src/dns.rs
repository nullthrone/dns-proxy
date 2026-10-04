//! Minimal DNS wire-format handling.
//!
//! The proxy does not interpret forwarded records. It only needs to:
//! - validate that an inbound message is a sane standard query,
//! - know the question (to match responses) and the client's UDP size,
//! - rewrite message IDs,
//! - synthesise SERVFAIL and truncated (TC) replies,
//! - build A/AAAA queries for allowlist hostnames and read the addresses
//!   from their answers.
//!
//! All access goes through bounds-checked helpers; malformed input yields
//! an error, never a panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const HEADER_LEN: usize = 12;
pub const MAX_MSG: usize = 65535;
/// Classic DNS UDP limit for clients without EDNS0.
const MIN_UDP_PAYLOAD: usize = 512;
/// Upper bound for UDP responses regardless of what the client advertises
/// (DNS Flag Day 2020: avoid IP fragmentation).
const MAX_UDP_PAYLOAD: usize = 1232;
const MAX_NAME_LEN: usize = 255;

const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const OPCODE_MASK: u16 = 0x7800;
const RCODE_MASK: u16 = 0x000F;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;
const TYPE_OPT: u16 = 41;
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// Maximum length of a hostname in presentation format.
const MAX_HOSTNAME_LEN: usize = 253;

#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed DNS message")
    }
}

impl std::error::Error for Malformed {}

/// Result of an address lookup (A or AAAA) for an allowlist hostname.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Addresses of the queried type and the smallest TTL in the answer.
    Found { addrs: Vec<IpAddr>, ttl: u32 },
    /// Definitive: NXDOMAIN, or NOERROR without addresses (NODATA).
    NotFound,
    /// SERVFAIL, REFUSED, truncated or malformed: nothing is known.
    Failed,
}

/// A validated standard query.
#[derive(Debug, Clone)]
pub struct Query {
    msg: Vec<u8>,
    /// End offset of the question section within `msg`.
    qend: usize,
    pub id: u16,
    /// Largest UDP response the client accepts.
    pub udp_size: usize,
}

impl Query {
    pub fn parse(msg: &[u8]) -> Result<Self, Malformed> {
        if msg.len() < HEADER_LEN || msg.len() > MAX_MSG {
            return Err(Malformed);
        }
        let id = be16(msg, 0)?;
        let flags = be16(msg, 2)?;
        if flags & FLAG_QR != 0 || flags & OPCODE_MASK != 0 {
            return Err(Malformed);
        }
        if be16(msg, 4)? != 1 {
            return Err(Malformed);
        }
        let ancount = be16(msg, 6)?;
        let nscount = be16(msg, 8)?;
        let arcount = be16(msg, 10)?;

        let mut off = skip_name(msg, HEADER_LEN, false)?;
        off = checked_end(msg, off, 4)?; // QTYPE + QCLASS
        let qend = off;

        for _ in 0..(u32::from(ancount) + u32::from(nscount)) {
            off = skip_rr(msg, off)?.next;
        }
        let mut udp_size = MIN_UDP_PAYLOAD;
        let mut seen_opt = false;
        for _ in 0..arcount {
            let rr = skip_rr(msg, off)?;
            if rr.rtype == TYPE_OPT {
                if seen_opt {
                    return Err(Malformed);
                }
                seen_opt = true;
                udp_size = usize::from(rr.class).clamp(MIN_UDP_PAYLOAD, MAX_UDP_PAYLOAD);
            }
            off = rr.next;
        }

        Ok(Self {
            msg: msg.to_vec(),
            qend,
            id,
            udp_size,
        })
    }

    /// Builds a recursive query for `name` (wire format, see
    /// [`encode_name`]) and `qtype`, class IN.
    pub fn build(name: &[u8], qtype: u16) -> Result<Self, Malformed> {
        let mut m = Vec::with_capacity(HEADER_LEN + name.len() + 4);
        m.extend_from_slice(&[0, 0]);
        m.extend_from_slice(&FLAG_RD.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        m.extend_from_slice(name);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        Self::parse(&m)
    }

    /// Extracts the addresses answering this (A or AAAA) query from `resp`,
    /// which must already have passed [`Query::is_answered_by`].
    ///
    /// Owner names are not matched against the CNAME chain: the response
    /// comes from an authenticated (TLS) upstream resolver, which only puts
    /// records relevant to the question into the answer section.
    pub fn addresses(&self, resp: &[u8]) -> Lookup {
        self.addresses_inner(resp).unwrap_or(Lookup::Failed)
    }

    fn addresses_inner(&self, resp: &[u8]) -> Result<Lookup, Malformed> {
        let flags = be16(resp, 2)?;
        if flags & FLAG_TC != 0 {
            return Ok(Lookup::Failed);
        }
        match flags & RCODE_MASK {
            0 => {}
            RCODE_NXDOMAIN => return Ok(Lookup::NotFound),
            _ => return Ok(Lookup::Failed),
        }
        let qtype = be16(&self.msg, self.qend.checked_sub(4).ok_or(Malformed)?)?;
        let ancount = be16(resp, 6)?;
        let mut off = checked_end(resp, HEADER_LEN, self.question().len())?;
        let mut addrs = Vec::new();
        let mut ttl = u32::MAX;
        for _ in 0..ancount {
            let rr = skip_rr(resp, off)?;
            ttl = ttl.min(rr.ttl);
            if rr.class == CLASS_IN && rr.rtype == qtype {
                let rdata = resp.get(rr.rdata..rr.next).ok_or(Malformed)?;
                let addr = match qtype {
                    TYPE_A => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(rdata).map_err(|_| Malformed)?)),
                    TYPE_AAAA => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(rdata).map_err(|_| Malformed)?,
                    )),
                    _ => return Err(Malformed),
                };
                addrs.push(addr);
            }
            off = rr.next;
        }
        Ok(if addrs.is_empty() {
            Lookup::NotFound
        } else {
            Lookup::Found { addrs, ttl }
        })
    }

    /// The raw question section (QNAME, QTYPE, QCLASS).
    pub fn question(&self) -> &[u8] {
        self.msg.get(HEADER_LEN..self.qend).unwrap_or_default()
    }

    /// The query with its ID replaced, ready to be sent upstream.
    pub fn with_id(&self, id: u16) -> Vec<u8> {
        let mut m = self.msg.clone();
        set_id(&mut m, id);
        m
    }

    fn rd(&self) -> u16 {
        be16(&self.msg, 2).unwrap_or(0) & FLAG_RD
    }

    fn reply(&self, flags: u16) -> Vec<u8> {
        let q = self.question();
        let mut out = Vec::with_capacity(HEADER_LEN + q.len());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&(FLAG_QR | FLAG_RA | self.rd() | flags).to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(q);
        out
    }

    pub fn servfail(&self) -> Vec<u8> {
        self.reply(RCODE_SERVFAIL)
    }

    pub fn truncated(&self) -> Vec<u8> {
        self.reply(FLAG_TC)
    }

    /// Whether `resp` is a plausible answer to this query: a response
    /// header, standard opcode, and an identical question (name compared
    /// case-insensitively). The ID is checked by the caller.
    pub fn is_answered_by(&self, resp: &[u8]) -> bool {
        let Ok(flags) = be16(resp, 2) else {
            return false;
        };
        if flags & FLAG_QR == 0 || flags & OPCODE_MASK != 0 || be16(resp, 4) != Ok(1) {
            return false;
        }
        let q = self.question();
        let Some(rq) = resp.get(HEADER_LEN..HEADER_LEN + q.len()) else {
            return false;
        };
        // Name compared case-insensitively; label length bytes are < 64 and
        // thus unaffected. QTYPE/QCLASS (last 4 bytes) compared exactly.
        let split = q.len().saturating_sub(4);
        q[..split].eq_ignore_ascii_case(&rq[..split]) && q[split..] == rq[split..]
    }
}

/// Encodes a hostname (letters, digits, hyphens; optional trailing dot)
/// into lowercase wire format. IP address literals are rejected: the last
/// label must not be purely numeric.
pub fn encode_name(name: &str) -> Result<Vec<u8>, Malformed> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_HOSTNAME_LEN {
        return Err(Malformed);
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    let mut last_numeric = false;
    for label in name.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-');
        if !valid {
            return Err(Malformed);
        }
        last_numeric = label.bytes().all(|c| c.is_ascii_digit());
        out.push(label.len() as u8);
        out.extend(label.bytes().map(|c| c.to_ascii_lowercase()));
    }
    if last_numeric {
        return Err(Malformed);
    }
    out.push(0);
    Ok(out)
}

pub fn id(msg: &[u8]) -> Option<u16> {
    be16(msg, 0).ok()
}

pub fn set_id(msg: &mut [u8], id: u16) {
    if let Some(h) = msg.get_mut(0..2) {
        h.copy_from_slice(&id.to_be_bytes());
    }
}

fn be16(b: &[u8], off: usize) -> Result<u16, Malformed> {
    let end = off.checked_add(2).ok_or(Malformed)?;
    let s: [u8; 2] = b
        .get(off..end)
        .ok_or(Malformed)?
        .try_into()
        .map_err(|_| Malformed)?;
    Ok(u16::from_be_bytes(s))
}

fn be32(b: &[u8], off: usize) -> Result<u32, Malformed> {
    let end = off.checked_add(4).ok_or(Malformed)?;
    let s: [u8; 4] = b
        .get(off..end)
        .ok_or(Malformed)?
        .try_into()
        .map_err(|_| Malformed)?;
    Ok(u32::from_be_bytes(s))
}

/// Returns `off + n` if that many bytes are available.
fn checked_end(b: &[u8], off: usize, n: usize) -> Result<usize, Malformed> {
    let end = off.checked_add(n).ok_or(Malformed)?;
    if end > b.len() {
        return Err(Malformed);
    }
    Ok(end)
}

/// Skips a domain name starting at `off`, returning the offset after it.
/// Compression pointers are not followed (only skipped) and are rejected
/// entirely when `allow_ptr` is false.
fn skip_name(b: &[u8], mut off: usize, allow_ptr: bool) -> Result<usize, Malformed> {
    let mut name_len = 0usize;
    loop {
        let len = *b.get(off).ok_or(Malformed)?;
        match len & 0xC0 {
            0x00 => {
                let len = usize::from(len);
                name_len += len + 1;
                if name_len > MAX_NAME_LEN {
                    return Err(Malformed);
                }
                off = checked_end(b, off, 1 + len)?;
                if len == 0 {
                    return Ok(off);
                }
            }
            0xC0 if allow_ptr => return checked_end(b, off, 2),
            _ => return Err(Malformed),
        }
    }
}

struct Rr {
    rtype: u16,
    class: u16,
    ttl: u32,
    /// Offset of the RDATA.
    rdata: usize,
    /// Offset after the record.
    next: usize,
}

fn skip_rr(b: &[u8], off: usize) -> Result<Rr, Malformed> {
    let off = skip_name(b, off, true)?;
    let rtype = be16(b, off)?;
    let class = be16(b, off + 2)?;
    let ttl = be32(b, off + 4)?;
    // RFC 2181 8: a TTL with the most significant bit set is treated as 0.
    let ttl = if ttl > i32::MAX as u32 { 0 } else { ttl };
    let rdlen = be16(b, off + 8)?;
    let rdata = off + 10;
    let next = checked_end(b, rdata, usize::from(rdlen))?;
    Ok(Rr {
        rtype,
        class,
        ttl,
        rdata,
        next,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a query for `name` (dotted) with type A, optionally with an
    /// EDNS0 OPT record advertising `edns`.
    pub fn build_query(id: u16, name: &str, edns: Option<u16>) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&FLAG_RD.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, u8::from(edns.is_some())]);
        for label in name.split('.').filter(|l| !l.is_empty()) {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        if let Some(size) = edns {
            m.push(0);
            m.extend_from_slice(&TYPE_OPT.to_be_bytes());
            m.extend_from_slice(&size.to_be_bytes());
            m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
        m
    }

    #[test]
    fn parses_simple_query() {
        let q = Query::parse(&build_query(0x1234, "example.com", None)).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.udp_size, 512);
        assert_eq!(q.question().len(), 13 + 4);
    }

    #[test]
    fn edns_size_is_clamped() {
        let q = Query::parse(&build_query(1, "a.b", Some(4096))).unwrap();
        assert_eq!(q.udp_size, MAX_UDP_PAYLOAD);
        let q = Query::parse(&build_query(1, "a.b", Some(100))).unwrap();
        assert_eq!(q.udp_size, MIN_UDP_PAYLOAD);
        let q = Query::parse(&build_query(1, "a.b", Some(1000))).unwrap();
        assert_eq!(q.udp_size, 1000);
    }

    #[test]
    fn root_query() {
        let q = Query::parse(&build_query(1, "", None)).unwrap();
        assert_eq!(q.question(), &[0, 0, 1, 0, 1]);
    }

    #[test]
    fn rejects_bad_queries() {
        let good = build_query(1, "example.com", None);
        // Too short.
        assert!(Query::parse(&good[..11]).is_err());
        // Truncated question.
        assert!(Query::parse(&good[..good.len() - 1]).is_err());
        // QR set.
        let mut m = good.clone();
        m[2] |= 0x80;
        assert!(Query::parse(&m).is_err());
        // Non-zero opcode.
        let mut m = good.clone();
        m[2] |= 0x08;
        assert!(Query::parse(&m).is_err());
        // QDCOUNT = 2.
        let mut m = good.clone();
        m[5] = 2;
        assert!(Query::parse(&m).is_err());
        // Compression pointer in question.
        let mut m = good[..HEADER_LEN].to_vec();
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        assert!(Query::parse(&m).is_err());
        // Reserved label type.
        let mut m = good[..HEADER_LEN].to_vec();
        m.extend_from_slice(&[0x40, 0, 0, 1, 0, 1]);
        assert!(Query::parse(&m).is_err());
        // ARCOUNT claims a record that is not there.
        let mut m = good.clone();
        m[11] = 1;
        assert!(Query::parse(&m).is_err());
        // Two OPT records.
        let mut m = build_query(1, "a", Some(1232));
        let opt = m[m.len() - 11..].to_vec();
        m.extend_from_slice(&opt);
        m[11] = 2;
        assert!(Query::parse(&m).is_err());
    }

    #[test]
    fn rejects_overlong_name() {
        let label = "a".repeat(63);
        let name = [label.as_str(); 4].join(".");
        assert!(Query::parse(&build_query(1, &name, None)).is_err());
        let name = [label.as_str(); 3].join(".");
        assert!(Query::parse(&build_query(1, &name, None)).is_ok());
    }

    #[test]
    fn synthesised_replies() {
        let q = Query::parse(&build_query(0xBEEF, "example.com", Some(1232))).unwrap();
        let sf = q.servfail();
        assert_eq!(id(&sf), Some(0xBEEF));
        assert_eq!(sf[3] & 0x0F, 2);
        assert_ne!(sf[2] & 0x80, 0);
        assert!(q.is_answered_by(&sf));
        let tc = q.truncated();
        assert_ne!(tc[2] & 0x02, 0);
        assert!(q.is_answered_by(&tc));
    }

    #[test]
    fn response_matching() {
        let q = Query::parse(&build_query(7, "Example.COM", None)).unwrap();
        let other = Query::parse(&build_query(7, "example.com", None)).unwrap();
        assert!(q.is_answered_by(&other.servfail()));
        let wrong = Query::parse(&build_query(7, "example.org", None)).unwrap();
        assert!(!q.is_answered_by(&wrong.servfail()));
        // A query (QR=0) is not a response.
        assert!(!q.is_answered_by(&build_query(7, "example.com", None)));
        // Different QTYPE whose byte happens to be an ASCII letter case-pair.
        let mut r = q.servfail();
        let n = r.len();
        r[n - 3] = 0x41;
        let mut r2 = r.clone();
        r2[n - 3] = 0x61;
        let q41 = Query::parse(&{
            let mut m = build_query(7, "example.com", None);
            let n = m.len();
            m[n - 3] = 0x41;
            m
        })
        .unwrap();
        assert!(q41.is_answered_by(&r));
        assert!(!q41.is_answered_by(&r2));
        assert!(!q.is_answered_by(&[]));
    }

    #[test]
    fn id_rewrite() {
        let q = Query::parse(&build_query(0x1111, "x", None)).unwrap();
        let m = q.with_id(0);
        assert_eq!(id(&m), Some(0));
        let mut short = vec![1u8];
        set_id(&mut short, 5);
        assert_eq!(short, vec![1u8]);
    }

    #[test]
    fn random_input_never_panics() {
        // xorshift: deterministic, no extra dependency.
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let seed = build_query(1, "example.com", Some(1232));
        for _ in 0..200_000 {
            let len = (next() % 64) as usize;
            let mut m: Vec<u8> = if next() % 2 == 0 {
                seed.clone()
            } else {
                (0..len).map(|_| next() as u8).collect()
            };
            // Mutate a few bytes of the seed-based variant.
            for _ in 0..(next() % 4) {
                if !m.is_empty() {
                    let i = (next() as usize) % m.len();
                    m[i] = next() as u8;
                }
            }
            if let Ok(q) = Query::parse(&m) {
                let _ = q.is_answered_by(&m);
                let _ = q.servfail();
            }
        }
    }

    /// Response to `q` with the given RCODE and answer records
    /// (type, TTL, RDATA), owner names compressed to the question.
    fn response(q: &Query, rcode: u8, records: &[(u16, u32, &[u8])]) -> Vec<u8> {
        let mut r = q.with_id(q.id);
        r.truncate(HEADER_LEN + q.question().len());
        r[2] |= 0x80;
        r[3] = 0x80 | rcode;
        r[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        r[10..12].copy_from_slice(&[0, 0]);
        for (t, ttl, data) in records {
            r.extend_from_slice(&[0xC0, 0x0C]);
            r.extend_from_slice(&t.to_be_bytes());
            r.extend_from_slice(&CLASS_IN.to_be_bytes());
            r.extend_from_slice(&ttl.to_be_bytes());
            r.extend_from_slice(&(data.len() as u16).to_be_bytes());
            r.extend_from_slice(data);
        }
        r
    }

    fn host_query(name: &str, qtype: u16) -> Query {
        Query::build(&encode_name(name).unwrap(), qtype).unwrap()
    }

    #[test]
    fn encode_names() {
        assert_eq!(
            encode_name("Home.Dyn.Example.").unwrap(),
            b"\x04home\x03dyn\x07example\x00"
        );
        assert!(encode_name("a-b.example").is_ok());
        assert!(encode_name(&format!("{}.example", "a".repeat(63))).is_ok());
        for bad in [
            "",
            ".",
            "a..b",
            "-a.example",
            "a-.example",
            "a_b.example",
            "a b.example",
            "1.2.3.4",
            "::1",
            "example.123",
        ] {
            assert!(encode_name(bad).is_err(), "{bad:?}");
        }
        assert!(encode_name(&format!("{}.example", "a".repeat(64))).is_err());
        let long = ["a".repeat(63).as_str(); 4].join(".");
        assert!(encode_name(&long).is_err());
    }

    #[test]
    fn built_query_is_valid() {
        let q = host_query("home.dyn.example", TYPE_AAAA);
        assert_eq!(&q.question()[q.question().len() - 4..], &[0, 28, 0, 1]);
        assert_eq!(q.with_id(0)[2] & 0x01, 0x01, "RD set");
    }

    #[test]
    fn address_extraction() {
        let q = host_query("home.dyn.example", TYPE_A);
        let r = response(
            &q,
            0,
            &[(TYPE_A, 300, &[192, 0, 2, 1]), (TYPE_A, 60, &[192, 0, 2, 2])],
        );
        assert_eq!(
            q.addresses(&r),
            Lookup::Found {
                addrs: vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
                ttl: 60
            }
        );
        // CNAME first: its TTL counts, its RDATA is ignored.
        let cname = b"\x03foo\x07example\x00";
        let r = response(&q, 0, &[(5, 30, cname), (TYPE_A, 300, &[192, 0, 2, 1])]);
        assert_eq!(
            q.addresses(&r),
            Lookup::Found {
                addrs: vec!["192.0.2.1".parse().unwrap()],
                ttl: 30
            }
        );
        // TTL with the high bit set counts as 0.
        let r = response(&q, 0, &[(TYPE_A, 0x8000_0000, &[192, 0, 2, 1])]);
        assert!(matches!(q.addresses(&r), Lookup::Found { ttl: 0, .. }));

        let q6 = host_query("home.dyn.example", TYPE_AAAA);
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let r = response(&q6, 0, &[(TYPE_AAAA, 60, &v6.octets())]);
        assert_eq!(
            q6.addresses(&r),
            Lookup::Found {
                addrs: vec![IpAddr::V6(v6)],
                ttl: 60
            }
        );
    }

    #[test]
    fn address_extraction_negative() {
        let q = host_query("home.dyn.example", TYPE_A);
        assert_eq!(q.addresses(&response(&q, 3, &[])), Lookup::NotFound);
        assert_eq!(q.addresses(&response(&q, 0, &[])), Lookup::NotFound);
        let cname_only = response(&q, 0, &[(5, 30, b"\x03foo\x00")]);
        assert_eq!(q.addresses(&cname_only), Lookup::NotFound);
        assert_eq!(q.addresses(&response(&q, 2, &[])), Lookup::Failed);
        assert_eq!(q.addresses(&response(&q, 5, &[])), Lookup::Failed);
        // Wrong RDATA length for A.
        let r = response(&q, 0, &[(TYPE_A, 60, &[1, 2, 3])]);
        assert_eq!(q.addresses(&r), Lookup::Failed);
        // Truncated.
        let mut r = response(&q, 0, &[(TYPE_A, 60, &[1, 2, 3, 4])]);
        r[2] |= 0x02;
        assert_eq!(q.addresses(&r), Lookup::Failed);
        // Record cut off.
        let r = response(&q, 0, &[(TYPE_A, 60, &[1, 2, 3, 4])]);
        assert_eq!(q.addresses(&r[..r.len() - 1]), Lookup::Failed);
        assert_eq!(q.addresses(&[]), Lookup::Failed);
    }

    #[test]
    fn random_responses_never_panic() {
        let mut s: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let q = host_query("home.dyn.example", TYPE_A);
        let seed = response(&q, 0, &[(5, 30, b"\x03foo\x00"), (TYPE_A, 60, &[192, 0, 2, 1])]);
        for _ in 0..200_000 {
            let mut m = seed.clone();
            m.truncate((next() as usize) % (seed.len() + 1));
            for _ in 0..(next() % 4) {
                if !m.is_empty() {
                    let i = (next() as usize) % m.len();
                    m[i] = next() as u8;
                }
            }
            let _ = q.addresses(&m);
        }
    }
}
