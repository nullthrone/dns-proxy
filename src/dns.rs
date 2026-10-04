//! Minimal DNS wire-format handling.
//!
//! The proxy never interprets records. It only needs to:
//! - validate that an inbound message is a sane standard query,
//! - know the question (to match responses) and the client's UDP size,
//! - rewrite message IDs,
//! - synthesise SERVFAIL and truncated (TC) replies.
//!
//! All access goes through bounds-checked helpers; malformed input yields
//! an error, never a panic.

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
const RCODE_SERVFAIL: u16 = 2;
const TYPE_OPT: u16 = 41;

#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed DNS message")
    }
}

impl std::error::Error for Malformed {}

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
    next: usize,
}

fn skip_rr(b: &[u8], off: usize) -> Result<Rr, Malformed> {
    let off = skip_name(b, off, true)?;
    let rtype = be16(b, off)?;
    let class = be16(b, off + 2)?;
    let rdlen = be16(b, off + 8)?;
    let next = checked_end(b, off + 10, usize::from(rdlen))?;
    Ok(Rr { rtype, class, next })
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
}
