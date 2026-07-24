//! DNS response snooping and a destination-IP → hostname cache.
//!
//! Ported from ProxyBridge's `snoop_dns_response` / `dns_parse_name` and the
//! `g_dns_cache` hash table. We passively parse inbound DNS responses (UDP
//! source port 53), extract every `A` / `AAAA` answer, and remember
//! `ip → qname` so domain-based rules can match a destination IP back to the
//! hostname the process resolved.
//!
//! Limitation (same as the C original): only plaintext DNS is visible.
//! DNS-over-HTTPS / DNS-over-TLS bypass this entirely.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Default time-to-live for a cached hostname (matches ProxyBridge's
/// `DNS_CACHE_TTL_MS` of 5 minutes).
pub const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Thread-safe cache mapping a resolved IP to the hostname that produced it.
#[derive(Debug)]
pub struct DnsCache {
    entries: RwLock<HashMap<IpAddr, Entry>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct Entry {
    domain: String,
    expires: Instant,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(DNS_CACHE_TTL)
    }
}

impl DnsCache {
    /// Create a cache with a custom TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Store (or refresh) a mapping.
    pub fn store(&self, ip: IpAddr, domain: &str) {
        if domain.is_empty() {
            return;
        }
        let entry = Entry {
            domain: domain.to_string(),
            expires: Instant::now() + self.ttl,
        };
        if let Ok(mut map) = self.entries.write() {
            map.insert(ip, entry);
        }
    }

    /// Look up the hostname for an IP, if present and not expired.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let map = self.entries.read().ok()?;
        let entry = map.get(&ip)?;
        if entry.expires > Instant::now() {
            Some(entry.domain.clone())
        } else {
            None
        }
    }

    /// Remove all expired entries. Callers may run this periodically.
    pub fn purge_expired(&self) {
        if let Ok(mut map) = self.entries.write() {
            let now = Instant::now();
            map.retain(|_, e| e.expires > now);
        }
    }

    /// Number of live (non-expired) entries. Primarily for tests/metrics.
    pub fn len(&self) -> usize {
        match self.entries.read() {
            Ok(map) => {
                let now = Instant::now();
                map.values().filter(|e| e.expires > now).count()
            }
            Err(_) => 0,
        }
    }

    /// Whether the cache holds no live entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Parse a DNS response payload (starting at the DNS header) and store all
    /// `A` / `AAAA` answers keyed by the first question's name.
    pub fn snoop_response(&self, payload: &[u8]) {
        for (ip, name) in parse_dns_answers(payload) {
            self.store(ip, &name);
        }
    }
}

/// Parse a DNS message and return `(answer_ip, qname)` pairs for every
/// `A` / `AAAA` record. Returns an empty vec for malformed / non-response
/// messages. Handles name compression pointers.
pub fn parse_dns_answers(payload: &[u8]) -> Vec<(IpAddr, String)> {
    let mut out = Vec::new();
    if payload.len() < 12 {
        return out;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 == 0 {
        return out; // not a response
    }
    if flags & 0x000F != 0 {
        return out; // RCODE != NOERROR
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    if ancount == 0 {
        return out;
    }

    let mut offset = 12usize;

    // First question name is the canonical hostname.
    let qname = match parse_name(payload, &mut offset) {
        Some(n) => n,
        None => return out,
    };
    offset += 4; // QTYPE + QCLASS
    if offset > payload.len() {
        return out;
    }

    // Skip remaining questions.
    for _ in 1..qdcount {
        if offset >= payload.len() || parse_name(payload, &mut offset).is_none() {
            return out;
        }
        offset += 4;
        if offset > payload.len() {
            return out;
        }
    }

    // Answer RRs.
    for _ in 0..ancount {
        if offset >= payload.len() {
            break;
        }
        if parse_name(payload, &mut offset).is_none() {
            break;
        }
        if offset + 10 > payload.len() {
            break;
        }
        let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let rclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
        let rdlen = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > payload.len() {
            break;
        }

        if rclass == 1 {
            if rtype == 1 && rdlen == 4 {
                let octets = [
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ];
                out.push((IpAddr::V4(Ipv4Addr::from(octets)), qname.clone()));
            } else if rtype == 28 && rdlen == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&payload[offset..offset + 16]);
                out.push((IpAddr::V6(Ipv6Addr::from(b)), qname.clone()));
            }
        }
        offset += rdlen;
    }

    out
}

/// Parse a DNS name (with 0xC0 compression pointers) starting at `*offset`.
/// Advances `*offset` past the name in the current record on success.
fn parse_name(msg: &[u8], offset: &mut usize) -> Option<String> {
    let mut pos = *offset;
    let mut out = String::new();
    let mut jumps = 0;
    let mut jumped = false;
    let mut jumped_end = 0usize;

    loop {
        let b = *msg.get(pos)?;
        if b == 0 {
            if !jumped {
                *offset = pos + 1;
            } else {
                *offset = jumped_end;
            }
            return Some(out);
        }
        if b & 0xC0 == 0xC0 {
            let b2 = *msg.get(pos + 1)?;
            if !jumped {
                jumped_end = pos + 2;
            }
            jumped = true;
            pos = (((b & 0x3F) as usize) << 8) | b2 as usize;
            jumps += 1;
            if jumps > 10 {
                return None; // pointer loop guard
            }
            continue;
        }
        let label_len = b as usize;
        pos += 1;
        if pos + label_len > msg.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        let label = std::str::from_utf8(&msg[pos..pos + label_len]).ok()?;
        out.push_str(label);
        pos += label_len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS response for `host` -> one A record `ip`.
    fn build_response(host: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]); // id
        m.extend_from_slice(&[0x81, 0x80]); // flags: response, no error
        m.extend_from_slice(&[0x00, 0x01]); // qdcount
        m.extend_from_slice(&[0x00, 0x01]); // ancount
        m.extend_from_slice(&[0x00, 0x00]); // nscount
        m.extend_from_slice(&[0x00, 0x00]); // arcount
        // Question name.
        let qname_start = m.len();
        for label in host.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        // Answer: pointer to question name.
        let ptr = 0xC000u16 | qname_start as u16;
        m.extend_from_slice(&ptr.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL 300
        m.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        m.extend_from_slice(&ip); // RDATA
        m
    }

    #[test]
    fn parses_a_record() {
        let msg = build_response("example.com", [93, 184, 216, 34]);
        let answers = parse_dns_answers(&msg);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(answers[0].1, "example.com");
    }

    #[test]
    fn snoop_populates_cache() {
        let cache = DnsCache::default();
        let msg = build_response("cdn.example.net", [1, 2, 3, 4]);
        cache.snoop_response(&msg);
        assert_eq!(
            cache
                .lookup(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
                .as_deref(),
            Some("cdn.example.net")
        );
        assert!(
            cache
                .lookup(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
                .is_none()
        );
    }

    #[test]
    fn ignores_queries_and_garbage() {
        // A query (flags high bit clear) yields nothing.
        let mut q = build_response("example.com", [1, 1, 1, 1]);
        q[2] = 0x01; // clear response bit
        q[3] = 0x00;
        assert!(parse_dns_answers(&q).is_empty());
        assert!(parse_dns_answers(&[0u8; 4]).is_empty());
    }

    #[test]
    fn ttl_expiry() {
        let cache = DnsCache::new(Duration::from_millis(0));
        cache.store(IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)), "gone.example");
        // Zero TTL means already expired on lookup.
        std::thread::sleep(Duration::from_millis(1));
        assert!(
            cache
                .lookup(IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)))
                .is_none()
        );
    }

    // ── Edge-case tests ──────────────────────────────────────────

    /// Build a DNS response with an AAAA (IPv6) record.
    fn build_aaaa_response(host: &str, ip: [u8; 16]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]); // id
        m.extend_from_slice(&[0x81, 0x80]); // flags: response, no error
        m.extend_from_slice(&[0x00, 0x01]); // qdcount
        m.extend_from_slice(&[0x00, 0x01]); // ancount
        m.extend_from_slice(&[0x00, 0x00]); // nscount
        m.extend_from_slice(&[0x00, 0x00]); // arcount
        let qname_start = m.len();
        for label in host.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x1c]); // QTYPE AAAA
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        let ptr = 0xC000u16 | qname_start as u16;
        m.extend_from_slice(&ptr.to_be_bytes()); // NAME: pointer to qname
        m.extend_from_slice(&[0x00, 0x1c]); // TYPE AAAA
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL 300
        m.extend_from_slice(&[0x00, 0x10]); // RDLENGTH 16
        m.extend_from_slice(&ip); // IPv6 address
        m
    }

    #[test]
    fn parses_aaaa_record() {
        let ipv6: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let msg = build_aaaa_response("ipv6.example.com", ipv6);
        let answers = parse_dns_answers(&msg);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0, IpAddr::V6(Ipv6Addr::from(ipv6)));
        assert_eq!(answers[0].1, "ipv6.example.com");
    }

    #[test]
    fn multiple_answers_a_plus_cname_plus_a() {
        // Build a response with 3 answers: CNAME → A → A.
        // CNAME is ignored; both A records should map to the qname.
        let host = "example.com";
        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]); // id
        m.extend_from_slice(&[0x81, 0x80]); // flags
        m.extend_from_slice(&[0x00, 0x01]); // qdcount
        m.extend_from_slice(&[0x00, 0x03]); // ancount = 3
        m.extend_from_slice(&[0x00, 0x00]); // nscount
        m.extend_from_slice(&[0x00, 0x00]); // arcount

        // Question — "example.com" starts at byte 12.
        let qname_start = m.len(); // = 12
        for label in host.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        let ptr_qname = (0xC000u16 | qname_start as u16).to_be_bytes();

        // Answer 1 — CNAME → pointer to qname (rdlen=2).
        m.extend_from_slice(&ptr_qname);
        m.extend_from_slice(&[0x00, 0x05]); // TYPE CNAME
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL
        m.extend_from_slice(&[0x00, 0x02]); // RDLENGTH = 2
        m.extend_from_slice(&ptr_qname); // RDATA → pointer to qname

        // Answer 2 — A record 1.2.3.4.
        m.extend_from_slice(&ptr_qname);
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
        m.extend_from_slice(&[0x00, 0x04]);
        m.extend_from_slice(&[1, 2, 3, 4]);

        // Answer 3 — A record 5.6.7.8.
        m.extend_from_slice(&ptr_qname);
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
        m.extend_from_slice(&[0x00, 0x04]);
        m.extend_from_slice(&[5, 6, 7, 8]);

        let answers = parse_dns_answers(&m);
        assert_eq!(answers.len(), 2, "CNAME ignored, 2 A records expected");
        assert_eq!(answers[0].0, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(answers[0].1, "example.com");
        assert_eq!(answers[1].0, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(answers[1].1, "example.com");
    }

    #[test]
    fn cname_chain_uses_qname_as_key() {
        // Question: "original.example.com"
        // Answer 1: CNAME → "aliased.example.net"
        // Answer 2: A record for the aliased name.
        // The A record must use the *original* qname as its key.
        let orig = "original.example.com";
        let alias = "aliased.example.net";

        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]); // id
        m.extend_from_slice(&[0x81, 0x80]); // flags
        m.extend_from_slice(&[0x00, 0x01]); // qdcount
        m.extend_from_slice(&[0x00, 0x02]); // ancount = 2
        m.extend_from_slice(&[0x00, 0x00]);
        m.extend_from_slice(&[0x00, 0x00]);

        let qname_start = m.len(); // = 12
        for label in orig.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        // Encode the CNAME target name in wire format.
        let mut alias_wire = Vec::new();
        for label in alias.split('.') {
            alias_wire.push(label.len() as u8);
            alias_wire.extend_from_slice(label.as_bytes());
        }
        alias_wire.push(0);
        let alias_len = alias_wire.len() as u16;

        let ptr_qname = (0xC000u16 | qname_start as u16).to_be_bytes();

        // Answer 1 — CNAME with RDATA = the alias domain.
        m.extend_from_slice(&ptr_qname);
        m.extend_from_slice(&[0x00, 0x05]); // TYPE CNAME
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
        m.extend_from_slice(&alias_len.to_be_bytes());
        m.extend_from_slice(&alias_wire);

        // Answer 2 — A record 10.0.0.1, NAME points to qname.
        m.extend_from_slice(&ptr_qname);
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
        m.extend_from_slice(&[0x00, 0x04]);
        m.extend_from_slice(&[10, 0, 0, 1]);

        let answers = parse_dns_answers(&m);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        // The key must be the original question name, not the CNAME target.
        assert_eq!(answers[0].1, "original.example.com");
    }

    #[test]
    fn compression_pointer_loop_does_not_hang() {
        // Craft a response where the answer NAME pointer points to itself.
        // parse_name guards loops at 10 jumps → returns None → answer skipped.
        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]); // id
        m.extend_from_slice(&[0x81, 0x80]); // flags
        m.extend_from_slice(&[0x00, 0x01]); // qdcount
        m.extend_from_slice(&[0x00, 0x01]); // ancount = 1
        m.extend_from_slice(&[0x00, 0x00]);
        m.extend_from_slice(&[0x00, 0x00]);

        // Question: "x.com" — 7 bytes of labels + null.
        m.push(1);
        m.push(b'x');
        m.push(3);
        m.push(b'c');
        m.push(b'o');
        m.push(b'm');
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        // Answer section starts at byte 12 + 7 + 4 = 23.
        // Answer NAME is a pointer to byte 23 → self-loop.
        assert_eq!(m.len(), 23, "answer section must start at offset 23");
        m.extend_from_slice(&[0xC0, 0x17]); // pointer to 23 (self)
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL
        m.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        m.extend_from_slice(&[1, 2, 3, 4]);

        let answers = parse_dns_answers(&m);
        // Loop is caught; result is empty (no panic, no hang).
        assert!(answers.is_empty());
    }

    #[test]
    fn truncated_rdlength() {
        // Two answers, but the second one has rdlen extending past EOF.
        // The first answer must still be returned.
        let host = "example.com";
        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]);
        m.extend_from_slice(&[0x81, 0x80]);
        m.extend_from_slice(&[0x00, 0x01]); // qdcount
        m.extend_from_slice(&[0x00, 0x02]); // ancount = 2
        m.extend_from_slice(&[0x00, 0x00]);
        m.extend_from_slice(&[0x00, 0x00]);

        let qname_start = m.len(); // = 12
        for label in host.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS

        let ptr_qname = (0xC000u16 | qname_start as u16).to_be_bytes();

        // Answer 1 — valid A record.
        m.extend_from_slice(&ptr_qname);
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
        m.extend_from_slice(&[0x00, 0x04]);
        m.extend_from_slice(&[1, 2, 3, 4]);

        // Answer 2 — truncated: rdlen = 256 but no RDATA follows.
        // The RR header (NAME + fixed fields) is 12 bytes.
        m.extend_from_slice(&ptr_qname); //  2 bytes
        m.extend_from_slice(&[0x00, 0x01]); //  2
        m.extend_from_slice(&[0x00, 0x01]); //  2
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); //  4
        m.extend_from_slice(&[0x01, 0x00]); // RDLENGTH = 256  → total = 12

        let answers = parse_dns_answers(&m);
        // Only the first (valid) answer before the truncated one.
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(answers[0].1, "example.com");
    }

    #[test]
    fn ancount_larger_than_buffer() {
        // Build a normal 1-answer response, then overwrite ancount with 100.
        let mut m = build_response("test.example", [10, 20, 30, 40]);
        m[6] = 0x00; // ancount hi
        m[7] = 0x64; // ancount lo = 100
        let answers = parse_dns_answers(&m);
        // The single answer should still be parsed.
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0, IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)));
        assert_eq!(answers[0].1, "test.example");
    }

    #[test]
    fn non_in_class_ignored() {
        // Build a response with CLASS = CHAOS (3).  The answer must be skipped.
        let host = "chaos.example.com";
        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]);
        m.extend_from_slice(&[0x81, 0x80]);
        m.extend_from_slice(&[0x00, 0x01]); // qdcount
        m.extend_from_slice(&[0x00, 0x01]); // ancount
        m.extend_from_slice(&[0x00, 0x00]);
        m.extend_from_slice(&[0x00, 0x00]);

        let qname_start = m.len(); // = 12
        for label in host.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        let ptr = 0xC000u16 | qname_start as u16;
        m.extend_from_slice(&ptr.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x03]); // CLASS CHAOS (not IN)
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
        m.extend_from_slice(&[0x00, 0x04]);
        m.extend_from_slice(&[1, 2, 3, 4]);

        let answers = parse_dns_answers(&m);
        assert!(answers.is_empty(), "non-IN class should be ignored");
    }

    #[test]
    fn ignores_non_noerror_rcode() {
        // NXDOMAIN rcode = 3 → flags 0x8183.
        let mut m = build_response("nx.example.com", [1, 1, 1, 1]);
        m[2] = 0x81; // QR=1, RD=1
        m[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
        let answers = parse_dns_answers(&m);
        assert!(
            answers.is_empty(),
            "NXDOMAIN responses must yield no answers"
        );
    }

    #[test]
    fn multiple_questions_parses_first_qname() {
        // Two questions: "first.example.com" and "second.example.net".
        // The answer should be keyed by the *first* question's name.
        let first = "first.example.com";
        let second = "second.example.net";

        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]);
        m.extend_from_slice(&[0x81, 0x80]);
        m.extend_from_slice(&[0x00, 0x02]); // qdcount = 2
        m.extend_from_slice(&[0x00, 0x01]); // ancount = 1
        m.extend_from_slice(&[0x00, 0x00]);
        m.extend_from_slice(&[0x00, 0x00]);

        let qname_start = m.len(); // = 12

        // Question 1.
        for label in first.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        // Question 2.
        for label in second.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        // Answer — points to qname_start.
        let ptr = (0xC000u16 | qname_start as u16).to_be_bytes();
        m.extend_from_slice(&ptr);
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
        m.extend_from_slice(&[0x00, 0x04]);
        m.extend_from_slice(&[7, 7, 7, 7]);

        let answers = parse_dns_answers(&m);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0, IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7)));
        assert_eq!(answers[0].1, "first.example.com");
    }

    #[test]
    fn fuzz_random_bytes_no_panic() {
        // Simple xorshift32 PRNG — no external crate needed.
        let mut state: u32 = 0xDEAD_BEEF;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };

        for _ in 0..1000 {
            let len = (next() as usize) % 201; // 0..200
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                data.push(next() as u8);
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = parse_dns_answers(&data);
            }));
            assert!(
                result.is_ok(),
                "parse_dns_answers panicked on random bytes of length {}",
                len
            );
        }
    }
}
