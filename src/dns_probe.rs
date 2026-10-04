// BUG: specs/bugs/BUG-network-manager-tun-address-loss.md

//! Reachability probe for the DNS servers the client advertises to the host.
//!
//! `[interface].dns` is published to the system resolver *and* pinned through
//! the tunnel, so the host's lookups travel inside the tunnel. When that path
//! stops answering, the host is left with a resolver that never replies and
//! every lookup hangs — strictly worse than an uncensored-but-working one. One
//! well-formed question is enough to tell a live responder from a black hole,
//! so this module builds a query, sends it, and inspects the reply header.
//!
//! Only the header is examined: the question is "does this responder answer at
//! all", not "is the answer correct". Any RCODE is accepted — a SERVFAIL or
//! REFUSED reply still proves the path works.

use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::atomic::{AtomicU16, Ordering},
    time::{Duration, Instant},
};

/// Standard DNS port the probe questions.
pub const DNS_PORT: u16 = 53;

/// Name asked by the probe. Reserved for documentation (RFC 2606), so the
/// probe never depends on, or pollutes, anything a client actually uses.
pub const PROBE_NAME: &str = "example.com";

/// Size of a DNS message header (RFC 1035 §4.1.1).
pub const DNS_HEADER_LEN: usize = 12;

/// Query flags: recursion desired, everything else zero.
const FLAGS_QUERY: u16 = 0x0100;

/// `QR` bit (bit 15 of the flags field): set in responses, clear in queries.
const QR_FLAG: u16 = 0x8000;

/// QTYPE value for `A`.
const QTYPE_A: u16 = 1;

/// QCLASS value for `IN`.
const QCLASS_IN: u16 = 1;

/// Largest response the probe reads (probes set no EDNS buffer size).
const MAX_RESPONSE_LEN: usize = 512;

/// First transaction id handed out; incremented per probe so overlapping
/// probes never confuse each other's replies.
const FIRST_PROBE_ID: u16 = 0xC000;

static NEXT_PROBE_ID: AtomicU16 = AtomicU16::new(FIRST_PROBE_ID);

/// Next transaction id to use for a probe.
fn next_probe_id() -> u16 {
    NEXT_PROBE_ID.fetch_add(1, Ordering::Relaxed)
}

/// Build a DNS query (class `IN`, type `A`) for `name` under transaction `id`.
pub fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(DNS_HEADER_LEN + name.len() + 6);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&FLAGS_QUERY.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.split('.').filter(|label| !label.is_empty()) {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // root label terminates the qname
    packet.extend_from_slice(&QTYPE_A.to_be_bytes());
    packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
    packet
}

/// Report whether `packet` is a DNS *response* to a query that used `id`.
///
/// Any RCODE is treated as success: the probe measures liveness of the path,
/// not the usefulness of the answer.
pub fn is_response_to(id: u16, packet: &[u8]) -> bool {
    if packet.len() < DNS_HEADER_LEN {
        return false;
    }
    let matches_id = u16::from_be_bytes([packet[0], packet[1]]) == id;
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    matches_id && (flags & QR_FLAG) != 0
}

/// Ask `server:port` one question over UDP, reporting whether it answered in
/// time.
///
/// The socket carries no `SO_MARK`, so the kernel routes the question by the
/// normal policy rules — which is exactly the tunnel path being gated.
pub fn responds_at_addr(target: SocketAddr, timeout: Duration) -> bool {
    let wildcard = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let Ok(socket) = UdpSocket::bind(wildcard) else {
        return false;
    };
    if socket.connect(target).is_err() {
        return false;
    }
    let query = build_query(next_probe_id(), PROBE_NAME);
    let id = u16::from_be_bytes([query[0], query[1]]);
    if socket.send(&query).is_err() {
        return false;
    }

    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        if socket.set_read_timeout(Some(remaining)).is_err() {
            return false;
        }
        let mut buffer = [0u8; MAX_RESPONSE_LEN];
        match socket.recv(&mut buffer) {
            Ok(read) if is_response_to(id, &buffer[..read]) => return true,
            Ok(_) => continue, // someone else's packet; keep waiting for ours
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return false,
            Err(_) => return false, // unreachable/refused: the path is down
        }
    }
}

/// Ask the configured resolver `server` (default DNS port) whether it answers.
pub fn server_responds(server: IpAddr, timeout: Duration) -> bool {
    responds_at_addr(SocketAddr::new(server, DNS_PORT), timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- AC: the probe asks a standards-shaped question ----------------------

    #[test]
    fn query_encodes_the_question_per_rfc_1035() {
        let query = build_query(0xC0DE, PROBE_NAME);
        let expected: Vec<u8> = vec![
            0xC0, 0xDE, // id
            0x01, 0x00, // flags: recursion desired
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];
        assert_eq!(query, expected);
    }

    #[test]
    fn query_ignores_a_trailing_dot_and_stays_probe_sized() {
        let query = build_query(1, "example.com.");
        assert_eq!(query, build_query(1, "example.com"), "trailing dot is not a label");
        assert!(query.len() < MAX_RESPONSE_LEN, "probe must fit one UDP datagram");
    }

    // -- AC: only a matching response counts ---------------------------------

    #[test]
    fn any_rcode_response_counts_as_alive() {
        let query = build_query(7, PROBE_NAME);
        for flags in [0x8180u16, 0x8182, 0x8005, 0x8000] {
            let mut response = query.clone();
            response[2..4].copy_from_slice(&flags.to_be_bytes());
            assert!(is_response_to(7, &response), "flags {flags:#06x} must be accepted");
        }
    }

    #[test]
    fn queries_mismatched_ids_and_ragged_packets_are_not_answers() {
        let query = build_query(7, PROBE_NAME);
        assert!(!is_response_to(7, &query), "the question is not an answer");

        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        assert!(!is_response_to(8, &response), "a reply to another id proves nothing");
        assert!(!is_response_to(7, &response[..DNS_HEADER_LEN - 1]), "truncated header rejected");
        assert!(!is_response_to(7, &[]), "empty datagram rejected");
    }

    // -- AC: the probe measures a real socket path ---------------------------

    #[test]
    fn probe_reports_alive_for_a_responding_server() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind fixture");
        let addr = server.local_addr().expect("fixture addr");
        let replier = std::thread::spawn(move || {
            // One round trip: answer from the queried address with QR set.
            let mut buffer = [0u8; MAX_RESPONSE_LEN];
            let (read, peer) = server.recv_from(&mut buffer).expect("fixture recv");
            let mut response = buffer[..read].to_vec();
            let flags = u16::from_be_bytes([response[2], response[3]]);
            response[2..4].copy_from_slice(&(flags | QR_FLAG).to_be_bytes());
            server.send_to(&response, peer).expect("fixture reply");
        });

        assert!(
            responds_at_addr(addr, Duration::from_secs(2)),
            "a responder on the queried address must read as alive"
        );
        replier.join().expect("fixture thread");
    }

    #[test]
    fn probe_reports_dead_for_an_unanswered_port() {
        // Bind then release an ephemeral port: nothing listens there, so the
        // kernel answers our datagram with ICMP port-unreachable.
        let addr = {
            let scratch = UdpSocket::bind("127.0.0.1:0").expect("bind scratch");
            scratch.local_addr().expect("scratch addr")
        };
        let start = Instant::now();
        assert!(!responds_at_addr(addr, Duration::from_secs(3)), "closed port must read as dead");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "dead path must fail without burning the timeout"
        );
    }

    #[test]
    fn server_responds_wraps_the_default_dns_port() {
        // Port 53 on loopback is not listening in the test environment, and
        // the address argument must reach the socket unchanged.
        assert!(!server_responds(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Duration::from_millis(500)
        ));
        assert_eq!(DNS_PORT, 53);
    }
}
