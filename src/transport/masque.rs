// FRD: specs/frds/FRD-007.md

//! MASQUE CONNECT-UDP framing over QUIC DATAGRAMs.
//!
//! Implements RFC 9297 (HTTP Datagrams) and RFC 9298 (CONNECT-UDP) framing
//! on top of quinn's native QUIC DATAGRAM support. Traffic appears as
//! standard HTTP/3 to external observers (ALPN `h3`).
//!
//! # Wire Format
//!
//! Each QUIC DATAGRAM payload has the structure:
//! ```text
//! [Quarter Stream ID (varint)] [Context ID (varint)] [UDP payload]
//! ```
//!
//! Quarter Stream ID = request_stream_id / 4 (per RFC 9297 §4).
//! Context ID = 0 for raw UDP payloads (per RFC 9298 §5).

use super::TransportError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Two most-significant bits mask for varint length prefix (RFC 9000 §16).
const VARINT_LENGTH_MASK: u8 = 0xC0;

/// 1-byte varint prefix (2 MSB = 00).
const VARINT_1BYTE_PREFIX: u8 = 0x00;

/// 2-byte varint prefix (2 MSB = 01).
const VARINT_2BYTE_PREFIX: u8 = 0x40;

/// 4-byte varint prefix (2 MSB = 10).
const VARINT_4BYTE_PREFIX: u8 = 0x80;

/// 8-byte varint prefix (2 MSB = 11).
const VARINT_8BYTE_PREFIX: u8 = 0xC0;

/// Maximum value for a 1-byte varint (6 bits).
const VARINT_1BYTE_MAX: u64 = 63;

/// Maximum value for a 2-byte varint (14 bits).
const VARINT_2BYTE_MAX: u64 = 16_383;

/// Maximum value for a 4-byte varint (30 bits).
const VARINT_4BYTE_MAX: u64 = 1_073_741_823;

/// Maximum value for a QUIC varint (62 bits).
const VARINT_MAX: u64 = 4_611_686_018_427_387_903;

/// Context ID for raw UDP payload (RFC 9298 §5).
const CONTEXT_ID_UDP_PAYLOAD: u64 = 0;

/// ALPN protocol identifier for HTTP/3.
pub const ALPN_H3: &[u8] = b"h3";

/// Default datagram receive buffer size in bytes.
const DEFAULT_DATAGRAM_RECV_BUFFER_SIZE: usize = 65_536;

/// Minimum encoded size for an HTTP Datagram frame (1-byte quarter stream id + 1-byte context id).
const MIN_HTTP_DATAGRAM_HEADER_SIZE: usize = 2;

// ---------------------------------------------------------------------------
// QUIC Variable-Length Integer (RFC 9000 §16)
// ---------------------------------------------------------------------------

/// Encode a QUIC variable-length integer into a byte buffer.
///
/// Returns the number of bytes written. The buffer must have at least 8 bytes
/// of space (worst case). Returns an error if the value exceeds the maximum
/// 62-bit varint range.
pub fn varint_encode(value: u64, buf: &mut [u8]) -> Result<usize, TransportError> {
    if value <= VARINT_1BYTE_MAX {
        let needed = 1;
        if buf.len() < needed {
            return Err(TransportError::VarintDecode(format!(
                "buffer too small: need {needed} bytes, got {}",
                buf.len()
            )));
        }
        buf[0] = value as u8;
        Ok(needed)
    } else if value <= VARINT_2BYTE_MAX {
        let needed = 2;
        if buf.len() < needed {
            return Err(TransportError::VarintDecode(format!(
                "buffer too small: need {needed} bytes, got {}",
                buf.len()
            )));
        }
        let encoded = (value as u16) | u16::from(VARINT_2BYTE_PREFIX) << 8;
        let bytes = encoded.to_be_bytes();
        buf[0] = bytes[0];
        buf[1] = bytes[1];
        Ok(needed)
    } else if value <= VARINT_4BYTE_MAX {
        let needed = 4;
        if buf.len() < needed {
            return Err(TransportError::VarintDecode(format!(
                "buffer too small: need {needed} bytes, got {}",
                buf.len()
            )));
        }
        let encoded = (value as u32) | u32::from(VARINT_4BYTE_PREFIX) << 24;
        let bytes = encoded.to_be_bytes();
        buf[..needed].copy_from_slice(&bytes);
        Ok(needed)
    } else if value <= VARINT_MAX {
        let needed = 8;
        if buf.len() < needed {
            return Err(TransportError::VarintDecode(format!(
                "buffer too small: need {needed} bytes, got {}",
                buf.len()
            )));
        }
        let encoded = value | u64::from(VARINT_8BYTE_PREFIX) << 56;
        let bytes = encoded.to_be_bytes();
        buf[..needed].copy_from_slice(&bytes);
        Ok(needed)
    } else {
        Err(TransportError::VarintDecode(format!(
            "value {value} exceeds maximum varint {VARINT_MAX}"
        )))
    }
}

/// Decode a QUIC variable-length integer from a byte slice.
///
/// Returns the decoded value and the number of bytes consumed.
/// Returns an error if the input is too short.
pub fn varint_decode(buf: &[u8]) -> Result<(u64, usize), TransportError> {
    if buf.is_empty() {
        return Err(TransportError::VarintDecode("empty input".to_string()));
    }

    let prefix = buf[0] & VARINT_LENGTH_MASK;
    match prefix {
        VARINT_1BYTE_PREFIX => {
            let value = u64::from(buf[0] & !VARINT_LENGTH_MASK);
            Ok((value, 1))
        }
        VARINT_2BYTE_PREFIX => {
            let needed = 2;
            if buf.len() < needed {
                return Err(TransportError::VarintDecode(format!(
                    "truncated 2-byte varint: need {needed} bytes, got {}",
                    buf.len()
                )));
            }
            let value = u64::from(u16::from_be_bytes([buf[0] & !VARINT_LENGTH_MASK, buf[1]]));
            Ok((value, needed))
        }
        VARINT_4BYTE_PREFIX => {
            let needed = 4;
            if buf.len() < needed {
                return Err(TransportError::VarintDecode(format!(
                    "truncated 4-byte varint: need {needed} bytes, got {}",
                    buf.len()
                )));
            }
            let value = u64::from(u32::from_be_bytes([buf[0] & !VARINT_LENGTH_MASK, buf[1], buf[2], buf[3]]));
            Ok((value, needed))
        }
        VARINT_8BYTE_PREFIX => {
            let needed = 8;
            if buf.len() < needed {
                return Err(TransportError::VarintDecode(format!(
                    "truncated 8-byte varint: need {needed} bytes, got {}",
                    buf.len()
                )));
            }
            let value = u64::from_be_bytes([buf[0] & !VARINT_LENGTH_MASK, buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
            Ok((value, needed))
        }
        _ => unreachable!("2-bit prefix covers all 4 cases"),
    }
}

// ---------------------------------------------------------------------------
// HTTP Datagram Framing (RFC 9297)
// ---------------------------------------------------------------------------

/// Frame a UDP payload as an HTTP Datagram (RFC 9297).
///
/// Prepends Quarter Stream ID and Context ID (0) to the payload.
/// `request_stream_id` is the HTTP/3 request stream ID (must be divisible by 4).
pub fn frame_datagram(request_stream_id: u64, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    let quarter_stream_id = request_stream_id / 4;

    let mut buf = vec![0u8; 8 + 8 + payload.len()];
    let n1 = varint_encode(quarter_stream_id, &mut buf)?;
    let n2 = varint_encode(CONTEXT_ID_UDP_PAYLOAD, &mut buf[n1..])?;
    let header_len = n1 + n2;
    buf[header_len..header_len + payload.len()].copy_from_slice(payload);
    buf.truncate(header_len + payload.len());

    Ok(buf)
}

/// Deframe an HTTP Datagram (RFC 9297) to extract the UDP payload.
///
/// Returns `(quarter_stream_id, context_id, payload)`.
pub fn deframe_datagram(data: &[u8]) -> Result<(u64, u64, Vec<u8>), TransportError> {
    if data.len() < MIN_HTTP_DATAGRAM_HEADER_SIZE {
        return Err(TransportError::MasqueDatagram(format!(
            "datagram too short: need at least {MIN_HTTP_DATAGRAM_HEADER_SIZE} bytes, got {}",
            data.len()
        )));
    }

    let (quarter_stream_id, n1) = varint_decode(data)?;
    if n1 >= data.len() {
        return Err(TransportError::MasqueDatagram(
            "datagram truncated after quarter stream id".to_string(),
        ));
    }
    let (context_id, n2) = varint_decode(&data[n1..])?;
    let header_len = n1 + n2;
    let payload = data[header_len..].to_vec();

    Ok((quarter_stream_id, context_id, payload))
}

// ---------------------------------------------------------------------------
// MASQUE Client & Proxy
// ---------------------------------------------------------------------------

/// MASQUE CONNECT-UDP client.
///
/// Wraps a QUIC connection and provides datagram send/receive with
/// HTTP Datagram framing per RFC 9297/9298.
pub struct MasqueClient {
    connection: quinn::Connection,
    request_stream_id: u64,
}

/// MASQUE CONNECT-UDP proxy.
///
/// Accepts CONNECT-UDP requests from clients and provides datagram
/// send/receive with HTTP Datagram framing per RFC 9297/9298.
pub struct MasqueProxy {
    connection: quinn::Connection,
    request_stream_id: u64,
}

/// The initial request stream ID for the first client-initiated bidi stream in HTTP/3.
const INITIAL_REQUEST_STREAM_ID: u64 = 0;

/// Extended CONNECT request line for CONNECT-UDP.
const CONNECT_UDP_REQUEST: &[u8] = b"CONNECT-UDP /tunnel HTTP/3\r\n\r\n";

/// Response for successful CONNECT-UDP establishment.
const CONNECT_UDP_RESPONSE_OK: &[u8] = b"HTTP/3 200 OK\r\n\r\n";

/// Maximum read size for the CONNECT-UDP handshake response.
const HANDSHAKE_MAX_READ: usize = 256;

impl MasqueClient {
    /// Establish a MASQUE CONNECT-UDP tunnel over the given QUIC connection.
    ///
    /// Sends an Extended CONNECT request and waits for a 200 OK response
    /// from the proxy. After this, datagrams can be sent/received.
    pub async fn connect(connection: quinn::Connection) -> Result<Self, TransportError> {
        let request_stream_id = INITIAL_REQUEST_STREAM_ID;

        // Open a bidi stream for the CONNECT-UDP request
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| TransportError::MasqueHandshake(e.to_string()))?;

        // Send CONNECT-UDP request and finish the send side
        send.write_all(CONNECT_UDP_REQUEST)
            .await
            .map_err(|e| TransportError::MasqueHandshake(e.to_string()))?;
        send.finish().map_err(|e| TransportError::MasqueHandshake(e.to_string()))?;

        // Read response (proxy sends response then finishes its side)
        let response = recv
            .read_to_end(HANDSHAKE_MAX_READ)
            .await
            .map_err(|e| TransportError::MasqueHandshake(e.to_string()))?;

        if response != CONNECT_UDP_RESPONSE_OK {
            return Err(TransportError::MasqueHandshake(format!(
                "unexpected response: expected {} bytes, got {}",
                CONNECT_UDP_RESPONSE_OK.len(),
                response.len()
            )));
        }

        Ok(Self {
            connection,
            request_stream_id,
        })
    }

    /// Send a UDP datagram through the MASQUE tunnel.
    ///
    /// The payload is framed as an HTTP Datagram (RFC 9297) and sent
    /// as a QUIC DATAGRAM.
    pub fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError> {
        let framed = frame_datagram(self.request_stream_id, payload)?;
        self.connection
            .send_datagram(framed.into())
            .map_err(|e| TransportError::MasqueDatagram(e.to_string()))
    }

    /// Receive a UDP datagram from the MASQUE tunnel.
    ///
    /// Reads a QUIC DATAGRAM, deframes the HTTP Datagram header, and
    /// returns the raw UDP payload.
    pub async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let data = self
            .connection
            .read_datagram()
            .await
            .map_err(|e| TransportError::MasqueDatagram(e.to_string()))?;

        let (_quarter_stream_id, _context_id, payload) = deframe_datagram(&data)?;
        Ok(payload)
    }

    /// Return the maximum datagram payload size, if datagrams are supported.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }
}

impl MasqueProxy {
    /// Accept a MASQUE CONNECT-UDP tunnel from a client on the given QUIC connection.
    ///
    /// Reads the Extended CONNECT request and sends a 200 OK response.
    /// After this, datagrams can be sent/received.
    pub async fn accept(connection: quinn::Connection) -> Result<Self, TransportError> {
        let request_stream_id = INITIAL_REQUEST_STREAM_ID;

        // Accept the bidi stream with the CONNECT-UDP request
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| TransportError::MasqueHandshake(e.to_string()))?;

        // Read CONNECT-UDP request
        let request = recv
            .read_to_end(HANDSHAKE_MAX_READ)
            .await
            .map_err(|e| TransportError::MasqueHandshake(e.to_string()))?;

        if request != CONNECT_UDP_REQUEST {
            return Err(TransportError::MasqueHandshake(format!(
                "unexpected request: expected {} bytes, got {}",
                CONNECT_UDP_REQUEST.len(),
                request.len()
            )));
        }

        // Send 200 OK response
        send.write_all(CONNECT_UDP_RESPONSE_OK)
            .await
            .map_err(|e| TransportError::MasqueHandshake(e.to_string()))?;
        send.finish().map_err(|e| TransportError::MasqueHandshake(e.to_string()))?;

        Ok(Self {
            connection,
            request_stream_id,
        })
    }

    /// Send a UDP datagram through the MASQUE tunnel.
    pub fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError> {
        let framed = frame_datagram(self.request_stream_id, payload)?;
        self.connection
            .send_datagram(framed.into())
            .map_err(|e| TransportError::MasqueDatagram(e.to_string()))
    }

    /// Receive a UDP datagram from the MASQUE tunnel.
    pub async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let data = self
            .connection
            .read_datagram()
            .await
            .map_err(|e| TransportError::MasqueDatagram(e.to_string()))?;

        let (_quarter_stream_id, _context_id, payload) = deframe_datagram(&data)?;
        Ok(payload)
    }

    /// Return the maximum datagram payload size, if datagrams are supported.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }
}

// ---------------------------------------------------------------------------
// QUIC Transport Config Helpers
// ---------------------------------------------------------------------------

/// Create a quinn `TransportConfig` with datagrams enabled.
///
/// This is needed for both client and server endpoints that use MASQUE.
pub fn datagram_transport_config(keep_alive_interval: u64, max_idle_timeout: u64) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.datagram_receive_buffer_size(Some(DEFAULT_DATAGRAM_RECV_BUFFER_SIZE));

    if keep_alive_interval > 0 {
        config.keep_alive_interval(Some(std::time::Duration::from_secs(keep_alive_interval)));
    }

    if max_idle_timeout > 0 {
        config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(max_idle_timeout)).unwrap(),
        ));
    } else {
        config.max_idle_timeout(None);
    }

    config
}

// ---------------------------------------------------------------------------
// Server/Client Builders with Datagram Support
// ---------------------------------------------------------------------------

/// Build a quinn `ServerConfig` for MASQUE with datagrams enabled and ALPN `h3`.
///
/// Accepts a certificate chain (one or more certs) and a private key.
pub fn build_masque_server_config(
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
    keep_alive_interval: u64,
    max_idle_timeout: u64,
) -> Result<quinn::ServerConfig, TransportError> {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    tls_config.alpn_protocols = vec![ALPN_H3.to_vec()];

    let quic_server_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(datagram_transport_config(keep_alive_interval, max_idle_timeout)));

    Ok(server_config)
}

/// Build a quinn `ClientConfig` for MASQUE with datagrams enabled and ALPN `h3`.
///
/// When `insecure` is `true`, skips certificate verification (dev/test).
/// When `insecure` is `false`, verifies against the Mozilla CA root store.
pub fn build_masque_client_config(
    keep_alive_interval: u64,
    max_idle_timeout: u64,
    insecure: bool,
) -> Result<quinn::ClientConfig, TransportError> {
    let verifier = super::tls::build_cert_verifier(insecure);
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![ALPN_H3.to_vec()];

    let quic_client_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    client_config.transport_config(Arc::new(datagram_transport_config(keep_alive_interval, max_idle_timeout)));

    Ok(client_config)
}

use std::sync::Arc;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SERVER_NAME: &str = "localhost";
    const TEST_BIND_ADDR: &str = "127.0.0.1:0";

    // -----------------------------------------------------------------------
    // T-1: Varint encode/decode round-trip for boundary values
    // -----------------------------------------------------------------------

    #[test]
    fn varint_round_trip_zero() {
        let mut buf = [0u8; 8];
        let n = varint_encode(0, &mut buf).expect("encode 0");
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x00);
        let (val, consumed) = varint_decode(&buf[..n]).expect("decode 0");
        assert_eq!(val, 0);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn varint_round_trip_1byte_max() {
        let mut buf = [0u8; 8];
        let n = varint_encode(VARINT_1BYTE_MAX, &mut buf).expect("encode 63");
        assert_eq!(n, 1);
        let (val, consumed) = varint_decode(&buf[..n]).expect("decode 63");
        assert_eq!(val, VARINT_1BYTE_MAX);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn varint_round_trip_2byte_min() {
        let value = VARINT_1BYTE_MAX + 1; // 64
        let mut buf = [0u8; 8];
        let n = varint_encode(value, &mut buf).expect("encode 64");
        assert_eq!(n, 2);
        let (val, consumed) = varint_decode(&buf[..n]).expect("decode 64");
        assert_eq!(val, value);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn varint_round_trip_2byte_max() {
        let mut buf = [0u8; 8];
        let n = varint_encode(VARINT_2BYTE_MAX, &mut buf).expect("encode 16383");
        assert_eq!(n, 2);
        let (val, consumed) = varint_decode(&buf[..n]).expect("decode 16383");
        assert_eq!(val, VARINT_2BYTE_MAX);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn varint_round_trip_4byte_min() {
        let value = VARINT_2BYTE_MAX + 1; // 16384
        let mut buf = [0u8; 8];
        let n = varint_encode(value, &mut buf).expect("encode 16384");
        assert_eq!(n, 4);
        let (val, consumed) = varint_decode(&buf[..n]).expect("decode 16384");
        assert_eq!(val, value);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn varint_round_trip_4byte_max() {
        let mut buf = [0u8; 8];
        let n = varint_encode(VARINT_4BYTE_MAX, &mut buf).expect("encode 2^30-1");
        assert_eq!(n, 4);
        let (val, consumed) = varint_decode(&buf[..n]).expect("decode 2^30-1");
        assert_eq!(val, VARINT_4BYTE_MAX);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn varint_round_trip_8byte_min() {
        let value = VARINT_4BYTE_MAX + 1; // 2^30
        let mut buf = [0u8; 8];
        let n = varint_encode(value, &mut buf).expect("encode 2^30");
        assert_eq!(n, 8);
        let (val, consumed) = varint_decode(&buf[..n]).expect("decode 2^30");
        assert_eq!(val, value);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn varint_round_trip_8byte_max() {
        let mut buf = [0u8; 8];
        let n = varint_encode(VARINT_MAX, &mut buf).expect("encode max");
        assert_eq!(n, 8);
        let (val, consumed) = varint_decode(&buf[..n]).expect("decode max");
        assert_eq!(val, VARINT_MAX);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn varint_encode_overflow_rejected() {
        let mut buf = [0u8; 8];
        let result = varint_encode(VARINT_MAX + 1, &mut buf);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // T-2: Varint decode rejects truncated input
    // -----------------------------------------------------------------------

    #[test]
    fn varint_decode_empty_input() {
        let result = varint_decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn varint_decode_truncated_2byte() {
        // First byte indicates 2-byte varint (01 prefix) but only 1 byte provided
        let buf = [0x40];
        let result = varint_decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn varint_decode_truncated_4byte() {
        // First byte indicates 4-byte varint (10 prefix) but only 2 bytes provided
        let buf = [0x80, 0x00];
        let result = varint_decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn varint_decode_truncated_8byte() {
        // First byte indicates 8-byte varint (11 prefix) but only 4 bytes provided
        let buf = [0xC0, 0x00, 0x00, 0x00];
        let result = varint_decode(&buf);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // T-3: HTTP Datagram frame/deframe round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn datagram_frame_deframe_round_trip() {
        let request_stream_id = 0u64;
        let payload = b"hello tunnel";

        let framed = frame_datagram(request_stream_id, payload).expect("frame");
        let (quarter_stream_id, context_id, decoded_payload) = deframe_datagram(&framed).expect("deframe");

        assert_eq!(quarter_stream_id, request_stream_id / 4);
        assert_eq!(context_id, CONTEXT_ID_UDP_PAYLOAD);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn datagram_frame_deframe_with_nonzero_stream_id() {
        // HTTP/3 bidi streams: 0, 4, 8, 12, ...
        let request_stream_id = 4u64;
        let payload = b"second stream datagram";

        let framed = frame_datagram(request_stream_id, payload).expect("frame");
        let (quarter_stream_id, context_id, decoded_payload) = deframe_datagram(&framed).expect("deframe");

        assert_eq!(quarter_stream_id, 1); // 4 / 4 = 1
        assert_eq!(context_id, CONTEXT_ID_UDP_PAYLOAD);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn datagram_frame_deframe_large_payload() {
        let request_stream_id = 0u64;
        let payload: Vec<u8> = (0..1024u16).map(|i| (i % 256) as u8).collect();

        let framed = frame_datagram(request_stream_id, &payload).expect("frame");
        let (_, _, decoded_payload) = deframe_datagram(&framed).expect("deframe");

        assert_eq!(decoded_payload, payload);
    }

    // -----------------------------------------------------------------------
    // T-4: HTTP Datagram deframe rejects truncated frame
    // -----------------------------------------------------------------------

    #[test]
    fn datagram_deframe_too_short() {
        let result = deframe_datagram(&[0x00]); // only 1 byte, need at least 2
        assert!(result.is_err());
    }

    #[test]
    fn datagram_deframe_truncated_after_quarter_stream_id() {
        // 2-byte varint for quarter stream id, but nothing left for context id
        let buf = [0x40, 0x01];
        let result = deframe_datagram(&buf);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // T-5: HTTP Datagram deframe with empty payload
    // -----------------------------------------------------------------------

    #[test]
    fn datagram_deframe_empty_payload() {
        let request_stream_id = 0u64;
        let payload: &[u8] = b"";

        let framed = frame_datagram(request_stream_id, payload).expect("frame");
        let (quarter_stream_id, context_id, decoded_payload) = deframe_datagram(&framed).expect("deframe");

        assert_eq!(quarter_stream_id, 0);
        assert_eq!(context_id, CONTEXT_ID_UDP_PAYLOAD);
        assert!(decoded_payload.is_empty());
    }

    /// MASQUE framing for stream_id=0 must produce exactly 2 bytes of overhead.
    /// TUNNEL_OVERHEAD_BYTES assumes this minimum; if it grows, the MTU budget breaks.
    #[test]
    fn masque_framing_overhead_for_stream_zero() {
        let payload = vec![0u8; 100];
        let framed = frame_datagram(0, &payload).expect("frame");
        let overhead = framed.len() - payload.len();
        assert_eq!(overhead, 2, "stream_id=0 framing must be exactly 2 bytes, got {overhead}");
    }

    // -----------------------------------------------------------------------
    // T-6: CONNECT-UDP handshake: client sends request, proxy accepts
    // -----------------------------------------------------------------------

    /// Install the rustls ring crypto provider (idempotent — safe to call multiple times).
    fn init_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn setup_masque_endpoints() -> (quinn::Endpoint, quinn::Endpoint, std::net::SocketAddr) {
        init_crypto_provider();
        let (cert, key) = super::super::quic::generate_self_signed_cert(vec![TEST_SERVER_NAME.to_string()]).expect("cert generation");

        let server_config = build_masque_server_config(vec![cert], key, 25, 300).expect("server config");
        let server_endpoint = quinn::Endpoint::server(server_config, TEST_BIND_ADDR.parse().expect("valid addr")).expect("server bind");
        let server_addr = server_endpoint.local_addr().expect("local addr");

        let client_config = build_masque_client_config(25, 300, true).expect("client config");
        let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid addr")).expect("client bind");
        client_endpoint.set_default_client_config(client_config);

        (server_endpoint, client_endpoint, server_addr)
    }

    #[tokio::test]
    async fn connect_udp_handshake() {
        let (server_endpoint, client_endpoint, server_addr) = setup_masque_endpoints();

        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept incoming");
            let connection = incoming.await.expect("connection");
            let proxy = MasqueProxy::accept(connection).await.expect("proxy accept");
            (server_endpoint, proxy)
        });

        let connection = client_endpoint
            .connect(server_addr, TEST_SERVER_NAME)
            .expect("connect")
            .await
            .expect("connection");

        let client = MasqueClient::connect(connection).await.expect("masque connect");

        // Verify max_datagram_size returns Some (datagrams are enabled)
        assert!(client.max_datagram_size().is_some(), "datagrams should be enabled");

        let (_server_endpoint, proxy) = server_handle.await.expect("server task");
        assert!(proxy.max_datagram_size().is_some(), "proxy datagrams should be enabled");
    }

    // -----------------------------------------------------------------------
    // T-7: Client sends datagram through tunnel, proxy receives
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn client_sends_datagram_proxy_receives() {
        let (server_endpoint, client_endpoint, server_addr) = setup_masque_endpoints();

        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept incoming");
            let connection = incoming.await.expect("connection");
            let proxy = MasqueProxy::accept(connection).await.expect("proxy accept");

            let payload = proxy.recv_datagram().await.expect("recv datagram");
            assert_eq!(payload, b"client-to-proxy");

            (server_endpoint, proxy)
        });

        let connection = client_endpoint
            .connect(server_addr, TEST_SERVER_NAME)
            .expect("connect")
            .await
            .expect("connection");

        let client = MasqueClient::connect(connection).await.expect("masque connect");
        client.send_datagram(b"client-to-proxy").expect("send datagram");

        let (_server_endpoint, _proxy) = server_handle.await.expect("server task");
    }

    // -----------------------------------------------------------------------
    // T-8: Proxy sends datagram back, client receives
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn proxy_sends_datagram_client_receives() {
        let (server_endpoint, client_endpoint, server_addr) = setup_masque_endpoints();

        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept incoming");
            let connection = incoming.await.expect("connection");
            let proxy = MasqueProxy::accept(connection).await.expect("proxy accept");

            proxy.send_datagram(b"proxy-to-client").expect("send datagram");

            (server_endpoint, proxy)
        });

        let connection = client_endpoint
            .connect(server_addr, TEST_SERVER_NAME)
            .expect("connect")
            .await
            .expect("connection");

        let client = MasqueClient::connect(connection).await.expect("masque connect");
        let payload = client.recv_datagram().await.expect("recv datagram");
        assert_eq!(payload, b"proxy-to-client");

        let (_server_endpoint, _proxy) = server_handle.await.expect("server task");
    }

    // -----------------------------------------------------------------------
    // T-9: Bidirectional datagram echo through MASQUE tunnel
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn bidirectional_datagram_echo() {
        let (server_endpoint, client_endpoint, server_addr) = setup_masque_endpoints();

        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept incoming");
            let connection = incoming.await.expect("connection");
            let proxy = MasqueProxy::accept(connection).await.expect("proxy accept");

            // Echo: receive from client, send back
            let payload = proxy.recv_datagram().await.expect("recv datagram");
            proxy.send_datagram(&payload).expect("send echo");

            (server_endpoint, proxy)
        });

        let connection = client_endpoint
            .connect(server_addr, TEST_SERVER_NAME)
            .expect("connect")
            .await
            .expect("connection");

        let client = MasqueClient::connect(connection).await.expect("masque connect");

        // Client sends, then receives echo
        let original = b"echo-me-please";
        client.send_datagram(original).expect("send datagram");
        let echoed = client.recv_datagram().await.expect("recv echo");
        assert_eq!(echoed, original);

        let (_server_endpoint, _proxy) = server_handle.await.expect("server task");
    }

    // -----------------------------------------------------------------------
    // T-10: High-throughput: 1000 datagrams through tunnel
    // -----------------------------------------------------------------------

    const HIGH_THROUGHPUT_COUNT: usize = 1_000;

    #[tokio::test]
    async fn high_throughput_datagram_stream() {
        let (server_endpoint, client_endpoint, server_addr) = setup_masque_endpoints();

        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept incoming");
            let connection = incoming.await.expect("connection");
            let proxy = MasqueProxy::accept(connection).await.expect("proxy accept");

            // Receive all datagrams and echo them back
            for _ in 0..HIGH_THROUGHPUT_COUNT {
                let payload = proxy.recv_datagram().await.expect("recv datagram");
                proxy.send_datagram(&payload).expect("send echo");
            }

            (server_endpoint, proxy)
        });

        let connection = client_endpoint
            .connect(server_addr, TEST_SERVER_NAME)
            .expect("connect")
            .await
            .expect("connection");

        let client = MasqueClient::connect(connection).await.expect("masque connect");

        // Send and receive datagrams one at a time (sequential for reliability)
        for i in 0..HIGH_THROUGHPUT_COUNT {
            let msg = format!("datagram-{i}");
            client.send_datagram(msg.as_bytes()).expect("send datagram");
            let echoed = client.recv_datagram().await.expect("recv echo");
            assert_eq!(echoed, msg.as_bytes(), "mismatch at datagram {i}");
        }

        let (_server_endpoint, _proxy) = server_handle.await.expect("server task");
    }
}
