# Transport Module

The `prrr::transport` module provides encrypted packet transport for post-handshake communication.

## Modules

### `transport::encrypted_channel` — Encrypted Bidirectional Channel

ChaCha20-Poly1305 encrypted channel with automatic nonce management, replay
protection, and rekeying. Built on `crypto::aead` (F-001) and designed to
consume `SessionKeys` from the hybrid handshake (F-004).

#### Usage

```rust
use prrr::transport::encrypted_channel::EncryptedChannel;

// After hybrid handshake, both sides have SessionKeys
// Initiator uses tx_key for sending, rx_key for receiving
let mut initiator = EncryptedChannel::new(
    session_keys.tx_key,
    session_keys.rx_key,
);

// Responder swaps: rx_key for sending (since initiator's tx = responder's rx)
let mut responder = EncryptedChannel::new(
    session_keys.rx_key,
    session_keys.tx_key,
);

// Initiator sends
let wire = initiator.send(b"hello responder").unwrap();
let plaintext = responder.recv(&wire).unwrap();
assert_eq!(plaintext, b"hello responder");

// Responder sends
let wire = responder.send(b"hello initiator").unwrap();
let plaintext = initiator.recv(&wire).unwrap();
assert_eq!(plaintext, b"hello initiator");
```

#### Wire Format

Each encrypted packet has the following structure:

```text
[8-byte nonce counter (big-endian)] [encrypted payload] [16-byte auth tag]
```

- **Nonce counter** (8 bytes): Monotonically increasing 64-bit counter, encoded
  big-endian. Also used as AAD for AEAD authentication.
- **Encrypted payload**: ChaCha20-Poly1305 ciphertext (same length as plaintext).
- **Auth tag** (16 bytes): Poly1305 authentication tag.

Minimum packet size: 24 bytes (8-byte counter + 16-byte tag, empty payload).

#### Nonce Strategy

The 8-byte counter is zero-padded to 12 bytes for the ChaCha20-Poly1305 nonce:

```text
[0x00 0x00 0x00 0x00] [8-byte big-endian counter]
 ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^
 4 bytes zero padding   8-byte counter
```

Each direction (tx/rx) maintains its own counter. The counter starts at 0
and increments by 1 for each packet sent.

#### Automatic Rekeying

When the tx nonce counter reaches the configured threshold (default 2^32),
a new key is derived and the counter resets to 0:

```text
new_key = HKDF-SHA256(salt=current_key, ikm="prrr-rekey-v1")
```

The wire format uses absolute nonce counters (including rekey epochs), so
the receiver can independently derive the correct key for any received packet.

The rekey threshold is configurable via `EncryptedChannel::with_config()`.

#### Replay Protection

A sliding-window bitmap tracks received nonces:

- Nonces up to 64 positions behind the highest seen nonce are tracked (configurable).
- Duplicate nonces within the window are rejected as replays.
- Nonces older than the window are rejected.
- Out-of-order packets within the window are accepted.

Window size is configurable via `EncryptedChannel::with_config()`.

#### Custom Configuration

```rust
use prrr::transport::encrypted_channel::EncryptedChannel;

let mut channel = EncryptedChannel::with_config(
    tx_key,
    rx_key,
    1024,  // rekey every 1024 packets
    128,   // replay window of 128 packets
);
```

**Types:**
- `EncryptedChannel` — Bidirectional encrypted transport channel.

**Functions:**
- `EncryptedChannel::new(tx_key, rx_key)` — Create with default settings (rekey at 2^32, window 64).
- `EncryptedChannel::with_config(tx_key, rx_key, rekey_threshold, replay_window)` — Create with custom settings.
- `send(plaintext) -> Result<Vec<u8>, TransportError>` — Encrypt and produce wire bytes.
- `recv(wire_bytes) -> Result<Vec<u8>, TransportError>` — Decrypt wire bytes to plaintext.
- `tx_counter() -> u64` — Current transmit nonce counter.
- `tx_rekey_count() -> u64` — Number of rekeys performed on the tx side.

**Constants:**
- `NONCE_COUNTER_LEN = 8` — Wire format nonce counter size.
- `MIN_PACKET_LEN = 24` — Minimum valid packet (counter + tag).
- `DEFAULT_REKEY_THRESHOLD = 4294967296` — Default rekey at 2^32 packets.
- `DEFAULT_REPLAY_WINDOW_SIZE = 64` — Default replay window.

### `transport::tls` — Shared TLS Certificate Verification

Internal module providing shared TLS certificate verification for all
QUIC/MASQUE client connections. Provides `build_cert_verifier(insecure)` which
returns either a production verifier backed by the Mozilla CA root store
(`webpki-roots`), or a dev/test `SkipServerVerification` that accepts any
certificate.

**Types:**
- `SkipServerVerification` — `ServerCertVerifier` that accepts any certificate (dev/test only).

**Functions:**
- `build_cert_verifier(insecure: bool) -> Arc<dyn ServerCertVerifier>` — Build a certificate verifier. When `insecure=false`, verifies against Mozilla CA roots. When `insecure=true`, accepts any certificate.
- `skip_server_verification() -> Arc<dyn ServerCertVerifier>` — Create an Arc-wrapped `SkipServerVerification` (convenience wrapper, equivalent to `build_cert_verifier(true)`).
- `load_pem_cert_and_key(cert_path, key_path) -> Result<(Vec<CertificateDer>, PrivateKeyDer), TransportError>` — Load a PEM certificate chain and private key from disk. Returns the full chain for use with server builders. Errors on missing files, corrupt PEM, or missing key. Uses `rustls-pemfile` for parsing.

**Visibility:** `pub(crate)` — internal to the prrr crate.

### `transport::quic` — QUIC Client & Server

QUIC transport layer using the `quinn` crate (v0.11.9) over TLS 1.3 (via
`rustls` v0.23). Provides thin wrappers around `quinn::Endpoint` for
establishing QUIC connections with bidirectional stream support. At this
layer, streams carry raw bytes — MASQUE framing is added in F-007.

#### Usage

```rust
use prrr::transport::quic::{QuicServer, QuicClient, generate_self_signed_cert};

// Generate a self-signed certificate for dev/test
let (cert, key) = generate_self_signed_cert(vec!["localhost".to_string()]).unwrap();

// Start server
let server = QuicServer::bind("127.0.0.1:0".parse().unwrap(), cert, key).unwrap();
let server_addr = server.local_addr().unwrap();

// Create client (skips cert verification for dev/test)
let client = QuicClient::new_insecure().unwrap();

// Connect and exchange data
// (in async context)
// let conn = client.connect(server_addr, "localhost").await.unwrap();
// let (mut send, mut recv) = conn.open_bi().await.unwrap();
// send.write_all(b"hello").await.unwrap();
// send.finish().await.unwrap();
```

#### Certificate Generation

For dev/test, `generate_self_signed_cert()` creates a self-signed TLS
certificate with the specified Subject Alternative Names:

```rust
use prrr::transport::quic::generate_self_signed_cert;

let (cert_der, key_der) = generate_self_signed_cert(
    vec!["localhost".to_string(), "127.0.0.1".to_string()]
).unwrap();
```

Uses the `rcgen` crate (v0.14) for certificate generation.

**Types:**
- `QuicServer` — QUIC server that listens for incoming connections.
- `QuicClient` — QUIC client endpoint for initiating connections.
- `QuicConnection` — Active QUIC connection with bidirectional stream support.
- `QuicSendStream` — Send side of a QUIC bidirectional stream.
- `QuicRecvStream` — Receive side of a QUIC bidirectional stream.

**Functions:**
- `generate_self_signed_cert(sans) -> Result<(CertificateDer, PrivateKeyDer)>` — Generate self-signed cert.
- `QuicServer::bind(addr, cert, key) -> Result<QuicServer>` — Bind server to address.
- `QuicServer::accept() -> Result<QuicConnection>` — Accept incoming connection.
- `QuicClient::new_insecure() -> Result<QuicClient>` — Create client (skip cert verification).
- `QuicClient::connect(addr, server_name) -> Result<QuicConnection>` — Connect to server.
- `QuicConnection::open_bi() -> Result<(QuicSendStream, QuicRecvStream)>` — Open bidirectional stream.
- `QuicConnection::accept_bi() -> Result<(QuicSendStream, QuicRecvStream)>` — Accept bidirectional stream.
- `QuicSendStream::write_all(data) -> Result<()>` — Write bytes.
- `QuicSendStream::finish() -> Result<()>` — Signal end of stream.
- `QuicRecvStream::read_to_end(max) -> Result<Vec<u8>>` — Read all bytes.
- `QuicRecvStream::read_exact(buf) -> Result<()>` — Read exact number of bytes.

**Constants:**
- `DEFAULT_IDLE_TIMEOUT_MS = 30000` — Default connection idle timeout.
- `DEFAULT_MAX_READ_SIZE = 1048576` — Default max stream read size (1 MiB).

**ALPN:** The protocol uses `"prrr"` as the ALPN identifier.

### `transport::masque` — MASQUE CONNECT-UDP Framing

MASQUE CONNECT-UDP framing (RFC 9297/9298) over QUIC DATAGRAMs. Wraps UDP
datagrams in HTTP Datagram frames so VPN traffic appears as standard HTTP/3
to external observers. Built directly on quinn's native datagram API with
zero additional crate dependencies.

#### Usage

```rust
use prrr::transport::quic::generate_self_signed_cert;
use prrr::transport::masque::{
    MasqueClient, MasqueProxy,
    build_masque_server_config, build_masque_client_config,
};

// Generate cert and build MASQUE-enabled configs (ALPN=h3, datagrams enabled)
let (cert, key) = generate_self_signed_cert(vec!["localhost".to_string()]).unwrap();
let server_config = build_masque_server_config(cert, key).unwrap();
let client_config = build_masque_client_config().unwrap();

// (in async context)
// Server side: accept connection, then accept MASQUE tunnel
// let proxy = MasqueProxy::accept(quic_connection).await.unwrap();
// let payload = proxy.recv_datagram().await.unwrap();
// proxy.send_datagram(&payload).unwrap();

// Client side: connect, then establish MASQUE tunnel
// let client = MasqueClient::connect(quic_connection).await.unwrap();
// client.send_datagram(b"hello").unwrap();
// let reply = client.recv_datagram().await.unwrap();
```

#### Wire Format

Each QUIC DATAGRAM payload contains an HTTP Datagram (RFC 9297):

```text
[Quarter Stream ID (varint)] [Context ID (varint)] [UDP payload]
```

- **Quarter Stream ID**: `request_stream_id / 4` encoded as a QUIC varint.
- **Context ID**: `0` for raw UDP payloads (RFC 9298 §5).
- **UDP payload**: The raw datagram bytes.

The QUIC varint encoding follows RFC 9000 §16 (1/2/4/8 byte variable-length
integers using the 2 MSB as a length prefix).

#### CONNECT-UDP Handshake

The handshake uses a simplified Extended CONNECT exchange on a bidirectional
QUIC stream:

1. Client opens a bidi stream, sends `CONNECT-UDP /tunnel HTTP/3\r\n\r\n`, finishes send side
2. Proxy reads request, sends `HTTP/3 200 OK\r\n\r\n`, finishes send side
3. Both sides exchange datagrams via QUIC DATAGRAMs (unreliable, no HoL blocking)

#### ALPN

MASQUE connections use `h3` as the ALPN protocol identifier, making the TLS
handshake indistinguishable from standard HTTP/3 traffic.

**Types:**
- `MasqueClient` — MASQUE CONNECT-UDP client tunnel endpoint.
- `MasqueProxy` — MASQUE CONNECT-UDP proxy tunnel endpoint.

**Functions:**
- `MasqueClient::connect(connection) -> Result<MasqueClient>` — Establish MASQUE tunnel.
- `MasqueClient::send_datagram(payload) -> Result<()>` — Send UDP datagram through tunnel.
- `MasqueClient::recv_datagram() -> Result<Vec<u8>>` — Receive UDP datagram from tunnel.
- `MasqueClient::max_datagram_size() -> Option<usize>` — Query max payload size.
- `MasqueProxy::accept(connection) -> Result<MasqueProxy>` — Accept MASQUE tunnel.
- `MasqueProxy::send_datagram(payload) -> Result<()>` — Send UDP datagram through tunnel.
- `MasqueProxy::recv_datagram() -> Result<Vec<u8>>` — Receive UDP datagram from tunnel.
- `MasqueProxy::max_datagram_size() -> Option<usize>` — Query max payload size.
- `build_masque_server_config(cert_chain, key, keep_alive, max_idle) -> Result<ServerConfig>` — Server config with ALPN=h3 and datagrams. Accepts a full `Vec<CertificateDer>` certificate chain.
- `build_masque_client_config(keep_alive, max_idle_timeout, insecure) -> Result<ClientConfig>` — Client config with ALPN=h3 and datagrams. When `insecure=false`, verifies server certificates against Mozilla CA roots.
- `datagram_transport_config() -> TransportConfig` — Transport config with datagrams enabled.
- `varint_encode(value, buf) -> Result<usize>` — Encode QUIC varint (RFC 9000 §16).
- `varint_decode(buf) -> Result<(u64, usize)>` — Decode QUIC varint.
- `frame_datagram(stream_id, payload) -> Result<Vec<u8>>` — Frame UDP payload as HTTP Datagram.
- `deframe_datagram(data) -> Result<(u64, u64, Vec<u8>)>` — Deframe HTTP Datagram to extract payload.

**Constants:**
- `ALPN_H3 = b"h3"` — HTTP/3 ALPN identifier.

## Error Handling

All fallible operations return `Result<T, TransportError>`:

```rust
use prrr::transport::TransportError;

match result {
    Err(TransportError::DecryptionFailed) => { /* tampered or wrong key */ }
    Err(TransportError::ReplayDetected(nonce)) => { /* duplicate packet */ }
    Err(TransportError::PacketTooShort { expected, actual }) => { /* truncated */ }
    Err(TransportError::RekeyFailed(msg)) => { /* HKDF failure */ }
    Err(TransportError::QuicConnection(msg)) => { /* QUIC connection error */ }
    Err(TransportError::QuicWrite(msg)) => { /* QUIC stream write error */ }
    Err(TransportError::QuicRead(msg)) => { /* QUIC stream read error */ }
    Err(TransportError::TlsConfig(msg)) => { /* TLS configuration error */ }
    Err(TransportError::BindFailed(msg)) => { /* server bind error */ }
    Err(TransportError::MasqueHandshake(msg)) => { /* MASQUE CONNECT-UDP handshake error */ }
    Err(TransportError::MasqueDatagram(msg)) => { /* MASQUE datagram framing error */ }
    Err(TransportError::VarintDecode(msg)) => { /* QUIC varint decode error */ }
    Err(TransportError::H2Stream(msg)) => { /* HTTP/2 stream error */ }
    Ok(data) => { /* success */ }
}
```

## Security Notes

- Nonce reuse is impossible: monotonic u64 counter per direction, never decrements.
- Replay protection via sliding-window bitmap (standard IPsec/WireGuard approach).
- Rekeying at 2^32 is conservative — well within ChaCha20-Poly1305 safety margin.
- AAD binding: the nonce counter bytes are authenticated as associated data, preventing nonce substitution.
- No `unsafe` code (`#![deny(unsafe_code)]`).
- Delegates encryption to `crypto::aead` (RustCrypto ChaCha20-Poly1305).

## Architecture

### Encrypted Channel Flow

```text
Initiator                          Responder
---------                          ---------
EncryptedChannel::new(tx, rx)      EncryptedChannel::new(rx, tx)
     |                                  |
     | send(plaintext)                  |
     |  → [counter][ciphertext][tag]    |
     |--------------------------------->|
     |                                  | recv(wire)
     |                                  |  → plaintext
     |                                  |
     |  [counter][ciphertext][tag] ←    |
     |<---------------------------------|
     | recv(wire)                       | send(plaintext)
     |  → plaintext                     |
     |                                  |
     |== automatic rekey at 2^32 =======|
```

### MASQUE Tunnel Flow

```text
Client                             Proxy
------                             -----
MasqueClient::connect(conn)        MasqueProxy::accept(conn)
     |                                  |
     | CONNECT-UDP request (bidi stream)|
     |--------------------------------->|
     |                                  |
     |         HTTP/3 200 OK            |
     |<---------------------------------|
     |                                  |
     | send_datagram(udp_payload)       |
     |  → QUIC DATAGRAM:               |
     |    [qstream_id][ctx=0][payload]  |
     |=================================>|
     |                                  | recv_datagram()
     |                                  |  → udp_payload
     |                                  |
     |    [qstream_id][ctx=0][payload]  |
     |<=================================|
     | recv_datagram()                  | send_datagram(udp_payload)
     |  → udp_payload                   |
```

### Full Protocol Stack

```text
Application data (IP packets, messages)
     ↓
EncryptedChannel (F-005): ChaCha20-Poly1305 + replay protection
     ↓
MASQUE framing (F-007): HTTP Datagram [Quarter Stream ID | Context ID | payload]
     ↓
QUIC DATAGRAMs (F-006): quinn native datagram API
     ↓
TLS 1.3 (ALPN=h3): indistinguishable from HTTP/3
     ↓
UDP/IP: standard port 443 traffic
```

### HARP HTTP/2 Transport (Hardening Phase 3, Feature 4)

The HARP transport supports HTTP/2 multiplexed streams as a binding mode alongside
WebSocket (`"stream"`) and HTTP/1.1 polling (`"poll"`). HTTP/2 streams look like
normal browser traffic and have lower latency than polling.

**Server configuration:**

```toml
[[transports]]
name = "harp"
h2_streaming_enabled = true  # Enable HTTP/2 binding (default: true)
```

**Client configuration:**

```toml
[transport]
preferred_binding = "h2"  # "stream" | "poll" | "h2"
```

**Dependencies:** `h2 = "0.4"`, `hyper` with `http2` feature, `bytes = "1"`.

### `transport::h2_adapter` — HTTP/2 Stream Adapters

Bridges `h2::SendStream<Bytes>` and `h2::RecvStream` to prrr's `DatagramSender` /
`DatagramReceiver` traits. Enables HARP frame exchange over HTTP/2 multiplexed
streams with proper flow control management.

**Types:**
- `H2Sender` — Sends HARP DATA frames over an HTTP/2 send stream. Wraps `h2::SendStream<Bytes>` behind `std::sync::Mutex` to satisfy the sync `&self` signature of `DatagramSender`.
- `H2Receiver` — Receives HARP frames from an HTTP/2 receive stream. Wraps `h2::RecvStream` + `HarpFrameReader` behind `tokio::sync::Mutex`. Automatically releases HTTP/2 flow control capacity after consuming each DATA chunk.

**Functions:**
- `H2Sender::new(stream) -> H2Sender` — Create a new sender wrapping an H2 send stream.
- `H2Receiver::new(stream) -> H2Receiver` — Create a new receiver wrapping an H2 receive stream.
- `H2Sender::send_datagram(payload) -> Result<(), TransportError>` — Encode as HARP DATA frame, send via H2.
- `H2Receiver::recv_datagram() -> Result<Vec<u8>, TransportError>` — Receive H2 DATA, decode HARP frame, return payload.

**Frame handling:**
- DATA frames: payload returned to caller
- KEEPALIVE frames: silently skipped
- CLOSE frames: returns `TransportError::HarpSessionClosed`
- H2 stream end: returns `TransportError::HarpChannelClosed`
- H2 errors: returns `TransportError::H2Stream(message)`

### H2 Client Connect Path

The `connect_harp_h2()` function establishes an HTTP/2 connection and opens
upload/download streams, returning `(H2Sender, H2Receiver)` for use with the
tunnel pipeline. This is the client-side counterpart to the server-side H2
streaming handlers (Step 4.4).

**Connection flow:**

```text
Client                                Server
------                                ------
1. DNS resolve host:port
2. Create marked TCP socket (fwmark)
3. TLS handshake (ALPN=["h2"] only)
4. h2::client::handshake(tls_stream)
5. Spawn H2 connection driver
6. POST /api/v1/harp/upload/{sid}    → Upload handler
   (end_of_stream=false)
7. GET /api/v1/harp/download/{sid}   → Download handler
   (end_of_stream=true)
8. Return (H2Sender, H2Receiver)
```

**Binding selection:** When `preferred_binding = "h2"` is configured, the H2
path is selected in both `connect_inner()` (direct) and `connect_via_cdn()`
(CDN fronting) before the WebSocket/polling fallback logic.

**TLS configuration:** `build_harp_h2_rustls_config()` creates a rustls config
with ALPN `["h2"]` only (not `["h2", "http/1.1"]`) to force HTTP/2 negotiation.
Uses the same TLS mimicry profile and certificate verification as other HARP
connections.

**Client capabilities:** `HARP_CLIENT_CAPABILITIES` includes `"h2"` alongside
`"stream"` and `"poll"`, informing the server that the client supports HTTP/2
streaming.

**Functions:**
- `connect_harp_h2(host, port, session_id, insecure, fwmark, profile) -> Result<(H2Sender, H2Receiver)>` — Full H2 connection establishment.
- `build_harp_h2_rustls_config(insecure, profile) -> Result<ClientConfig>` — H2-only TLS config.

**Constants:**
- `HARP_H2_UPLOAD_PATH = "/api/v1/harp/upload/"` — Upload stream endpoint prefix.
- `HARP_H2_DOWNLOAD_PATH = "/api/v1/harp/download/"` — Download stream endpoint prefix.
- `LOG_HARP_H2_STREAMS = "HARP transport: using HTTP/2 streams"` — Log message for H2 binding selection.
- `BINDING_H2 = "h2"` — Preferred binding value for HTTP/2.
- `BINDING_POLL = "poll"` — Preferred binding value for HTTP polling.
