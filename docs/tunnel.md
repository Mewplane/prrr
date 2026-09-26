# Tunnel Module

The `prrr::tunnel` module provides IP tunneling: a TUN device abstraction,
mock implementation for testing, and a packet pipeline that wires
TUN ↔ EncryptedChannel ↔ Transport for bidirectional VPN traffic.

The transport layer is pluggable via the `DatagramSender`/`DatagramReceiver`
traits. Currently two transports exist:

- **MASQUE** — UDP-based framing over QUIC, low latency for unblocked networks
- **HARP** — HTTPS API Relay Protocol, frames VPN packets over
  standard HTTP/1.1 and HTTP/2 via WebSocket or HTTP polling, making
  traffic indistinguishable from normal HTTPS web browsing

Both transports coexist as first-class options behind a pluggable transport
abstraction layer (see [Transport Abstraction Layer](#transport-abstraction-layer) below).

## Routing & local-LAN auto-exclusion

When the tunnel comes up, prrr decides which destination prefixes to route into
the tunnel and which to leave on the local link. By **default** it excludes the
active interface's RFC1918 local-LAN subnet (split-tunnel courtesy), so a device
on the same LAN stays reachable instead of being swallowed by the full tunnel.

The prefix computation lives in the vendor-neutral core (`prrr::routing`) as the
single source of truth for both platforms:

- `InterfaceEnumerator` — trait wrapping interface discovery; `SystemInterfaceEnumerator`
  is the production implementation (`if-addrs`), and tests inject fixtures.
- `lan_prefixes_to_exclude(interfaces, skip)` — pure, IO-free function returning
  the RFC1918 network prefixes to exclude (IPv6/malformed/non-RFC1918 skipped,
  deduplicated, tunnel subnet honored via `skip`).
- `compute_excluded_ips(user_excluded, interfaces, skip, full_tunnel)` — merges the
  user's `excluded_ips` with the auto-detected LAN prefixes unless `full_tunnel`.

**Linux:** `main.rs` feeds the computed set into `RouteParams.excluded_ips`, written
to `/run/prrr/env` as `PRRR_EXCLUDED_IPS` for the routing hook, so no tunnel route
is installed for the LAN prefix.

**Android:** `prrr-mobile::lan_excluded_cidrs(full_tunnel)` is exported over UniFFI;
`PrrrVpnService` calls it and applies `VpnService.Builder.excludeRoute()` for each
returned CIDR, so the route set omits the LAN prefix.

Set `[routing].full_tunnel = true` to restore strict full-tunnel capture of the
LAN (see [Configuration](configuration.md#routing)).

### Selected resource routes

When `[routing].resources` is non-empty, the Linux client resolves each
hostname before the tunnel route is activated. It writes the deduplicated IPv4
answers to `PRRR_RESOURCE_IPS` in `/run/prrr/env`. The routing hook installs
those addresses as exact `/32` routes in the fwmark policy table and removes
them during teardown. In resource-only mode the same policy rule is used
without a default route, so non-resource traffic continues through the host's
normal route.

Resolution is intentionally fail-closed: a hostname that cannot resolve to an
IPv4 address prevents client startup. DNS changes require a client restart.
IPv6 is outside this feature until the client TUN supports IPv6.

## Modules

### `tunnel::tun_device` — TUN Device Abstraction

Defines the [`TunDevice`] trait and [`TunConfig`] for creating TUN interfaces.
Production code uses `SystemTun` (Linux, requires `CAP_NET_ADMIN`), while
tests use [`MockTun`] with channel-based packet injection.

#### TunDevice Trait

```rust
pub trait TunDevice: Send + Sync {
    fn name(&self) -> &str;
    fn mtu(&self) -> u16;
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
}
```

The trait uses `&self` (not `&mut self`) to allow concurrent read/write
from separate async tasks. This is safe because TUN devices support
concurrent reads and writes at the OS level.

#### TunConfig

```rust
use prrr::tunnel::TunConfig;
use std::net::Ipv4Addr;

let config = TunConfig::new(Ipv4Addr::new(10, 0, 0, 1))
    .with_name("prrr0".to_string())
    .with_netmask(Ipv4Addr::new(255, 255, 255, 0))
    .with_mtu(1280);
```

**Types:**
- `TunConfig` — Configuration for creating a TUN device.
- `TunDevice` — Async trait for reading/writing IP packets.

**Constants:**
- `DEFAULT_TUNNEL_MTU = 1280` — Safe default (IPv6 minimum, works everywhere).
- `MIN_TUNNEL_MTU = 1280` — Minimum allowed MTU.
- `MAX_TUNNEL_MTU = 1420` — Maximum allowed MTU (Ethernet - VPN overhead).
- `DEFAULT_TUN_NAME = "prrr0"` — Default device name.

### `tunnel::mock_tun` — Mock TUN for Testing

Channel-based mock TUN device that enables testing without root privileges.
Packets are injected via `MockTunHandle::inject_packet()` and captured via
`MockTunHandle::capture_packet()`.

#### Usage

```rust
use prrr::tunnel::{MockTun, MockTunHandle};
use prrr::tunnel::tun_device::DEFAULT_TUNNEL_MTU;

let (tun, handle) = MockTun::new(DEFAULT_TUNNEL_MTU);

// Inject a packet (simulates an IP packet arriving at the interface)
handle.inject_packet(b"ip-packet-data").await.unwrap();

// Read it from the TUN device
let mut buf = vec![0u8; 1500];
let n = tun.recv(&mut buf).await.unwrap();
assert_eq!(&buf[..n], b"ip-packet-data");

// Send a packet through the TUN (VPN writing to interface)
tun.send(b"outgoing-packet").await.unwrap();

// Capture it from the handle
let captured = handle.capture_packet().await.unwrap();
assert_eq!(captured, b"outgoing-packet");
```

**Types:**
- `MockTun` — Mock TUN device implementing `TunDevice`.
- `MockTunHandle` — Test handle for packet injection/capture.

**Functions:**
- `MockTun::new(mtu) -> (MockTun, MockTunHandle)` — Create paired mock device and handle.
- `MockTunHandle::inject_packet(data) -> Result<()>` — Inject a packet into the mock TUN.
- `MockTunHandle::capture_packet() -> Option<Vec<u8>>` — Capture a packet from the mock TUN.

### `tunnel::pipeline` — Packet Pipeline

Bidirectional pipeline: TUN ↔ EncryptedChannel ↔ MASQUE.

Two concurrent loops:
- **Inbound**: TUN recv → `EncryptedChannel::send` → `DatagramSender::send_datagram`
- **Outbound**: `DatagramReceiver::recv_datagram` → `EncryptedChannel::recv` → TUN send

#### Usage

```rust
use prrr::tunnel::pipeline::{TunnelPipeline, TrafficStats, DatagramSender, DatagramReceiver};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

// let stats = Arc::new(TrafficStats::new());
// let pipeline = TunnelPipeline::new(tun_device, encrypted_channel, masque_sender, masque_receiver, stats);
// let cancel = CancellationToken::new();
// pipeline.run(cancel).await?;
```

#### MTU Enforcement

Packets exceeding the TUN device's MTU are dropped with a warning log.
This prevents oversized packets from entering the encryption pipeline.

#### Cancellation

Pass a `CancellationToken` to `run()`. When cancelled, both pipeline halves
stop and `TunnelError::Cancelled` is returned.

**Types:**
- `TunnelPipeline<T, S, R>` — Bidirectional packet pipeline.
- `DatagramSender` — Trait for sending datagrams (implemented by `MasqueClient`/`MasqueProxy`).
- `DatagramReceiver` — Trait for receiving datagrams (implemented by `MasqueClient`/`MasqueProxy`).

**Functions:**
- `TrafficStats` — Atomic byte counters (`bytes_sent`, `bytes_received`) for lock-free tunnel instrumentation.
- `TunnelPipeline::new(tun, channel, sender, receiver, stats)` — Create pipeline with traffic stats.
- `TunnelPipeline::run(cancel) -> Result<(), TunnelError>` — Run until cancelled or error.

## HARP Frame Codec

The `transport::harp` module provides the binary framing layer for HARP.
Each frame has a minimal 4-byte header followed by a variable-length payload:

```text
Byte 0:     [Version (4 bits)] [Type (4 bits)]
Byte 1:     Reserved (0x00)
Bytes 2-3:  Payload Length (16 bits, big-endian)
Bytes 4+:   Payload (0..65535 bytes)
```

### Frame Types

| Type | Value | Payload | Purpose |
|------|-------|---------|---------|
| DATA | 0x0 | Encrypted tunnel packet | VPN traffic |
| KEEPALIVE | 0x1 | Empty | Cover traffic, connection keep-alive |
| CLOSE | 0x2 | Empty or reason bytes | Session teardown |

### API

```rust
use prrr::transport::harp::{HarpFrame, HarpFrameReader};

// Encode a DATA frame
let frame = HarpFrame::data(encrypted_payload);
let wire_bytes = frame.encode()?;

// Decode a frame from a buffer
let (decoded, bytes_consumed) = HarpFrame::decode(&wire_bytes)?;

// Stream reader for TCP segments
let mut reader = HarpFrameReader::new();
reader.push(&partial_data);
while let Some(result) = reader.next_frame() {
    let frame = result?;
    // process frame
}
```

### Constants

- `HARP_VERSION = 0x1` — Protocol version
- `HARP_HEADER_LEN = 4` — Fixed header size in bytes
- `HARP_MAX_PAYLOAD_LEN = 65535` — Maximum payload size

## Transport Abstraction Layer

The `transport::traits` module defines the pluggable transport abstraction
that decouples the VPN core from specific transport implementations.

### Core Traits

**`ClientTransport`** — Client-side transport interface:
```rust
pub trait ClientTransport: Send + Sync {
    fn name(&self) -> &str;
    fn connect<'a>(
        &'a self,
        params: ClientConnectParams<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<TransportConnection>> + Send + 'a>>;
}
```

**`ServerTransport`** — Server-side transport interface:
```rust
pub trait ServerTransport: Send + Sync {
    fn name(&self) -> &str;
    fn run(
        &self,
        shared: Arc<SharedServerState>,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}
```

### Key Types

| Type | Purpose |
|------|---------|
| `ClientConnectParams<'a>` | Borrows noise keypair, server keys, and cancellation token |
| `TransportConnection` | Returned by `connect()`: boxed sender + receiver + session keys |
| `SharedServerState` | Registry, keypairs, active connections, max clients, gateway IP |
| `BoxedDatagramSender` | Dyn-compatible version of `DatagramSender` |
| `BoxedDatagramReceiver` | Dyn-compatible version of `DatagramReceiver` |

### Dyn-Compatibility Bridge

The existing `DatagramSender`/`DatagramReceiver` traits use `impl Future`
returns and are not dyn-compatible. The transport abstraction provides:

1. **`BoxedDatagramSender`/`BoxedDatagramReceiver`** — Dyn-safe equivalents
   that return `Pin<Box<dyn Future>>`.
2. **Blanket impls** — Any `DatagramSender` automatically implements
   `BoxedDatagramSender` (and same for receivers).
3. **Reverse adapters** — `Box<dyn BoxedDatagramSender>` implements
   `DatagramSender`, allowing `TransportConnection` to be used with
   `TunnelPipeline`.

### Design Decisions

- **`TunFactory` excluded from `SharedServerState`**: The `TunFactory` trait
  has associated types and is not dyn-compatible. Each `ServerTransport`
  receives its factory at construction time.
- **No `async_trait` dependency**: Dyn-compatible async methods use manually
  written `Pin<Box<dyn Future>>` returns.
- **Both transports coexist**: MASQUE and HARP run concurrently on the same
  server, sharing the same `SharedServerState`.

### MASQUE Transport Adapters (Step 11)

The existing QUIC/MASQUE code is wrapped behind the transport traits via
thin adapter types:

- **`MasqueClientTransport`** (`src/client.rs`) — Implements `ClientTransport`.
  `connect()` creates a QUIC endpoint, establishes a MASQUE tunnel, performs
  the hybrid handshake, and returns a `TransportConnection` with
  `Arc<MasqueClient>` as both sender and receiver.

- **`MasqueServerTransport<F: TunFactory>`** (`src/server.rs`) — Implements
  `ServerTransport`. `run()` delegates to `run_multi_server()`, sharing
  the `Arc<tokio::sync::Mutex<ClientRegistry>>` from `SharedServerState`
  with other transports and the web admin.

The `main.rs` client dispatch uses `HarpClientTransport` for the default
`"harp"` transport, running the generic pipeline flow:
```
transport.connect(params) → EncryptedChannel → TunnelPipeline::run()
```

### HARP Transport Adapters (Step 12)

The HARP client and server code is wrapped behind the same transport traits:

- **`HarpClientTransport`** (`src/client.rs`) — Implements `ClientTransport`.
  `connect()` builds an HTTP client, establishes a HARP session via
  `establish_harp_session()`, then attempts a WebSocket connection. On
  WebSocket success it returns `HarpWsSender`/`HarpWsReceiver`; on failure
  it falls back to `HarpPollSender`/`HarpPollReceiver`. The caller sees
  only a `TransportConnection` regardless of wire transport.

- **`HarpServerTransport<F: TunFactory>`** (`src/web/harp.rs`) — Implements
  `ServerTransport`. `run()` constructs an `AppState` from the shared
  `SharedServerState` (using stub values for admin-only fields like JWT
  secret and password hash), creates a `DefaultHarpTunnelSpawner`, and
  delegates to `run_web_server()`.

Both adapters share the unified client dispatch in `main.rs`:
```rust
let transport: Box<dyn ClientTransport> = match protocol {
    "harp" => Box::new(HarpClientTransport::new(...)),
    _      => Box::new(MasqueClientTransport::new(...)),
};
let tun = Arc::new(tun);
// Reconnection loop handles transport failures automatically
prrr::reconnect::run_with_reconnect(
    transport.as_ref(), &noise_keypair, &server_noise_pub, &server_kem_pub,
    tun, &reconnect_config, cancel,
).await
```

### Client Reconnection (Step 15)

The `reconnect` module provides transport-agnostic automatic reconnection.
When a transport connection drops, the client re-establishes a new session
(new handshake, new keys) with exponential backoff and jitter.

**Key behaviors:**

- **TUN persistence**: The TUN device is wrapped in `Arc` and persists
  across reconnections. The client's IP address does not change.
- **Exponential backoff**: Starts at `reconnect_backoff_ms` (default 1000ms),
  doubles on each consecutive failure, caps at `reconnect_max_backoff_ms`
  (default 30000ms).
- **Jitter**: Each backoff delay has +-25% jitter applied via
  `compute_jitter()` for traffic analysis resistance.
- **Reset on success**: Backoff resets to initial after a successful connect.
- **Cancellation-aware**: The loop exits cleanly when the cancellation
  token is triggered, whether during connect, pipeline run, or backoff wait.

**Configuration** (in client `[transport]` section):
```toml
[transport]
reconnect_backoff_ms = 1000       # Initial backoff (default)
reconnect_max_backoff_ms = 30000  # Max backoff (default)
```

## HARP WebSocket Streaming Transport

The `web::harp` module provides a WebSocket-based streaming transport for
HARP sessions. After session establishment (see [API docs](api.md)), the
client connects via `GET /api/v1/harp/stream/{session_id}` with a WebSocket
upgrade. The server bridges the WebSocket to the session's frame channels.

### Connection Flow

```text
Client                          Server
  |  HTTP GET /api/v1/harp/     |
  |  stream/{session_id}        |
  |  Connection: Upgrade        |
  |  Upgrade: websocket         |
  |  ─────────────────────────→ |
  |                             |  Look up session in HarpSessionStore
  |  101 Switching Protocols    |
  |  ←───────────────────────── |
  |                             |
  |  WS Binary (HARP frame)    |
  |  ←─────────────────────────→|  Bidirectional frame bridge
  |                             |
  |  WS Close                  |
  |  ─────────────────────────→ |  Session removed from store
```

### Bridge Architecture

The server runs a single `tokio::select!` loop per connection:

- **Server → Client**: reads from `session.to_client_rx`, sends as WS `Binary`
- **Client → Server**: reads WS `Binary` messages, forwards to `session.from_client_tx`
- Both directions call `session.touch()` on every frame
- On close/error from either side, the session is removed from the store

### URL Encoding

Session IDs in transport endpoint paths use **URL-safe base64** (no padding)
to avoid `/`, `+`, and `=` characters that would break URL path matching.
The `session_id` field in JSON responses uses standard base64.

## HARP Polling Transport (Fallback)

When WebSocket is unavailable (blocked by intermediaries, stripped upgrade
headers), the client falls back to HTTP polling. Both transports reuse the
same `HarpSession` channel infrastructure — only the wire transport differs.

### Server Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/harp/upload/{session_id}` | POST | Client uploads HARP frames |
| `/api/v1/harp/download/{session_id}` | POST | Client downloads queued frames |

### Upload Flow

```text
Client                                        Server
  |  POST /api/v1/harp/upload/{session_id}     |
  |  Body: [HARP Frame 1][Frame 2]...          |
  |  ─────────────────────────────────────────→ |
  |                                             |  Decode frames via HarpFrameReader
  |                                             |  DATA → forward to from_client_tx
  |                                             |  KEEPALIVE → skip
  |                                             |  CLOSE → remove session
  |  200 OK                                     |
  |  Body: [piggybacked download frames]        |
  |  ←───────────────────────────────────────── |
```

### Piggyback Optimization

The upload handler returns any queued download frames in the response body.
This halves the number of HTTP round-trips when there is bidirectional
traffic, since the client gets download data without a separate request.

### Client Polling Adapters

**HarpPollSender** (`DatagramSender`):
- Encodes payloads as HARP DATA frames
- Buffers in an mpsc channel
- Background task drains buffer, POSTs to upload endpoint at jittered intervals
- Parses upload response for piggybacked download frames

**HarpPollReceiver** (`DatagramReceiver`):
- Background task POSTs to download endpoint at jittered intervals
- Also receives piggybacked frames from upload responses
- Decodes HARP frames: DATA → return payload, KEEPALIVE → skip, CLOSE → error

### Jitter

All polling intervals use `compute_jitter(poll_interval_ms)` from the
`obfuscation::traffic_morph` module for traffic analysis resistance.
Default poll interval: 100ms.

### Client Fallback

In `run_harp_client()`, after session establishment:
1. Attempt WebSocket connection
2. On WS failure: log warning, create polling adapters instead
3. Pipeline runs identically with either transport

## HARP Pipeline Bridge

The `transport::harp` module also provides `HarpSender` and `HarpReceiver`
adapter types that implement the `DatagramSender` and `DatagramReceiver`
traits. This allows `TunnelPipeline` to use HARP sessions without any
changes to the pipeline itself — the same generic pipeline that works with
MASQUE also works with HARP.

### HarpSender

Wraps an `mpsc::Sender<Vec<u8>>` (the session's `to_client_tx` channel).
When the pipeline calls `send_datagram(payload)`:

1. Encodes payload as a HARP DATA frame via `HarpFrame::data(payload).encode()`
2. Sends wire bytes via `tx.try_send()` (non-blocking, required because `DatagramSender::send_datagram` is synchronous)
3. Returns `TransportError::HarpChannelClosed` if the channel is closed or full

### HarpReceiver

Wraps an `Arc<TokioMutex<mpsc::Receiver<Vec<u8>>>>` (the session's `from_client_rx` channel).
When the pipeline calls `recv_datagram()`:

1. Reads raw bytes from `rx.recv().await`
2. Decodes HARP frame via `HarpFrame::decode()`
3. For **DATA** frames: returns the payload to the pipeline
4. For **KEEPALIVE** frames: silently skips and reads next frame
5. For **CLOSE** frames: returns `TransportError::HarpSessionClosed`
6. Channel closed: returns `TransportError::HarpChannelClosed`

### Pipeline Integration

```text
TUN Device ──recv──→ EncryptedChannel::send ──→ HarpSender::send_datagram ──→ HARP session channel
                                                                                      │
TUN Device ←──send── EncryptedChannel::recv ←── HarpReceiver::recv_datagram ←─────────┘
```

The bridge is transparent to the pipeline — it sees only encrypted payloads,
never HARP framing details.

## HARP Tunnel Orchestration

The `web::harp` module includes server-side tunnel orchestration that
automatically starts a full VPN pipeline when a client completes session
establishment. This is the HARP equivalent of `handle_client()` in the
legacy QUIC code path.

### Architecture

```text
Client                                Server
  |                                      |
  |-- POST /harp/session (handshake) --> |
  |<-- 200 { session_id, noise_msg2 } --|
  |                                      |
  |                     [create_session creates HarpSession]
  |                     [HarpTunnelSpawner spawns pipeline]
  |                                      |
  |-- WS /harp/stream/{id} -----------> |
  |                                      |
  |<======= WS bridge ================> |
  |  WS binary <-> to_client/from_client |
  |                channels              |
  |                    |                 |
  |                HarpSender/Receiver   |
  |                    |                 |
  |              EncryptedChannel        |
  |                    |                 |
  |               TUN device (prrr0)     |
  |                    |                 |
  |              IP forwarding/NAT       |
```

### HarpTunnelSpawner Trait

The orchestration uses a trait-based design for type erasure:

```rust
pub trait HarpTunnelSpawner: Send + Sync {
    fn spawn(&self, params: HarpTunnelParams) -> bool;
}
```

`HarpTunnelParams` bundles all state needed to start a tunnel: session,
session keys, client record, registry, active connections counter,
cancellation token, and gateway IP.

The concrete `DefaultHarpTunnelSpawner<F: TunFactory>` implementation:

1. Checks `active_connections < max_clients` (returns `false` if at capacity)
2. Creates a per-client TUN device via `TunFactory`
3. Builds `EncryptedChannel::new(rx_key, tx_key)` (keys swapped for server)
4. Creates `HarpSender` + `HarpReceiver` from session channels
5. Spawns `TunnelPipeline` in a background task
6. On pipeline exit: updates traffic stats, logs disconnect event

### ActiveClientGuard

An RAII guard that decrements the `active_connections` counter on drop,
ensuring the counter stays accurate even if the pipeline task panics.

### Max Clients Enforcement

When the server is at capacity (`active_connections >= max_clients`), the
tunnel spawn is rejected but the session response still looks valid
(probe resistance). The orphaned session is cleaned up by the idle timeout.

## Client HARP Transport

The `client` module provides the client-side HARP connection flow via
`run_harp_client()`. This replaces the QUIC/MASQUE `run_client()` when
`transport.protocol = "harp"` in the client configuration.

### Connection Flow

```text
Client                                    Server
  |                                         |
  |  [1] HybridInitiator::new()             |
  |       → (initiator, noise_msg1)         |
  |                                         |
  |  [2] POST /api/v1/harp/session          |
  |       { noise_msg1, capabilities }      |
  |  ────────────────────────────────────→  |
  |                                         |
  |  [3] 200 OK                             |
  |       { session_id, noise_msg2 }        |
  |  ←────────────────────────────────────  |
  |                                         |
  |  [4] initiator.finish(noise_msg2)       |
  |       → SessionKeys                    |
  |  [5] EncryptedChannel::new(tx, rx)      |
  |                                         |
  |  [6] WS wss://.../harp/stream/{id}      |
  |  ════════════════════════════════════   |
  |       WS Binary ←→ HARP frames         |
  |                                         |
  |  [7] TunnelPipeline::run()              |
  |       TUN ↔ Encrypt ↔ WS               |
```

### Client WebSocket Adapters

The client uses different adapters than the server:

**HarpWsSender** wraps a WebSocket write half via an internal mpsc channel
and a background tokio task. When `send_datagram(payload)` is called:

1. Encodes payload as HARP DATA frame
2. Sends wire bytes to the mpsc channel (non-blocking `try_send`)
3. Background task drains the channel and writes to the WS sink

This pattern bridges the synchronous `DatagramSender` trait to the async
WebSocket API.

**HarpWsReceiver** wraps a WebSocket read half via the `WsStreamRead` trait
and a `HarpFrameReader` for buffered frame decoding. When `recv_datagram()`
is called:

1. Reads the next WS binary message
2. Pushes raw bytes to `HarpFrameReader`
3. Decodes HARP frame: DATA → return payload, KEEPALIVE → skip, CLOSE → error

The `WsStreamRead` trait abstracts over the WS read half, enabling unit
tests with mock streams without requiring a real WebSocket connection.

### Transport Dispatch

In `main.rs`, the client command checks `transport.protocol`:

- `"harp"` (default) → uses `HarpClientTransport`
- `"masque"` → uses `MasqueClientTransport` (QUIC/MASQUE)

### TLS Configuration

Both the HTTP POST (via `reqwest`) and WebSocket (via `tokio-tungstenite`)
use rustls for TLS. The `--insecure` flag enables `InsecureCertVerifier`
to skip certificate verification (useful for self-signed certs during
development/testing).

## Error Handling

```rust
use prrr::tunnel::TunnelError;

match result {
    Err(TunnelError::TunIo(e)) => { /* TUN device I/O error */ }
    Err(TunnelError::Transport(e)) => { /* encryption/decryption error */ }
    Err(TunnelError::PacketTooLarge { size, mtu }) => { /* oversized packet */ }
    Err(TunnelError::Cancelled) => { /* pipeline was cancelled */ }
    Ok(()) => { /* clean shutdown */ }
}
```

## Architecture

### Packet Flow

```text
                    Inbound (TUN → Network)
TUN Device ──recv──→ EncryptedChannel::send ──→ MASQUE send_datagram ──→ QUIC
                                                                           │
                    Outbound (Network → TUN)                               │
TUN Device ←──send── EncryptedChannel::recv ←── MASQUE recv_datagram ←────┘
```

### Full Protocol Stack

```text
Application (IP packets from TUN device)
     ↓
TunnelPipeline (F-008): TUN ↔ encrypt ↔ MASQUE
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

## Security Notes

- Packets are encrypted with ChaCha20-Poly1305 before leaving the pipeline.
- Replay protection via sliding-window bitmap (inherited from EncryptedChannel).
- MTU enforcement prevents amplification attacks via oversized packets.
- No `unsafe` code (`#![deny(unsafe_code)]`).
- `tokio-tun` contains 1 unavoidable `unsafe` block (libc FFI for `/dev/net/tun`).
- MockTun enables full testing without root or real network access.

## Testing Strategy

All tests use `MockTun` and run without root privileges:

- **Unit tests**: TunConfig, MockTun inject/capture, name/mtu accessors
- **Integration tests**: Inbound pipeline, outbound pipeline, bidirectional, cancellation
- **Throughput tests**: 100 packets through paired pipelines
- **Edge cases**: Oversized packets dropped, closed channels error correctly
