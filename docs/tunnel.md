# Tunnel Module

The `prrr::tunnel` module provides IP tunneling: a TUN device abstraction,
mock implementation for testing, and a packet pipeline that wires
TUN ↔ EncryptedChannel ↔ MASQUE for bidirectional VPN traffic.

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
