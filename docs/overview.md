# Architecture Overview

This document describes the architecture of prrr, its core concepts, and how the components fit together.

## Design Goals

prrr is designed around three principles:

1. **Indistinguishable from HTTPS** -- VPN traffic tunnels through HARP over TCP port 443 (default) or MASQUE/QUIC over UDP port 443, making it look like regular web browsing to network observers and DPI systems.
2. **Post-quantum security** -- Hybrid X25519 + ML-KEM-768 key exchange protects sessions against both classical and future quantum attacks.
3. **Operational simplicity** -- A single binary handles server, client, key management, diagnostics, and administration.

## System Architecture

```text
                    +-----------+
                    |  Web Admin|  (optional, port 8443)
                    |  REST API |
                    +-----+-----+
                          |
+--------+          +-----+-----+          +--------+
| Client | <------> |   Server  | <------> | Client |
| (prrr) |  HARP/   |   (prrr)  |  HARP/   | (prrr) |
+--------+  443/TCP +-----+-----+  443/TCP +--------+
            (or MASQUE    |        (or MASQUE
             443/UDP)     |         443/UDP)
                    +-----+-----+
                    |  Registry |  (SQLite)
                    +-----------+
```

Each client maintains an independent connection to the server via HARP (HTTPS/WebSocket, default) or MASQUE (QUIC). The server spawns a per-client task that owns its own TUN device, encrypted channel, and transport tunnel.

## Protocol Stack

Traffic flows through layered encryption and framing. The transport layer
is pluggable -- HARP is the default, MASQUE is available as an alternative.

### HARP Transport (Default)

HARP (HTTPS API Relay Protocol) is the default transport. It tunnels
encrypted VPN packets over standard HTTPS using WebSocket streaming or
HTTP polling. Since HTTPS/TCP cannot be blocked without breaking the web,
HARP is highly resistant to DPI-based protocol blocking.

```text
Application (IP packets from TUN device)
     |
TunnelPipeline: TUN <-> encrypt <-> HARP
     |
EncryptedChannel: ChaCha20-Poly1305 + replay protection
     |
HARP framing: 4-byte header [version | type | length] + payload
     |
WebSocket (streaming) or HTTP POST/GET (polling)
     |
TLS 1.3: indistinguishable from HTTPS
     |
TCP/IP: standard port 443 traffic
```

HARP uses a minimal 4-byte frame header (version, type, payload length)
to encapsulate `EncryptedChannel` output. The frame codec lives in
`transport::harp`. See `docs/tunnel.md` for the frame format details.

### MASQUE Transport (Legacy)

MASQUE (RFC 9297/9298) is a standard HTTP/3 mechanism for proxying UDP
traffic. It remains available for environments where UDP/QUIC performs
better than TCP/HTTPS.

```text
Application (IP packets from TUN device)
     |
TunnelPipeline: TUN <-> encrypt <-> MASQUE
     |
EncryptedChannel: ChaCha20-Poly1305 + replay protection
     |
MASQUE framing: HTTP Datagram [Quarter Stream ID | Context ID | payload]
     |
QUIC DATAGRAMs: quinn native datagram API
     |
TLS 1.3 (ALPN=h3): indistinguishable from HTTP/3
     |
UDP/IP: standard port 443 traffic
```

> **Note:** MASQUE/QUIC is available as an alternative transport but is no
> longer the default. QUIC (UDP) is increasingly blocked by DPI systems,
> so HARP (TCP/HTTPS) is preferred for most deployments.

## Module Map

The codebase is organized into focused modules:

| Module | Responsibility |
|--------|---------------|
| `config` | CLI parsing (clap) and TOML configuration |
| `server` | Multi-client VPN server orchestrator |
| `client` | VPN client orchestrator |
| `registry` | Client management and IP allocation (SQLite) |
| `keys` | Persistent server key storage |
| `crypto` | Cryptographic primitives (AEAD, KDF, X25519, hybrid KEX) |
| `handshake` | Noise IK + ML-KEM-768 hybrid handshake |
| `transport` | HARP framing, QUIC (legacy), MASQUE (legacy), encrypted channels |
| `tunnel` | TUN device abstraction and packet pipeline |
| `obfuscation` | TLS mimicry, traffic padding, probe resistance |
| `messaging` | Whisper: PQXDH, double ratchet, relay |
| `web` | REST API, JWT auth, embedded SPA frontend, HARP session management |
| `metrics` | Prometheus metrics and health endpoint |
| `diagnostics` | Server and client diagnostic checks |
| `distribution` | Client config export, QR codes, token URLs |
| `cli` | CLI command handlers |

## Core Concepts

### Hybrid Handshake

Every connection begins with a two-phase handshake:

1. **Noise IK** -- The client sends its static public key encrypted under the server's known public key. This provides mutual authentication and forward secrecy using X25519.
2. **ML-KEM-768 Encapsulation** -- Immediately after Noise IK, the server encapsulates a shared secret using the client's ML-KEM-768 key. The Noise session keys and the KEM shared secret are combined via HKDF to produce the final session keys.

This hybrid approach means an attacker must break both X25519 and ML-KEM-768 to compromise a session.

### Encrypted Channel

After the handshake, a bidirectional `EncryptedChannel` handles all packet encryption:

- **Algorithm:** ChaCha20-Poly1305 (AEAD)
- **Nonce management:** Monotonically increasing 64-bit counter per direction
- **Replay protection:** Sliding window bitmap rejects duplicate or out-of-order nonces
- **Rekeying:** Automatic rekeying after a configurable interval (default: 3600 seconds)

### Tunnel Pipeline

The `TunnelPipeline` bridges the TUN device and the encrypted transport channel with two concurrent loops:

- **Inbound:** TUN device recv -> encrypt -> transport send
- **Outbound:** transport recv -> decrypt -> TUN device send

Each client gets an independent pipeline with its own TUN device and traffic counters. The pipeline is transport-agnostic -- it works identically with HARP or MASQUE via the `DatagramSender`/`DatagramReceiver` traits.

### Client Registry

The registry is a SQLite database that tracks:

- Client identity (UUID, name, X25519 public key, ML-KEM-768 key)
- Network allocation (assigned IP address from the configured subnet)
- State (active, suspended, revoked)
- Activity (last seen timestamp, bytes sent/received)
- Connection history (connect, disconnect, auth failure events)

IP addresses are allocated sequentially from the subnet (skipping network, gateway, and broadcast addresses) and released when a client is revoked.

### Obfuscation

Three obfuscation layers work together:

| Layer | What It Does | Why |
|-------|-------------|-----|
| TLS Mimicry | Reorders cipher suites and KEX groups to match Chrome or Firefox fingerprints | Defeats JA3/JA4 fingerprinting |
| Traffic Morphing | Pads packets, adds timing jitter, injects dummy traffic | Defeats statistical traffic analysis |
| Probe Resistance | HMAC-BLAKE2s cookie authentication with rate limiting and decoy responses | Defeats active probing attacks |

### Whisper Messaging

Whisper provides end-to-end encrypted messaging over the VPN tunnel:

- **Key Agreement:** PQXDH (Post-Quantum Extended Diffie-Hellman) for initial sessions
- **Ratcheting:** Double Ratchet with SPQR (Sparse Post-Quantum Ratchet) for forward secrecy
- **Delivery:** Server-side store-and-forward relay for offline recipients
- **Transport:** Messages are sent as datagrams over the VPN tunnel

## Connection Lifecycle

### HARP (Default)

```text
Client                                          Server
------                                          ------
1. Parse CLI / load config                      1. Parse CLI / load config
2. Init tracing                                 2. Init tracing, start HTTP server
                                                3. Accept connection loop
3. HTTPS POST /session            ---------->   4. Check max_clients limit
4. WebSocket upgrade (or polling) ---------->   5. HARP session established
5. Hybrid handshake (initiator)   <--------->   6. Hybrid handshake (responder)
                                                7. Authenticate client key
6. EncryptedChannel created                     8. EncryptedChannel created
                                                9. Create TUN device
7. TunnelPipeline::run(cancel)    <--------->   10. TunnelPipeline::run(cancel)
8. Signal -> cancel -> shutdown                 11. Persist traffic stats
```

### MASQUE (Legacy)

```text
Client                                          Server
------                                          ------
1. Parse CLI / load config                      1. Parse CLI / load config
2. Init tracing                                 2. Init tracing, bind QUIC
                                                3. Accept connection loop
3. QUIC connect (ALPN=h3)         ---------->   4. Check max_clients limit
4. MASQUE CONNECT-UDP             ---------->   5. MASQUE accept
5. Hybrid handshake (initiator)   <--------->   6. Hybrid handshake (responder)
                                                7. Authenticate client key
6. EncryptedChannel created                     8. EncryptedChannel created
                                                9. Create TUN device
7. TunnelPipeline::run(cancel)    <--------->   10. TunnelPipeline::run(cancel)
8. Signal -> cancel -> shutdown                 11. Persist traffic stats
```

## Web Admin

When enabled, the web admin provides:

- **REST API** at `/api/v1/` -- JWT-authenticated endpoints for server management
- **SPA Frontend** at `/` -- Embedded Preact application (no external dependencies at runtime)
- **Config Distribution** -- Generate client configs, QR codes, and shareable URLs

The SPA is embedded in the binary via `include_str!`, so the web admin works with zero filesystem dependencies.

## Glossary

| Term | Definition |
|------|-----------|
| **AEAD** | Authenticated Encryption with Associated Data (ChaCha20-Poly1305) |
| **DPI** | Deep Packet Inspection -- network-level traffic analysis |
| **HARP** | HTTPS API Relay Protocol — tunnels VPN traffic over standard HTTPS |
| **HKDF** | HMAC-based Key Derivation Function |
| **KEM** | Key Encapsulation Mechanism (ML-KEM-768) |
| **MASQUE** | Multiplexed Application Substrate over QUIC Encryption (RFC 9297) |
| **ML-KEM-768** | Module-Lattice-based Key Encapsulation, NIST standard (formerly Kyber) |
| **MTU** | Maximum Transmission Unit (default: 1280 bytes for tunnel) |
| **Noise IK** | Noise protocol pattern with known initiator and responder keys |
| **PQXDH** | Post-Quantum Extended Diffie-Hellman key agreement |
| **QUIC** | UDP-based transport protocol (RFC 9000) |
| **SNI** | Server Name Indication -- TLS extension identifying the target hostname |
| **SPQR** | Sparse Post-Quantum Ratchet -- periodic KEM ratchet steps in double ratchet |
| **TUN** | Virtual network tunnel device operating at IP layer |
| **Whisper** | prrr's integrated end-to-end encrypted messaging system |
| **X25519** | Elliptic curve Diffie-Hellman on Curve25519 |
