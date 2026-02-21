# Architecture Overview

This document describes the architecture of prrr, its core concepts, and how the components fit together.

## Design Goals

prrr is designed around three principles:

1. **Indistinguishable from HTTPS** -- All VPN traffic tunnels through MASQUE/QUIC on UDP port 443, making it look like regular HTTP/3 web browsing to network observers and DPI systems.
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
| (prrr) |  QUIC/   |   (prrr)  |  QUIC/   | (prrr) |
+--------+  443/UDP +-----+-----+  443/UDP +--------+
                          |
                    +-----+-----+
                    |  Registry |  (SQLite)
                    +-----------+
```

Each client maintains an independent QUIC connection to the server. The server spawns a per-client task that owns its own TUN device, encrypted channel, and MASQUE tunnel.

## Protocol Stack

Traffic flows through six layers, each adding a specific capability:

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

### Why MASQUE?

MASQUE (RFC 9297/9298) is a standard HTTP/3 mechanism for proxying UDP traffic. By framing VPN packets as MASQUE datagrams, prrr traffic is structurally identical to HTTP/3 web traffic. DPI systems cannot distinguish prrr from a browser loading a website over QUIC.

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
| `transport` | QUIC, MASQUE framing, encrypted channels |
| `tunnel` | TUN device abstraction and packet pipeline |
| `obfuscation` | TLS mimicry, traffic padding, probe resistance |
| `messaging` | Whisper: PQXDH, double ratchet, relay |
| `web` | REST API, JWT auth, embedded SPA frontend |
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

The `TunnelPipeline` bridges the TUN device and the encrypted MASQUE channel with two concurrent loops:

- **Inbound:** TUN device recv -> encrypt -> MASQUE send_datagram
- **Outbound:** MASQUE recv_datagram -> decrypt -> TUN device send

Each client gets an independent pipeline with its own TUN device and traffic counters.

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
