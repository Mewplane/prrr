# Changelog

All notable changes to prrr are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-02-21

Initial release with full protocol stack, production deployment infrastructure, and web administration.

### Added

**Core Protocol**
- Hybrid X25519 + ML-KEM-768 post-quantum key exchange
- Noise IK mutual authentication handshake
- ChaCha20-Poly1305 AEAD packet encryption with replay protection
- MASQUE/QUIC transport (RFC 9297/9298) on UDP port 443
- Bidirectional TUN-based tunnel pipeline with per-client isolation
- Automatic session rekeying (configurable interval, default 3600s)

**Traffic Obfuscation**
- TLS fingerprint mimicry (Chrome, Firefox profiles)
- Adaptive packet padding (power-of-two, http-sizes, fixed-mtu strategies)
- Timing jitter injection
- Dummy traffic generation
- Active probing resistance with HMAC-BLAKE2s cookie authentication
- Decoy HTTP responses for unauthorized probes

**Whisper Messaging**
- PQXDH initial key agreement
- Double Ratchet with Sparse Post-Quantum Ratchet (SPQR)
- Server-side store-and-forward message relay
- Configurable message size limits and retention

**Server**
- Multi-client VPN server with concurrent connection handling
- SQLite-backed client registry with IP allocation from configurable subnet
- Per-client traffic counters (bytes sent/received)
- Connection history logging (connect, disconnect, auth failure events)
- Persistent X25519 and ML-KEM-768 key storage with rotation support
- Configurable max client limit with graceful rejection
- TOML configuration with 8 sections and 30+ options
- Environment variable and CLI flag overrides

**Client**
- TOML-based client configuration with server key resolution
- Config import from file path or `prrr://import?config=<base64>` URL
- Ephemeral or persistent client keypairs
- Graceful shutdown on SIGINT/SIGTERM

**Web Administration**
- REST API at `/api/v1/` with JWT authentication (Argon2id password hashing)
- Server status, configuration, and statistics endpoints
- Client CRUD with suspend/resume lifecycle
- Client config distribution: TOML export, SVG QR codes, time-limited token URLs
- Embedded Preact SPA frontend (single HTML file, no build step)
- Dark theme with auto-refreshing dashboard

**Monitoring**
- Prometheus metrics endpoint (`/metrics`) with client and handshake gauges/counters
- Health check endpoint (`/health`) with version and uptime
- Structured JSON log output with configurable rotation and retention

**Diagnostics**
- `prrr server doctor`: config validation, key integrity, port availability, disk space, memory, stale clients
- `prrr client doctor`: key presence, config validation, server reachability
- Colored terminal output with exit codes (0=pass, 1=warn, 2=fail)

**Deployment**
- Server installation script (Ubuntu 22.04+, Debian 11+, Fedora 38+)
- Client installation script
- Systemd service with security hardening
- Firewall auto-configuration (UFW, firewalld)
- Terraform module for DigitalOcean (droplet, firewall, DNS)
- Cloud-init bootstrap template

**Quality**
- 582 tests (unit, integration, end-to-end data flow)
- Zero unsafe code (`#![deny(unsafe_code)]`)
- Zero clippy warnings
- Benchmarks for crypto, handshake, transport, and messaging
