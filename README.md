# prrr

**Censorship-resistant VPN protocol.**

prrr combines post-quantum cryptography, traffic obfuscation, and pluggable transports (HARP over HTTPS and MASQUE over QUIC) to provide a VPN that is indistinguishable from regular web traffic. It resists deep packet inspection, active probing, and traffic analysis attacks while maintaining high throughput on standard port 443.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-edition%202024-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/Tests-1006%20passing-brightgreen.svg)](#testing)

---

## Features

- **Post-Quantum Security** -- Hybrid X25519 + ML-KEM-768 key exchange protects against both classical and quantum attacks.
- **Traffic Obfuscation** -- TLS fingerprint mimicry (Chrome/Firefox profiles), adaptive padding, and timing jitter make VPN traffic indistinguishable from regular HTTPS.
- **Active Probing Resistance** -- HMAC-BLAKE2s token authentication with decoy responses prevents server fingerprinting.
- **HARP Transport** -- Tunnels over HTTPS/WebSocket on TCP port 443, indistinguishable from regular web traffic and resistant to UDP blocking.
- **MASQUE/QUIC Transport (Default)** -- Alternative transport over HTTP/3 on UDP port 443 for environments where QUIC performs better.
- **Web Admin Panel** -- Single-page application for server management, client provisioning, and real-time monitoring.
- **Client Distribution** -- QR codes, shareable URLs, and TOML config export for easy client onboarding.
- **Diagnostics** -- Built-in `doctor` command checks configuration, keys, connectivity, and system resources.
- **One-Click Deployment** -- Installation scripts for Ubuntu/Debian/Fedora and a Terraform module for DigitalOcean.
- **Zero Unsafe Code** -- `#![deny(unsafe_code)]` enforced project-wide.

---

## Quick Start

### Server

```bash
# Option 1: Installation script (Ubuntu/Debian/Fedora)
curl -fsSL https://install.prrr.dev/server | sudo bash

# Option 2: Build from source
cargo install --path .
prrr server --listen 0.0.0.0:443 --server-name vpn.example.com
```

### Register a Client

```bash
prrr server --config /etc/prrr/server.toml client add my-laptop
# Outputs: name, IP address, public key, private key
# SAVE THE PRIVATE KEY -- it is shown only once.

prrr server --config /etc/prrr/server.toml client export my-laptop > my-laptop.toml
```

### Client

```bash
# Save the private key from the "client add" output
mkdir -p ~/.local/share/prrr/keys
echo -n "THE_PRIVATE_KEY_BASE64" | base64 -d > ~/.local/share/prrr/keys/client.key
chmod 600 ~/.local/share/prrr/keys/client.key
echo -e "\nprivate_key_path = \"$HOME/.local/share/prrr/keys/client.key\"" >> my-laptop.toml

# Import and connect
prrr client import my-laptop.toml
sudo $(which prrr) client --config ~/.config/prrr/client.toml
```

See [Getting Started](docs/getting-started.md) for a complete walkthrough with troubleshooting.

---

## Architecture

```text
Application (IP packets from TUN device)
     |
TunnelPipeline: TUN <-> encrypt <-> transport
     |
EncryptedChannel: ChaCha20-Poly1305 + replay protection
     |
     ├── HARP (default): 4-byte frame header + WebSocket/HTTP polling
     │        |
     │   TLS 1.3: indistinguishable from HTTPS
     │        |
     │   TCP/IP: standard port 443 traffic
     │
     └── MASQUE (legacy): HTTP Datagram framing
              |
         QUIC DATAGRAMs: quinn native datagram API
              |
         TLS 1.3 (ALPN=h3): indistinguishable from HTTP/3
              |
         UDP/IP: standard port 443 traffic
```

### Cryptographic Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key Exchange | X25519 + ML-KEM-768 | Hybrid classical + post-quantum |
| Handshake | Noise IK | Mutual authentication |
| Packet Encryption | ChaCha20-Poly1305 | AEAD with replay protection |
| Key Derivation | HKDF-BLAKE2s | Session key derivation |
| Probing Resistance | HMAC-BLAKE2s | Token-based authentication |

See [Architecture Overview](docs/overview.md) for a detailed breakdown.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, first connection, troubleshooting |
| [Architecture Overview](docs/overview.md) | System design, concepts, glossary |
| [Configuration Reference](docs/configuration.md) | All config options with defaults |
| [CLI Reference](docs/cli.md) | Commands, flags, and usage examples |
| [REST API Reference](docs/api.md) | Web admin endpoints and authentication |
| [Cryptography](docs/crypto.md) | Primitives, key derivation, hybrid KEX |
| [Handshake Protocol](docs/handshake.md) | Noise IK, hybrid handshake flow |
| [Transport Layer](docs/transport.md) | QUIC, MASQUE framing, encrypted channels |
| [Obfuscation](docs/obfuscation.md) | TLS mimicry, padding, probe resistance |
| [Tunneling](docs/tunnel.md) | TUN device abstraction, packet pipeline |
| [Security](docs/security.md) | Threat model, key zeroization, fuzzing |

---

## Building from Source

**Prerequisites:** Rust 1.85+ (edition 2024), Git

```bash
git clone https://github.com/prrr-vpn/prrr.git
cd prrr
cargo build --release
```

The binary is at `target/release/prrr`.

---

## Android App

The Prrr Android app is in `prrr-android/`. Building requires the Android NDK and Rust cross-compilation targets.

### Prerequisites

```bash
# Install Android NDK via SDK Manager or https://developer.android.com/ndk/downloads
# Install Rust cross-compilation targets
rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi i686-linux-android
```

### Building

```bash
# Full build: compile Rust native library + Gradle APK
make android-debug

# Install on connected device
make android-install

# Gradle-only build (skip native rebuild when only editing Kotlin)
make android-debug-apk

# Release build
make android-release
```

Set `NDK_HOME` if auto-detection fails:

```bash
NDK_HOME=/path/to/ndk make android-debug
```

---

## Testing

prrr has 1,000+ tests covering the full protocol stack, including end-to-end data flow tests that verify packets traverse the complete encrypted pipeline across both HARP and MASQUE transports.

```bash
make test          # Run all tests
make lint          # Clippy + format check
make bench         # Performance benchmarks
make shellcheck    # Lint installation scripts
make android-test  # Android unit tests
```

Coverage targets: 90% for critical paths, 85% overall.

---

## Deployment

### Installation Scripts

```bash
# Server (requires root)
curl -fsSL https://install.prrr.dev/server | sudo bash -s -- \
  --admin-pass "your-password" \
  --domain vpn.example.com

# Client
curl -fsSL https://install.prrr.dev/client | bash
```

Supported: Ubuntu 22.04+, Debian 11+, Fedora 38+. See [docs/getting-started.md](docs/getting-started.md).

### Terraform (DigitalOcean)

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit with your DigitalOcean token and SSH key
terraform init && terraform apply
```

See [deploy/terraform/README.md](deploy/terraform/README.md) for details.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the PR process.

---

## License

prrr is released under the [MIT License](LICENSE).
