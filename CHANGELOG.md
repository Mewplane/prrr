# Changelog

All notable changes to prrr are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- **Split mode no longer asks the tunnel to resolve every name on the host**
  (specs/bugs/BUG-split-mode-dns-catchall-hijacks-host-resolver.md). The hook
  advertised the tunnel resolver with `resolvectl domain prrr0 "~."`, so while a
  degraded tunnel held the gate open, unrelated names (`github.com`, `apt`, SSH)
  hung on a resolver whose path did not carry their traffic either. Split mode
  now advertises only the resource domains (`~chatgpt.com ~t.me …`) published as
  `PRRR_RESOURCE_DOMAINS`, and a full tunnel keeps `~.` because it really does
  carry everything. Binaries that do not publish the variable keep the old
  catch-all behaviour.

### Removed

- **Whisper integrated messaging** (`feat/remove-messaging`). The built-in
  end-to-end encrypted messaging layer — PQXDH key agreement, double ratchet
  with SPQR, store-and-forward relay, and the messaging client — is removed
  (`src/messaging/`, 8 modules). Nothing in the runtime ever referenced it: no
  CLI subcommand started it, the server never spawned the relay, and the mobile
  apps never called it, so it was library-only surface. Also removed: the
  dormant `[messaging]` server and client config sections and their defaults,
  the `messaging_benchmarks` bench, the three messaging fuzz targets
  (`fuzz_wire_message`, `fuzz_message_header`, `fuzz_encrypted_envelope`), and
  the messaging documentation. The wire format, handshake, transports, tunnel,
  admin panel, and mobile APIs are unchanged. Existing config files that still
  contain a `[messaging]` section keep working — unknown TOML fields are
  silently ignored.

### Fixed

- **A slow DNS round froze the whole tunnel**
  (specs/bugs/BUG-pipeline-refresh-starves-packet-pump.md). The reconnect loop
  `await`ed resource re-resolution — a blocking `getaddrinfo` over every
  hostname resource — inside the same `select!` that polls the packet pump, the
  black-hole watchdog and the DNS gate, so a stalled resolver stopped all three.
  Observed as `prrr0` counting zero packets across 300 successful sends, a
  3-minute gap on a 60-second refresh ticker, a dead tunnel that never logged
  `black-holing` because its detector could not run, and a DNS verdict frozen
  for minutes. Resolution now runs on its own task behind a 20-second budget and
  reports through a channel; a verdict nobody refreshes expires on a 45-second
  lease and hands resolution back to the host's resolver.

- **Resource routing had no effect on systemd-service clients**
  (specs/bugs/BUG-resource-routing-not-effective.md). Three stacked defects:
  the deployed `/usr/local/bin/prrr-route` hook consumed the space-separated
  `PRRR_RESOURCE_IPS` with `read <<< "$var"`, producing one malformed route and
  aborting under `set -e`; the hook never ensured the TUN link is up; and no
  install path updated the binary + hook the service actually runs
  (`make install` targets `~/.cargo/bin`).
- `deploy/client/entrypoint.sh`: SC2064 trap-expansion warning.
- `deploy/client/install-client.sh`: prefer the fresh repo build over
  `command -v prrr` (sudo `secure_path` could pick a stale binary and abort
  with "are the same file" when it is hardlinked to the install target).
- **The tunnel could degrade into a silent one-way black hole**
  (specs/bugs/BUG-network-manager-tun-address-loss.md). NetworkManager adopted
  `prrr0` and a later profile deactivation flushed its IPv4 address while the
  client still owned the device fd; the kernel then sourced injected packets
  from a LAN address, the server's subnet-scoped masquerade rule stopped
  matching them, and nothing ever came back — while `prrr-route` kept reporting
  `routing is UP`. Fixed on three levels: the hook re-asserts the tunnel address
  on every `up` (self-healing within one 60 s refresh cycle), keeps
  NetworkManager off the device, and the client now detects the data-plane
  signature (`BlackHoleDetector`: outbound progress with no inbound answer for
  15 s) and reconnects instead of hanging forever.
- **Advertised DNS could starve host resolution.** `[interface].dns` is pinned
  through the tunnel and handed to the system resolver, so when that path died
  every lookup on the host hung with it. The client now probes the pinned server
  every 15 s and withdraws the advertisement while it does not answer
  (`PRRR_DNS_GATE=off`), re-advertising automatically on recovery. The `/32`
  pins stay in both gate states so the probe always measures the tunnel.

### Added

- `[routing].resources` selective resource routing: config-driven hostnames
  resolved to `/32` VPN routes, with `prrr client ... route add|remove|list`
  CLI (specs/frds/FRD-resource-routing.md).
- `make install-system`: installs the client the way `prrr-client.service`
  runs it (`/usr/local/bin/prrr` + `/usr/local/bin/prrr-route`).
- `PRRR_ENV_FILE` override in the route hook for black-box testing; hook tests
  now execute the script against stub `ip`/`resolvectl` instead of grep.
- `make shellcheck` covers `deploy/client/install-client.sh` and
  `deploy/client/prrr-route`.
- `deploy/client/nm-unmanaged.sh`: writes
  `/etc/NetworkManager/conf.d/99-prrr-unmanaged.conf`
  (`unmanaged-devices+=interface-name:prrr*`) so NetworkManager never adopts a
  prrr TUN; `deploy/client/install-client.sh` installs it and reloads NetworkManager
  config. Scoped to `prrr*`, so unrelated tunnels are untouched.
- **One silent resolver address closed tunnel DNS for the whole client**
  (specs/bugs/BUG-tunnel-dns-single-probe-target.md). The liveness gate asked
  only the first `[interface].dns` address. On the operator's host `1.1.1.1`
  never answered UDP/53 through the tunnel (TCP/53 did, and `8.8.8.8` answered
  both), so the gate stayed shut, the host fell back to its uncensored LAN
  resolver, resource refreshes failed with `Temporary failure in name
  resolution`, and pushes failed with `Could not resolve host`. The gate now
  opens on any responder that answers and advertises only those; addresses the
  IPv4-only probe cannot measure (IPv6, names) are never withdrawn.
- `prrr::dns_probe`: single-question DNS liveness probe (RFC 1035 query, any
  RCODE counts as an answer) used to gate tunnel DNS.
- `PRRR_DNS_GATE=on|off` in the routing env file, plus `deploy/client/prrr-route`
  `apply_dns_policy` honouring it; `PRRR_ENV_FILE` fixtures extended to cover
  NetworkManager, address re-assertion, and the gate in black-box tests.
- `make shellcheck` covers `deploy/client/nm-unmanaged.sh`.

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
