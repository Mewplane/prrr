# prrr

<img src="assets/logo_app.png" width="180" alt="prrr pixel cat carrying a gold key">

An encrypted VPN tunnel with a hybrid Noise IK + ML-KEM-768 handshake and a choice of HTTPS-based HARP or QUIC-based MASQUE transports. prrr includes Linux routing/recovery, an Android companion, client provisioning, and web administration.

[Documentation](https://mewplane.github.io/prrr/) · [Animated mechanics](https://mewplane.github.io/prrr/explanation/mechanics/) · [Security boundaries](https://mewplane.github.io/prrr/explanation/security/) · [Source](https://github.com/Mewplane/prrr)

## Install

Build the current source with a toolchain compatible with `Cargo.lock`:

```sh
git clone https://github.com/Mewplane/prrr.git
cd prrr
cargo build --locked --release --bin prrr
target/release/prrr --help
```

Linux clients need TUN support and privileges for socket marks and routing. The documented service uses systemd. Servers need their selected TCP/UDP endpoint, a matching trusted TLS certificate, forwarding, and NAT configured by their administrator.

For a service installation, first [provision a complete client configuration](https://mewplane.github.io/prrr/how-to/provision-client/), then run:

```sh
sudo ./deploy/client/install-client.sh ./my-laptop.toml
sudo systemctl start prrr-client
```

The service runs `/usr/local/bin/prrr` with `/usr/local/bin/prrr-route`; `cargo install` into `~/.cargo/bin` does not update those paths. See [installation](https://mewplane.github.io/prrr/how-to/install/) for server setup and service updates.

## Use

Configure transports explicitly on both ends. An implicit server transport resolves to HARP, while an unqualified client and provisioning fallback use MASQUE. Generated configuration records the selected transport; avoid relying on conflicting defaults.

On a configured server:

```sh
umask 077
sudo prrr server --config /etc/prrr/server.toml \
  --listen 0.0.0.0:443 --server-name vpn.example.net \
  client add my-laptop > my-laptop.toml
```

Replace the example domain with your real server name. The first output includes the client private key; transfer it privately and save it securely. Later exports do not recover that key.

For inspection and diagnostics:

```sh
prrr client --config /etc/prrr/client.toml doctor
prrr client --config /etc/prrr/client.toml route list
sudo prrr server --config /etc/prrr/server.toml client list
```

Follow [your first tunnel](https://mewplane.github.io/prrr/tutorials/first-tunnel/) to select a routing policy, verify real packet egress, and disconnect cleanly.

## Documentation

The [browsable documentation](https://mewplane.github.io/prrr/) uses prrr's cat/key artwork and includes three illustrated walkthroughs with **22 chapters**:

- **Handshake:** pinned identities, outer transport, Noise IK and ML-KEM exchange, authorization, and directional session keys.
- **Packets:** TUN capture, counter/ciphertext/tag anatomy, HARP or MASQUE framing, forwarding, replies, and replay rejection.
- **Routing and recovery:** resource routes, server/LAN bypasses, DNS gating, black-hole detection, backoff, and a fresh session on the same TUN.

Animations support Play/Pause, Previous/Next, chapter seeking, speed selection, keyboard access, reduced motion, mobile portrait layouts, and complete text transcripts.

| Need | Guide |
| --- | --- |
| Connect one client | [First tunnel tutorial](docs/tutorials/first-tunnel.md) |
| Set up the components | [Install](docs/how-to/install.md), [provision](docs/how-to/provision-client.md), [Android](docs/how-to/android.md) |
| Diagnose the path | [Recover a connection](docs/how-to/recover.md) |
| Look up exact behavior | [CLI](docs/reference/cli.md), [configuration](docs/reference/configuration.md), [protocol](docs/reference/protocol.md), [admin API](docs/reference/api.md) |
| Understand the boundaries | [Mechanics](docs/explanation/mechanics.md), [security](docs/explanation/security.md), [glossary](docs/reference/glossary.md) |

The canonical guides pin their source observations to the inspected revision. Older flat documentation remains in the repository as historical material.

## Security expectations

Tunnel encryption does not hide the server address, packet timing, or volume. Browser-like TLS profiles are approximate; HTTPS carriage does not prove indistinguishability from a browser. The VPN server is a trust boundary, and normal application HTTPS remains useful beyond it.

Routing and DNS recovery can restore ordinary host egress when the tunnel fails. This is not a kill switch or proof of IPv6 capture. Keep the separate HTTP admin listener private or behind a controlled TLS proxy. Read the [security guide](https://mewplane.github.io/prrr/explanation/security/) before deployment.

## Development and contributing

```sh
make test
make lint
make shellcheck
python3 scripts/docs-examples-check.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [documentation development](docs/contributing/documentation.md). Open an [issue](https://github.com/Mewplane/prrr/issues) with reproduction steps and sanitized diagnostics, or a pull request with the relevant tests. Keep private keys, client TOML, QR credentials, and unreviewed logs out of reports.

For Android, `make android-debug` builds the native library and debug app; `make android-debug-apk` builds only the Kotlin app and requires a current native library. See [the Android guide](docs/how-to/android.md).

## Maintainers

Maintained by [Mewplane](https://github.com/Mewplane) and contributors.

## License

[MIT](LICENSE).
