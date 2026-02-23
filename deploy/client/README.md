# prrr Podman E2E Testing

End-to-end VPN tunnel testing using Podman containers with real TUN devices.

## Prerequisites

- **Podman** >= 4.0 (`podman --version`)
- **Linux kernel** with TUN/TAP support (`ls /dev/net/tun`)
- **Rust toolchain** >= 1.85 (for building inside the container)

## Quick Start

From the project root:

```bash
# Build image and run full E2E test (both transports)
make podman-e2e

# Run individual transports
make podman-e2e-masque    # MASQUE/QUIC only
make podman-e2e-harp      # HARP/HTTP+WebSocket only
make podman-e2e-multi     # Both transports sequentially

# Build image only
make podman-build

# Run E2E with pre-built image (skip rebuild)
PRRR_SKIP_BUILD=1 ./deploy/client/run-podman.sh

# Run E2E with specific transport
PRRR_TRANSPORT=harp ./deploy/client/run-podman.sh
```

## Architecture

The E2E test uses a Podman **pod** with shared networking:

```text
+-- prrr-e2e-pod (shared localhost) -----+
|                                         |
|  +-----------+      +-----------+       |
|  |  server   |      |  client   |       |
|  |           | QUIC  |           |       |
|  | TUN prrr0 |<====>| TUN prrr0 |       |
|  | 10.66.66.1|  443 | 10.66.66.2|       |
|  +-----------+      +-----------+       |
|                                         |
|  Shared volume: /shared                 |
|    server-ready (marker file)           |
|    client.toml (exported config)        |
+-----------------------------------------+
```

1. **Server** starts, generates keys, registers a test client, exports config
2. **Client** reads config from shared volume, connects via QUIC with `--insecure`
3. **Connectivity test**: bidirectional ping through VPN tunnel

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PRRR_IMAGE_NAME` | `prrr-e2e` | Container image name |
| `PRRR_IMAGE_TAG` | `latest` | Container image tag |
| `PRRR_POD_NAME` | `prrr-e2e-pod` | Pod name |
| `PRRR_SUBNET` | `10.66.66.0/24` | VPN subnet CIDR |
| `PRRR_LISTEN_PORT` | `443` | Server listen port |
| `PRRR_LOG_LEVEL` | `debug` | Log level for both server and client |
| `PRRR_STARTUP_WAIT` | `15` | Seconds to wait for server readiness |
| `PRRR_CLIENT_WAIT` | `30` | Seconds to wait for client tunnel |
| `PRRR_TEST_TIMEOUT` | `10` | Seconds for ping test timeout |
| `PRRR_SKIP_BUILD` | `0` | Set to `1` to skip image rebuild |
| `PRRR_TRANSPORT` | `harp` | Client transport: `harp` or `masque` |

## Container Capabilities

Both containers require:

- `--cap-add=NET_ADMIN` for TUN device creation and routing
- `--device=/dev/net/tun` for access to the TUN character device

## Troubleshooting

### "Permission denied" creating TUN device

Ensure you have `/dev/net/tun` available and the container has `NET_ADMIN`:

```bash
ls -la /dev/net/tun
podman run --cap-add=NET_ADMIN --device=/dev/net/tun ...
```

### Build fails downloading crates

Check network connectivity inside the builder container:

```bash
podman run --rm docker.io/rust:1.85-bookworm curl -s https://crates.io/
```

### Client fails to connect

Check server logs first:

```bash
podman logs prrr-e2e-pod-server
```

Then client logs:

```bash
podman logs prrr-e2e-pod-client
```

### Cleanup stale resources

```bash
podman pod rm -f prrr-e2e-pod
podman volume rm prrr-e2e-pod-shared
podman rmi prrr-e2e:latest
```
