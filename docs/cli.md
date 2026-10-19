# CLI Application

The `prrr` binary provides a VPN client and server that composes all Phase 1
components into a working censorship-resistant tunnel.

## Usage

### Server

```bash
prrr server [OPTIONS]
```

**Options:**

| Flag | Default | Env Var | Description |
|------|---------|---------|-------------|
| `--listen <ADDR>` | `0.0.0.0:443` | `PRRR_LISTEN` | Address to listen on |
| `--log-level <LEVEL>` | `info` | `PRRR_LOG_LEVEL` | Log level (trace, debug, info, warn, error) |
| `--config <PATH>` | — | — | Optional TOML configuration file |
| `--server-name <NAME>` | `localhost` | — | TLS server name (SNI) |

The server:
1. Generates a self-signed TLS certificate (dev/test mode)
2. Binds a QUIC endpoint on the listen address
3. Accepts multiple concurrent client connections (up to `max_clients`)
4. Authenticates each client against the client registry
5. Performs hybrid Noise IK + ML-KEM-768 handshake per client
6. Establishes per-client MASQUE CONNECT-UDP tunnel
7. Runs independent bidirectional packet pipelines

### Server Client Management

```bash
prrr server client add <NAME>
prrr server client list
prrr server client remove <NAME>
prrr server client export <NAME> [--qr] [--output PATH]
```

These subcommands manage the client registry without starting the VPN server.
They load the server config file (via `--config`) to determine data directory
and subnet, then operate directly on the SQLite database.

| Subcommand | Description |
|------------|-------------|
| `add <name>` | Register new client, auto-generate X25519 keypair, allocate IP, print details |
| `list` | Display table of all non-revoked clients (name, IP, status, created) |
| `remove <name>` | Revoke client by name (marks as revoked in registry) |
| `export <name>` | Export client TOML config to stdout |
| `export <name> --qr` | Export client config as SVG QR code |
| `export <name> --output PATH` | Write config or QR to file instead of stdout |

**Examples:**

```bash
# Add a new client
prrr server --config /etc/prrr/server.toml client add alice

# List all clients
prrr server --config /etc/prrr/server.toml client list

# Export client config as QR SVG
prrr server --config /etc/prrr/server.toml client export alice --qr --output alice-qr.svg

# Remove a client
prrr server --config /etc/prrr/server.toml client remove alice

# Run server diagnostics
prrr server doctor
prrr server --config /etc/prrr/server.toml doctor
```

### Server Doctor (P-010)

```bash
prrr server doctor
```

Runs server-side diagnostic checks and reports results with colored output:

| Check | Description |
|-------|-------------|
| Configuration valid | Verifies TOML config parses without errors |
| Keys present and valid | Checks identity key (32 bytes) and PQ key (2400 bytes) exist with correct sizes |
| Port available | Tests UDP bind on configured listen address |
| Disk space sufficient | Checks filesystem usage for data directory (warn >80%, fail >95%) |
| Memory available | Checks system available memory (warn <128MB, fail <64MB) |
| Stale clients | Warns about clients not seen in 30+ days |

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Warnings present (no failures) |
| 2 | At least one check failed |

**Example output:**

```
Running diagnostics...

✓ Configuration valid
✓ Keys present and valid
✓ Port 443/UDP available
✓ Disk space sufficient (42% used)
✓ Memory available (512MB free)
! Warning: 2 clients haven't connected in 30+ days

Recommendations:
  - Remove inactive clients to free IP addresses
```

### Client

```bash
prrr client --server <ADDR> [OPTIONS]
```

**Options:**

| Flag | Default | Env Var | Description |
|------|---------|---------|-------------|
| `--server <ADDR>` | (required) | — | Server address to connect to |
| `--log-level <LEVEL>` | `info` | `PRRR_LOG_LEVEL` | Log level |
| `--config <PATH>` | — | — | Optional TOML configuration file |
| `--server-name <NAME>` | — | — | TLS server name (SNI) — required (CLI or config) |
| `--server-public-key <BASE64>` | — | — | Server Noise IK public key (base64, 32 bytes decoded) |
| `--server-pq-public-key <BASE64>` | — | — | Server ML-KEM-768 public key (base64, 1184 bytes decoded) |

### Client Config Import

```bash
prrr client import <SOURCE>
```

Import a client configuration from a file path or `prrr://import?config=<base64>` URL.
The config is saved to `~/.config/prrr/client.toml`.

**Examples:**

```bash
# Import from a file
prrr client import /tmp/alice.toml

# Import from a prrr:// URL (e.g., decoded from QR code)
prrr client import "prrr://import?config=W2NsaWVudF0KbmFtZSA9..."
```

### Client Doctor (P-010)

```bash
prrr client doctor
prrr client --config /etc/prrr/client.toml doctor
```

Runs client-side diagnostic checks:

| Check | Description |
|-------|-------------|
| Client keys present | Checks private key file exists (passes in ephemeral mode) |
| Configuration valid | Verifies server endpoint is configured |
| Server reachable | UDP probe to server address with 5-second timeout |

Exit codes and colored output follow the same conventions as `prrr server doctor`.

**Example output:**

```
Running diagnostics...

✓ Client keys present (ephemeral mode)
✓ Configuration valid
✗ Server unreachable: connection refused

Recommendations:
  - Check if server is running
  - Verify firewall allows UDP port 443
```

### Selected resource routing

Manage the hostnames routed through the VPN without editing the TOML by hand:

```bash
prrr client --config /etc/prrr/client.toml route add chatgpt.com
prrr client --config /etc/prrr/client.toml route add claude.ai
prrr client --config /etc/prrr/client.toml route add youtube.com
prrr client --config /etc/prrr/client.toml route add telegram.org
prrr client --config /etc/prrr/client.toml route list
prrr client --config /etc/prrr/client.toml route remove youtube.com
```

`route add` is idempotent. `route remove` fails if the hostname is not
configured. The command updates only `[routing].resources` and replaces the
file atomically, preserving unrelated configuration and comments. Restart the
client after changing resources so DNS is resolved again and the new `/32`
routes are installed. Use hostnames, not URLs or wildcard entries; IPv6-only
answers are not supported by the current IPv4 client tunnel.

### Client-to-Client Sharing (FRD-004)

Opt a client into inter-client routing (the ecosystem off-LAN mesh, SPEC §6).
Sharing is **off by default**; it is the single explicit capability switch.

```bash
prrr sharing enable     # opt this client into inter-client routing
prrr sharing disable    # opt out (and drop any learned peer mesh address)
prrr sharing status     # show enabled/disabled + peer mesh address
```

`status` prints the live on-disk state:

```
sharing: enabled
peer mesh address: 100.64.0.2:51820
```

The peer mesh address is `none` until sharing is **established** — i.e. enabled
and the inter-client route confirmed reachable by a probe. Once established it
shows the authorized peer's reachable `host:port`, and `disable` clears it back
to `none`. State is persisted to `$HOME/.config/prrr/sharing.json` (atomic
write; a missing or corrupt file is read as **disabled** — fail-closed). The
running daemon honors this state when deciding whether to accept the inter-client
route, reflects it in the ecosystem descriptor's `flags.client_to_client`, and —
once probed reachable — publishes the address into `flags.mesh_peer_addr` so a
sibling reaches the laptop off-LAN with zero configuration (see
`docs/ecosystem.md`).

**prrr stays the enforcement point.** Sharing also accepts an *authorized remote
enable request* relayed from `sy`/cathouse (SPEC §9.4), but prrr honors it **only**
when (a) the server-side sharing-pair authorization exists and (b) the request
carries a per-use biometric signature that verifies. An unauthorized or unsigned
request is refused with no state change. The local CLI toggle above is always
available regardless of the relay.

### Client Connection Flow

The client:
1. Loads optional config file (if `--config` provided)
2. Resolves server Noise public key: CLI flag > config `[server].public_key` > error
3. Resolves server KEM public key: CLI flag > config `[server].pq_public_key` > error
4. Generates ephemeral client keypair (or loads from `[interface].private_key_path` if configured)
5. Connects to the server via QUIC
6. Performs hybrid Noise IK + ML-KEM-768 handshake
7. Establishes MASQUE CONNECT-UDP tunnel
8. Runs the bidirectional packet pipeline

## Configuration File

An optional TOML configuration file can be loaded with `--config`.

### Server Configuration

The server uses a section-based TOML schema (`ServerConfig`). All sections
and fields are optional — missing values use built-in defaults.

```toml
[server]
listen_addr = "0.0.0.0:443"
max_clients = 100
log_level = "info"
data_dir = "/var/lib/prrr"
server_name = "vpn.example.com"

[network]
subnet = "10.66.66.0/24"
dns_servers = ["1.1.1.1", "8.8.8.8"]
mtu = 1280

[crypto]
identity_key_path = "/etc/prrr/keys/server_identity.key"
pq_key_path = "/etc/prrr/keys/server_pq.key"
rekey_interval = 3600

[transport]
protocol = "masque"
max_idle_timeout = 300
keep_alive = 25

[obfuscation]
enabled = true
padding_strategy = "power-of-two"
timing_jitter_ms = 50
tls_profile = "chrome"

[obfuscation.probe_resist]
enabled = true
psk = ""
tokens_per_second = 20
burst_capacity = 5

[web_admin]
enabled = false
listen_addr = "0.0.0.0:8443"
tls_cert = "/etc/prrr/tls/server.crt"
tls_key = "/etc/prrr/tls/server.key"
admin_password_hash = ""
session_timeout = 3600

[monitoring]
metrics_enabled = false
prometheus_port = 9090
log_file = ""
log_rotation = "daily"
log_retention_days = 7
```

### Client Configuration

The client uses its own section-based TOML schema (`ClientConfigFile`):

```toml
[client]
name = "laptop-fedora"
auto_connect = false
log_level = "info"

[server]
endpoint = "vpn.example.com:443"
public_key = "base64-encoded-x25519-public-key"
pq_public_key = "base64-encoded-mlkem768-public-key"

[interface]
private_key_path = "/home/user/.local/share/prrr/keys/client.key"
pq_private_key_path = "/home/user/.local/share/prrr/keys/client_pq.key"
address = "10.66.66.2/32"
dns = ["1.1.1.1", "8.8.8.8"]
mtu = 1280

[routing]
all_traffic = true
allowed_ips = ["0.0.0.0/0", "::/0"]
excluded_ips = ["192.168.0.0/16"]

[transport]
protocol = "masque"
keep_alive = 25

[obfuscation]
enabled = true

```

Unknown fields in TOML files are silently ignored for forward compatibility.
CLI flags take precedence over config file values.

## Signal Handling

The binary handles graceful shutdown on:
- **SIGINT** (Ctrl+C) — cross-platform
- **SIGTERM** — Unix only (sent by systemd, Docker, Kubernetes)

When a signal is received, the tunnel pipeline is cancelled and all
connections are closed cleanly.

## Logging

Structured logging uses the `tracing` framework with `tracing-subscriber`.

- Default level: `info`
- Override via `--log-level` flag or `PRRR_LOG_LEVEL` env var
- `RUST_LOG` env var is also supported (takes precedence over `--log-level`)

Example with debug logging:

```bash
prrr server --log-level debug
```

Example with RUST_LOG:

```bash
RUST_LOG=prrr=trace prrr server
```

## Modules

### `diagnostics` — Diagnostic Checks (P-010)

- `CheckStatus` — Pass, Warn, Fail enum for check results
- `CheckResult` — single check result with name, status, and message
- `DiagnosticReport` — collection of check results with recommendations
  - `exit_code()` — returns 0 (all pass), 1 (warnings), or 2 (failures)
  - `print_colored()` — ANSI-colored output with ✓/!/✗ symbols
- `run_server_doctor(config, listen_addr)` — run all server diagnostic checks
  - `check_server_config_valid()` — verify TOML config parses
  - `check_server_config_from_path(path)` — validate config file from path
  - `check_keys_present(identity_path, pq_path)` — check key files exist with correct sizes
  - `check_port_available(addr)` — test UDP bind on listen address
  - `check_disk_space(data_dir)` — filesystem usage check (Linux: `df`, other: passthrough)
  - `check_memory()` — system memory check (Linux: `/proc/meminfo`, other: passthrough)
  - `check_stale_clients(subnet, db_path)` — warn about clients not seen in 30+ days
  - `check_tls_cert(tls_cert, tls_key, server_name)` — validate TLS certificate: file existence, PEM parsing, expiry (30-day warn), SAN matching
- `run_client_doctor(config)` — run all client diagnostic checks
  - `check_client_keys(config)` — verify client key files exist (pass in ephemeral mode)
  - `check_client_config(config)` — verify server endpoint is configured
  - `check_server_reachable(endpoint)` — UDP probe with 5-second timeout
  - `check_sni_config(server_name)` — warn on missing, dangerous (`www.google.com`), or invalid SNI
- `parse_meminfo_and_check(content)` — parse `/proc/meminfo` content for memory check

### `cli` — CLI Command Handlers (P-009B)

- `handle_server_client_action(registry, action, config, args)` — dispatch server client subcommands
- `handle_client_add(registry, name)` — generate keypair, register client, print details
- `handle_client_list(registry)` — format and print client table
- `handle_client_remove(registry, name)` — revoke client by name
- `handle_client_export(registry, ctx, name, qr, output)` — export TOML config or QR SVG
- `handle_client_import(source)` — import config from file path or `prrr://import` URL
- `import_config_to(source, config_dir)` — testable inner function for import
- `build_server_context(config, args)` — load KeyStore to build `ServerContext` for exports

### `config` — CLI Argument Parsing & Configuration

- `Cli` — top-level clap parser with `server` and `client` subcommands
- `ServerArgs` — server-specific arguments, with optional `ServerSubcommand`
- `ClientArgs` — client-specific arguments (includes `--server-public-key` and `--server-pq-public-key`), with optional `ClientSubcommand`
- `ServerSubcommand::Client(ServerClientArgs)` — nested client management subcommands
- `ServerSubcommand::Doctor` — run server diagnostic checks (P-010)
- `ServerClientAction` — `Add`, `List`, `Remove`, `Export` variants
- `ClientSubcommand::Import { source }` — import config from file or URL
- `ClientSubcommand::Doctor` — run client diagnostic checks (P-010)
- `ServerConfig` — full server TOML configuration (8 nested sections)
- `ClientConfigFile` — full client TOML configuration (7 nested sections)
- `load_server_config(path)` — load and parse server config file
- `load_client_config(path)` — load and parse client config file
- `resolve_server_noise_key(cli_flag, config_value)` — decode base64 Noise public key (32 bytes)
- `resolve_server_kem_key(cli_flag, config_value)` — decode base64 KEM public key (1184 bytes)
- `init_tracing(level)` — initialize tracing subscriber
- 27 named default constants matching SPEC.md values

### `keys` — Persistent Key Management

- `KeyStore` — owns Noise IK (X25519) and ML-KEM-768 keypairs
- `KeyStore::load_or_generate(identity_path, pq_path)` — load from disk or generate + save
- `KeyStore::save(identity_path, pq_path)` — write 4 files (private + public for each key type)
- `KeyStore::rotate(identity_path, pq_path)` — backup old keys (`.bak`), generate new
- `KeyStore::generate()` — generate fresh keypairs without persisting
- `KeyStore::into_parts()` — consume store, return `(noise_ik::KeyPair, KemKeyPair)`
- `noise_public_key_base64()` / `kem_public_key_base64()` — base64-encoded public keys
- Private key files: 0600 permissions (Unix), raw bytes
- Public key files: `.pub` suffix, raw bytes

### `registry` — Client Registry & IP Allocation

- `ClientRegistry::new(subnet_cidr)` — create empty registry for a CIDR subnet (e.g. `"10.66.66.0/24"`)
- `add(name, public_key, pq_public_key)` — register client, allocate next IP from subnet
- `remove(id)` — revoke client, release IP for reuse
- `get(id)` / `get_by_public_key(key)` / `get_by_name(name)` — lookup by UUID, Noise IK public key, or name
- `list()` — all non-revoked clients
- `authenticate(initiator_static)` — lookup active client by Noise IK key (returns `None` for suspended/revoked/unknown)
- `update_last_seen(id, timestamp)` — update activity timestamp
- `suspend(id)` / `reactivate(id)` — temporarily disable/re-enable a client
- `update_traffic(id, sent_delta, recv_delta)` — increment per-client byte counters
- `log_connection_event(client_id, event, remote_addr, error, bytes_sent, bytes_received)` — log to connection history
- `get_connection_history(client_id, limit)` — query connection history (most recent first)
- `ConnectionEvent` — Connect, Disconnect, AuthFailed
- `ConnectionHistoryRecord` — id, client_id, event_type, timestamp, remote_addr, error_message, bytes_sent, bytes_received
- `save(path)` / `load(path)` — JSON file persistence at `{data_dir}/clients.json`
- `ClientRecord` — id (UUID), name, public_key, pq_public_key, ip_address, created_at, last_seen, status, bytes_sent, bytes_received
- `ClientStatus` — Active, Suspended, Revoked
- IP allocation: sequential from `network+2` to `broadcast-1`, skipping network/gateway/broadcast
- Dependencies: `uuid` (v1), `ipnet` (v2.11), `serde_json` (v1)

### `server` — Server Orchestrator

- `run_multi_server(listen_addr, server_name, noise_kp, kem_kp, params)` — multi-client production server
- `run_multi_server_on_endpoint(endpoint, noise_kp, kem_kp, params)` — multi-client on pre-bound endpoint (used in tests)
- `MultiServerParams<F>` — configuration bundle: registry, max_clients, tun_factory, cancel, active_connections
- `handle_client(incoming, noise_private, noise_public, kem_dk_bytes, registry, tun_factory, cancel)` — per-client task
- `ActiveClientGuard` — RAII guard that decrements active counter on drop (even on panic)
- `bind_ephemeral_server(name)` — bind to `:0` for testing
- `TunFactory` trait (in `tunnel/mod.rs`) — factory for creating per-client TUN devices
- `MockTunFactory` (in `tunnel/mock_tun.rs`) — test factory producing `(MockTun, MockTunHandle)` pairs

### `client` — Client Orchestrator

- `run_client(server_addr, server_name, noise_kp, server_noise_pub, server_kem_pub, tun, cancel)` — full client lifecycle

### `web` — REST API Backend & Web Frontend (P-006, P-007)

- `AppState` — shared state (registry, active_connections, jwt_secret, admin_password_hash, cancel)
- `build_router(state) -> Router` — axum router with API routes, auth middleware, and SPA frontend
- `run_web_server(listen_addr, state)` — HTTP server with graceful shutdown on CancellationToken
- **SPA:** `GET /` and fallback — serves embedded Preact+HTM single-page application (`assets/index.html`)
- **Auth:** `POST /api/v1/auth/login` — JWT token issuance with Argon2id password verification
- **Server:** `GET /api/v1/server/status` — uptime, version, connected/total clients
- **Server Config:** `GET /api/v1/server/config` — non-sensitive server configuration (P-009B)
- **Clients:** `GET/POST /api/v1/clients`, `GET/DELETE /api/v1/clients/{id}`, `POST .../suspend`, `POST .../resume`
- **Stats:** `GET /api/v1/stats/overview` — client counts, active connections, uptime
- **Distribution:** `GET /api/v1/clients/{id}/config` — client TOML config as text/plain
- **Distribution:** `GET /api/v1/clients/{id}/qr` — SVG QR code as image/svg+xml
- **Distribution:** `POST /api/v1/clients/{id}/config-url` — create time-limited token URL
- **Distribution:** `GET /c/{token}` — public config retrieval by token (no auth)
- `ApiError` — typed error enum mapping to HTTP status codes (400, 401, 404, 409, 500)
- `spa_handler()` — serves embedded HTML for all non-API GET requests (client-side hash routing)
- `logo_handler()` — serves embedded `logo_w.png` at `GET /assets/logo_w.png` (image/png)
- `logo_text_handler()` — serves embedded `logo_w_text.png` at `GET /assets/logo_w_text.png` (image/png)
- `server_transports()` — `GET /api/v1/server/transports` returns enabled transport configurations
- `stats_traffic()` — `GET /api/v1/stats/traffic` returns aggregate traffic statistics across all clients
- CORS enabled via `tower-http` for SPA development
- Dependencies: `axum 0.8`, `jsonwebtoken 9`, `argon2 0.5`, `tower-http 0.6`

### `distribution` — Client Distribution (P-009)

- `ServerContext` — server endpoint, noise public key, KEM public key for config generation
- `generate_client_config(ctx, record) -> Result<String>` — assembles complete client TOML config
- `generate_qr_svg(config_toml) -> Result<String>` — encodes config as `prrr://import?config=<base64>` URL, renders SVG QR code
- `decode_import_url(url) -> Result<String>` — decodes `prrr://import?config=<base64>` back to TOML
- `ConfigTokenStore` — in-memory token store with configurable TTL (default 24h)
  - `insert(config_toml) -> String` — stores config, returns 32-char hex token
  - `get(token) -> Option<String>` — retrieves config if token is valid and not expired
  - `cleanup_expired() -> usize` — removes expired tokens, returns count removed
  - `len() -> usize` / `is_empty() -> bool` — store size queries
- `DistributionError` — QR generation and serialization error types
- URL scheme: `prrr://import?config=<base64>` (URL-safe base64, no padding, RFC 4648)
- QR error correction: level M, minimum 200x200 SVG dimensions
- Token: 128-bit random (16 bytes → 32 hex chars), 24-hour TTL
- Dependencies: `qrcode 0.14`

### Web Admin Interface

When `web_admin.enabled = true` in the server configuration, the admin web
interface is available at `http://<listen_addr>/` (default `http://0.0.0.0:8443/`).

**Features:**
- Login page with username/password authentication (JWT-based sessions)
- Dashboard with server status cards (status, connected/total clients, uptime, version)
- Client list table with name, IP, status, last seen, and action buttons
- Add Client modal with auto-generated keys (displays private key once)
- Client distribution in creation modal: Show QR Code, Share URL, Download Config buttons (P-009B)
- Settings page: read-only server configuration display with card grid (P-009B)
- Suspend, resume, and delete client actions with confirmation
- Cat logo in sidebar navigation, cat+text logo on login page, favicon in browser tab
- Transport visibility: Settings page shows transport config cards, Dashboard shows HARP session count, client table has Transport column
- Traffic statistics: client table shows per-client sent/received bytes, Dashboard shows aggregate totals
- HARP session management: dedicated Sessions page with session list, terminate action, and sidebar session count badge
- Dark theme (automatic, no toggle needed)
- Auto-refreshing dashboard (every 10 seconds)

**Architecture:**
- Single `assets/index.html` file embedded in binary via `include_str!`
- Logo images embedded via `include_bytes!` and served at `/assets/logo_w.png` and `/assets/logo_w_text.png`
- Preact + HTM loaded from esm.sh CDN (no build step, no bundler)
- Hash-based client-side routing (`#/login`, `#/`, `#/sessions`, `#/settings`)
- Zero runtime filesystem dependency — fully self-contained binary
- All data fetched from the REST API endpoints (P-006)

## Client Distribution (P-009)

The server provides automated client configuration distribution via REST API
endpoints. After creating a client through the admin interface or API, the
administrator can export the client's configuration as TOML text, QR code, or
time-limited URL.

### Distribution Endpoints

| Endpoint | Method | Auth | Content-Type | Description |
|----------|--------|------|-------------|-------------|
| `/api/v1/clients/{id}/config` | GET | JWT | `text/plain` | Full client TOML config |
| `/api/v1/clients/{id}/qr` | GET | JWT | `image/svg+xml` | SVG QR code encoding config |
| `/api/v1/clients/{id}/config-url` | POST | JWT | `application/json` | Create time-limited token URL |
| `/c/{token}` | GET | None | `text/plain` | Retrieve config by token (public) |

### Config Export

`GET /api/v1/clients/{id}/config` returns a complete client TOML configuration:

```toml
# prrr client configuration — generated for "alice"

[client]
name = "alice"

[server]
endpoint = "vpn.example.com:443"
public_key = "<base64 X25519 public key>"
pq_public_key = "<base64 ML-KEM-768 public key>"

[interface]
address = "10.66.66.2/32"
dns = ["1.1.1.1", "8.8.8.8"]
mtu = 1280
```

### QR Code Export

`GET /api/v1/clients/{id}/qr` returns an SVG image containing a QR code. The QR
data encodes a `prrr://import?config=<base64>` URL where the config is URL-safe
base64-encoded (RFC 4648, no padding). Error correction level M is used for a
balance of density and recoverability.

### Token URL

`POST /api/v1/clients/{id}/config-url` creates a time-limited token and returns:

```json
{
  "token": "a1b2c3d4e5f6...",
  "url": "/c/a1b2c3d4e5f6..."
}
```

The token is a 128-bit random value (32 hex characters) valid for 24 hours.
The config can be retrieved without authentication via `GET /c/{token}`, making
it suitable for sharing with clients who don't have admin access.

### Usage Examples

```bash
# Export client config as TOML
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/clients/$CLIENT_ID/config > client.toml

# Download QR code as SVG
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/clients/$CLIENT_ID/qr > client-qr.svg

# Create a shareable config URL
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/clients/$CLIENT_ID/config-url

# Retrieve config via token (no auth needed)
curl http://localhost:8443/c/a1b2c3d4e5f67890abcdef1234567890
```

## Architecture

### Connection Flow

```text
Client                                          Server
------                                          ------
1. Parse CLI args                               1. Parse CLI args
2. Init tracing                                 2. Init tracing
3. Load config                                  3. Load config / generate cert
4. Connect QUIC (ALPN=h3)                       4. Bind QUIC, accept
5. MASQUE CONNECT-UDP                           5. MASQUE accept
6. Hybrid handshake (initiator)                 6. Hybrid handshake (responder)
7. Create EncryptedChannel                      7. Create EncryptedChannel
8. TunnelPipeline::run(cancel)                  8. TunnelPipeline::run(cancel)
9. Signal → cancel → shutdown                   9. Signal → cancel → shutdown
```

### Full Protocol Stack

```text
Application (IP packets from TUN device)
     |
TunnelPipeline (F-008): TUN <-> encrypt <-> MASQUE
     |
EncryptedChannel (F-005): ChaCha20-Poly1305 + replay protection
     |
MASQUE framing (F-007): HTTP Datagram [Quarter Stream ID | Context ID | payload]
     |
QUIC DATAGRAMs (F-006): quinn native datagram API
     |
TLS 1.3 (ALPN=h3): indistinguishable from HTTP/3
     |
UDP/IP: standard port 443 traffic
```

## Installation Scripts (P-011)

### Server Installation

```bash
# Single-command bootstrap (requires root/sudo)
curl -fsSL https://install.prrr.dev/server | sudo bash -s -- [OPTIONS]

# Or run locally
sudo bash scripts/install-server.sh [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--admin-pass PASSWORD` | auto-generated | Web admin password |
| `--port PORT` | 443 | VPN listen port (UDP) |
| `--web-port PORT` | 8443 | Web admin port (TCP) |
| `--domain DOMAIN` | — | Domain name for TLS |
| `--no-web` | false | Skip web UI installation |
| `--dns DNS_SERVERS` | 1.1.1.1,8.8.8.8 | Custom DNS servers |
| `--max-clients N` | 100 | Maximum concurrent clients |
| `--data-dir PATH` | /var/lib/prrr | Data directory |
| `--log-level LEVEL` | info | Log level |

**What the script does:**

1. Detects OS (Ubuntu 22.04+, Debian 11+, Fedora 38+) and architecture (x86_64, aarch64)
2. Checks root privileges, port availability, system requirements (1GB RAM, 10GB disk)
3. Installs dependencies via apt-get (Ubuntu/Debian) or dnf (Fedora)
4. Downloads pre-compiled binary (or builds from source via cargo)
5. Generates `/etc/prrr/server.toml` with all config sections
6. Creates systemd service at `/etc/systemd/system/prrr.service` (security-hardened)
7. Configures firewall: UFW (Ubuntu/Debian) or firewalld (Fedora)
8. Enables IP forwarding via sysctl
9. Auto-generates admin password (saved to `/etc/prrr/admin_credentials.txt`)
10. Prints formatted installation summary

### Client Installation

```bash
# Single-command install (does NOT require root for main install)
curl -fsSL https://install.prrr.dev/client | bash

# Or run locally
bash scripts/install-client.sh
```

**What the script does:**

1. Detects OS and architecture
2. Installs dependencies (curl)
3. Downloads pre-compiled binary (or builds from source)
4. Creates user directories: `~/.config/prrr`, `~/.local/share/prrr/{keys,logs}`
5. Sets restrictive permissions (700) on config and keys directories
6. Prints formatted installation summary with next steps

### Linting Scripts

```bash
make shellcheck    # Runs shellcheck on both scripts
```

## Terraform Module (P-012)

Automated DigitalOcean deployment via Terraform. See [`deploy/terraform/README.md`](../deploy/terraform/README.md) for full usage.

### Module Structure

```
deploy/terraform/
├── main.tf              # Droplet, firewall, DNS resources
├── variables.tf         # 11 input variables
├── outputs.tf           # server_ip, web_admin_url, vpn_endpoint
├── templates/
│   └── cloud-init.yml   # Bootstrap template (calls install-server.sh)
└── README.md            # Usage guide
```

### Quick Start

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your DigitalOcean token, SSH key IDs, and admin password
terraform init
terraform plan
terraform apply
```

### Resources Created

| Resource | Description |
|----------|-------------|
| `digitalocean_droplet` | Ubuntu 22.04 server with cloud-init bootstrap |
| `digitalocean_firewall` | SSH (22/tcp, admin IPs), VPN (443/udp, public), Web Admin (8443/tcp, admin IPs) |
| `digitalocean_domain` | DNS zone (conditional, only when `domain` is set) |
| `digitalocean_record` | A record pointing to droplet IP (conditional) |

### Outputs

```bash
terraform output server_ip       # Server public IPv4
terraform output web_admin_url   # https://ip:8443
terraform output vpn_endpoint    # domain:443 or ip:443
```

### Cleanup

```bash
terraform destroy
```

## Security Notes

- Self-signed certificates are used in dev/test mode. Production deployments
  should use proper certificates.
- The insecure TLS verifier (`SkipServerVerification`) is only for development.
- All packet encryption uses ChaCha20-Poly1305 with replay protection.
- Post-quantum security via ML-KEM-768 hybrid handshake.
- No `unsafe` code (`#![deny(unsafe_code)]`).

## Testing

Integration tests exercise the full client-server flow using `MockTun`:

- `integration_keystore_to_client_round_trip` — KeyStore keys → base64 resolution → single client round trip (P-003)
- `tun_factory_creates_tun` — TunFactory trait produces independent TUN devices (P-005)
- `multi_client_graceful_shutdown` — multi-client server shuts down cleanly (P-005)
- `multi_client_two_simultaneous` — two clients connect, both authenticated (P-005)
- `multi_client_max_clients_enforced` — connection rejected at capacity (P-005)
- `multi_client_disconnect_isolation` — one disconnect doesn't affect others (P-005)
- `multi_client_unauthorized_rejected` — unregistered client rejected by server (P-005)
- `active_client_guard_decrements_on_drop` — RAII counter guard (P-005)
- `load_test_ten_concurrent_clients` — 10 simultaneous clients connect and authenticate (P-005/P-009B)

Registry tests (P-009B deferred items):

- `new_client_has_zero_traffic` — new clients start with bytes_sent=0, bytes_received=0
- `update_traffic_increments` — traffic counters increment additively
- `update_traffic_not_found` — unknown UUID returns error
- `migration_v2_schema_version` — schema version set to 2 after migration
- `traffic_persists_across_reopen` — traffic counters survive database reopen
- `log_connect_event` — connect event logged with correct fields
- `log_disconnect_with_traffic` — disconnect event includes byte counts
- `get_history_respects_limit` — query limit parameter works correctly
- `log_auth_failed_event` — auth failure with nil UUID and error message
- `connection_event_as_str` — event type string representations

Pipeline tests (P-009B deferred items):

- `traffic_stats_counted` — bidirectional traffic stats correctly counted via AtomicU64 counters

Web API tests (P-006, P-009B):

- 12 error mapping tests — `ApiError` variants and `RegistryError` conversion
- 13 auth tests — Argon2id password verify, JWT create/verify/expired/tampered, login handler, auth middleware
- 21 handler tests — server status, server config, client CRUD (list/get/create/delete/suspend/resume), stats overview, client traffic response
- 4 HARP session handler tests — list empty, list with sessions (client name resolved), terminate, terminate not found
- 7 integration tests — full CRUD flow through router, auth rejection, CORS, graceful shutdown, shared active count, server config auth + JSON response
- 3 HARP session integration tests — list requires auth, list with auth returns data, terminate requires auth

Web frontend tests (P-007, P-009B):

- 8 SPA handler tests — returns HTML, contains Preact CDN import, app mount element, page title, Settings nav, QR button, Share URL button, Download Config button
- 7 logo tests — logo_handler returns PNG with correct content-type and size, logo_text_handler returns PNG with correct content-type and size, SPA HTML contains sidebar logo, login logo, and favicon
- 4 transport visibility SPA tests — transport section, HARP session card, transport column, getTransports API
- 9 HARP session management SPA tests — sessions route, table headers, nav item, terminate button, session count badge, getHarpSessions API, terminateHarpSession API, active sessions title, empty state
- 4 transport handler tests — transports endpoint returns list, MASQUE transport fields, server status includes HARP sessions, zero HARP sessions
- 7 SPA routing tests — root serves HTML, fallback serves HTML, API routes not captured by fallback, logo route returns PNG, logo text route returns PNG, transports requires auth, transports returns list with auth

CLI tests (P-009B):

- 12 cli handler tests in `src/cli.rs` — add/list/remove/export/import client operations
- 10 config parse tests in `src/config.rs` — nested subcommand parsing, backward compatibility
- 3 registry tests in `src/registry.rs` — `get_by_name` found/not-found/revoked

Distribution tests (P-009):

- 17 unit tests in `src/distribution.rs`:
  - Config generation — valid TOML, server keys present, client fields, no private keys
  - QR SVG generation — valid SVG, `prrr://import` URL scheme, URL-safe base64, round-trip decode
  - Token store — insert returns hex token, get valid/expired/unknown tokens, cleanup expired, concurrent access
- 8 integration tests in `src/web/handlers.rs`:
  - `api_get_client_config` / `api_get_client_config_not_found` — TOML config endpoints
  - `api_get_client_qr` / `api_get_client_qr_not_found` — SVG QR code endpoints
  - `api_create_config_url` / `api_create_config_url_not_found` — token URL creation
  - `api_get_config_by_token` / `api_get_config_by_token_not_found` — public token retrieval

Metrics and monitoring tests (P-008):

- `health_returns_json` — GET /health returns 200 with JSON status
- `health_includes_version_and_uptime` — health response contains version and uptime_seconds
- `metrics_serves_prometheus_format` — GET /metrics returns Prometheus text format
- `metrics_clients_total_gauge` — client gauges (total, connected, suspended) recorded
- `metrics_handshakes_counter_increments` — handshake counters (success, failure) increment
- `metrics_server_graceful_shutdown` — metrics server stops on CancellationToken

Diagnostics tests (P-010):

- `check_status_variants` — CheckStatus Pass, Warn, Fail are distinct
- `check_result_fields` — CheckResult stores name, status, message
- `report_exit_code_all_pass` — exit code 0 for all-pass report
- `report_exit_code_warnings` — exit code 1 for warnings-only report
- `report_exit_code_failures` — exit code 2 for any failure
- `report_exit_code_empty` — exit code 0 for empty report
- `server_config_valid_passes` — valid TOML config passes check
- `server_config_invalid_fails` — invalid TOML config fails check
- `server_config_none_passes` — None path (defaults) passes check
- `server_keys_present_passes` — key files with correct sizes pass
- `server_keys_missing_fails` — missing identity key fails
- `server_keys_pq_missing_fails` — missing PQ key fails
- `server_keys_wrong_identity_size_fails` — wrong identity key size fails
- `server_keys_wrong_pq_size_fails` — wrong PQ key size fails
- `server_port_available_passes` — free port passes
- `server_port_occupied_fails` — occupied port fails
- `server_disk_space_check` — disk space check on /tmp
- `server_disk_space_nonexistent` — nonexistent path handled gracefully
- `server_memory_check` — memory check on real system
- `memory_parse_sufficient` — 10GB available = pass
- `memory_parse_warn` — 100MB available = warn
- `memory_parse_critical` — 32MB available = fail
- `memory_parse_missing_field` — missing MemAvailable handled
- `server_stale_clients_warns` — never-connected client = warn
- `server_no_stale_clients_passes` — recently-seen client = pass
- `server_no_database_passes` — no database file = pass
- `client_keys_present_passes` — existing key file passes
- `client_keys_ephemeral_passes` — no key path configured = pass (ephemeral)
- `client_keys_missing_fails` — configured but missing key = fail
- `client_config_valid_passes` — config with endpoint passes
- `client_config_missing_endpoint_fails` — no endpoint = fail
- `client_server_unreachable_fails` — unreachable address handled
- `client_server_invalid_address_fails` — invalid address = fail
- `report_print_colored_output` — colored output doesn't panic
- `report_recommendations_present` — recommendations list populated
- `run_server_doctor_produces_report` — server doctor returns 7 checks
- `run_client_doctor_produces_report` — client doctor returns 3 checks (no endpoint)
- `run_client_doctor_with_endpoint_has_four_checks` — client doctor returns 4 checks (with endpoint)
- `cli_server_doctor_parses` — `prrr server doctor` CLI parsing
- `cli_client_doctor_parses` — `prrr client doctor` CLI parsing

All tests run without root privileges via `MockTun`.

## Monitoring

### Prometheus Metrics

When `[monitoring] metrics_enabled = true` in the server config, a metrics HTTP server
starts on `prometheus_port` (default 9090) alongside the VPN server.

**Endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /health` | JSON health check: `{"status":"healthy","version":"...","uptime_seconds":N}` |
| `GET /metrics` | Prometheus text exposition format |

**Available Metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `prrr_clients_total` | Gauge | Total registered (non-revoked) clients |
| `prrr_clients_connected` | Gauge | Currently connected VPN clients |
| `prrr_clients_suspended` | Gauge | Suspended clients |
| `prrr_handshakes_total` | Counter | Total successful handshakes |
| `prrr_handshakes_failed_total` | Counter | Total failed handshakes |

**Usage:**

```bash
# Check server health
curl http://localhost:9090/health

# Scrape Prometheus metrics
curl http://localhost:9090/metrics
```

### Structured JSON Logging

When `[monitoring] log_file = "/var/log/prrr/server.log"` is set, the server writes
structured JSON log entries to the specified file alongside the compact console output
on stderr. Each line is a self-contained JSON object with timestamp, level, target,
and message fields.
