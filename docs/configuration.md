# Configuration Reference

prrr uses TOML configuration files for both server and client. All fields are optional -- missing values use built-in defaults. CLI flags take precedence over config file values. Unknown fields are silently ignored for forward compatibility.

## Server Configuration

Load with `prrr server --config /path/to/server.toml`.

### `[server]`

General server settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | String | `"0.0.0.0:443"` | Address and port to listen on (TCP for HARP, UDP for MASQUE) |
| `max_clients` | u32 | `100` | Maximum concurrent client connections |
| `log_level` | String | `"info"` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `data_dir` | String | `"/var/lib/prrr"` | Directory for database and runtime files |
| `server_name` | String | `"localhost"` | TLS server name (SNI) — set to your server's actual domain in production |

### `[network]`

Network and tunnel settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `subnet` | String | `"10.66.66.0/24"` | CIDR subnet for client IP allocation |
| `dns_servers` | Array of String | `["1.1.1.1", "8.8.8.8"]` | DNS servers pushed to clients |
| `mtu` | u16 | `1280` | Tunnel MTU (range: 1280--1420) |

### `[crypto]`

Cryptographic key paths and rekeying.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `identity_key_path` | String | `"/etc/prrr/keys/server_identity.key"` | Path to X25519 identity key (32 bytes) |
| `pq_key_path` | String | `"/etc/prrr/keys/server_pq.key"` | Path to ML-KEM-768 key (2400 bytes) |
| `rekey_interval` | u64 | `3600` | Rekey interval in seconds |

Keys are generated automatically on first run if the files don't exist. Public keys are saved alongside as `.pub` files.

### `[[transports]]`

Transport protocol settings. Multiple transports can be enabled simultaneously
using TOML's array-of-tables syntax. Each entry has a `name` field that selects
the transport type, plus transport-specific settings.

If `[[transports]]` is absent, the server defaults to a single enabled HARP
transport with all-default values.

#### MASQUE Transport (`name = "masque"`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | String | -- | Must be `"masque"` |
| `enabled` | bool | `true` | Whether this transport is active |
| `max_idle_timeout` | u64 | `300` | QUIC connection idle timeout in seconds |
| `keep_alive` | u64 | `25` | QUIC keep-alive interval in seconds |
| `tls_cert` | String | -- | Path to TLS certificate (PEM) for QUIC |
| `tls_key` | String | -- | Path to TLS private key (PEM) for QUIC |

#### HARP Transport (`name = "harp"`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | String | -- | Must be `"harp"` |
| `enabled` | bool | `true` | Whether this transport is active |
| `websocket_enabled` | bool | `true` | Enable WebSocket streaming binding |
| `polling_enabled` | bool | `true` | Enable HTTP polling fallback binding |
| `h2_streaming_enabled` | bool | `true` | Enable HTTP/2 multiplexed streaming binding |
| `session_idle_timeout` | u64 | `300` | HARP session idle timeout in seconds |

### `[obfuscation]`

Traffic obfuscation settings. Disabled by default.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable traffic obfuscation |
| `padding_strategy` | String | `"power-of-two"` | Padding strategy: `power-of-two`, `http-sizes`, `fixed-mtu:<N>`, `none` |
| `timing_jitter_ms` | u64 | `50` | Maximum random jitter added to packet timing (ms) |
| `tls_profile` | String | `"chrome"` | TLS fingerprint profile: `chrome`, `firefox`, `default` |

### `[obfuscation.probe_resist]`

Active probing resistance. Requires `[obfuscation].enabled = true`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | -- | Enable probe resistance |
| `psk` | String | -- | Pre-shared key for HMAC cookie authentication |
| `tokens_per_second` | u64 | `20` | Rate limit: tokens refilled per second |
| `burst_capacity` | u64 | `5` | Rate limit: maximum burst capacity |

When probe resistance is enabled, unauthenticated connections receive a decoy HTTP response mimicking an nginx web server instead of a connection refusal.

### `[web_admin]`

Web administration panel. Disabled by default.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable web admin panel |
| `listen_addr` | String | `"0.0.0.0:8443"` | HTTP listen address |
| `tls_cert` | String | -- | Path to TLS certificate (PEM) |
| `tls_key` | String | -- | Path to TLS private key (PEM) |
| `admin_password_hash` | String | -- | Argon2id password hash (required when enabled) |
| `session_timeout` | u64 | `3600` | JWT session timeout in seconds |
| `cover_page_enabled` | bool | `true` | Serve cover landing page at `/` for DPI camouflage. When `false`, `/` serves the admin SPA directly. |
| `trust_proxy_headers` | bool | `false` | Trust CDN proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`) for real client IP extraction. Enable when behind Cloudflare or another trusted reverse proxy. |

### `[messaging]`

Whisper messaging subsystem. Disabled by default.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable Whisper messaging |
| `relay_mode` | String | `"server"` | Relay mode |
| `max_message_size` | u64 | `10485760` | Maximum message size in bytes (10 MiB) |
| `retention_days` | u32 | `30` | Message retention period in days |

### `[monitoring]`

Prometheus metrics and logging. Disabled by default.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `metrics_enabled` | bool | `false` | Enable Prometheus metrics endpoint |
| `prometheus_port` | u16 | `9090` | Metrics HTTP server port |
| `log_file` | String | -- | Path for structured JSON log output |
| `log_rotation` | String | `"daily"` | Log rotation interval |
| `log_retention_days` | u32 | `7` | Number of days to retain rotated logs |

---

## Client Configuration

Load with `prrr client --config /path/to/client.toml`.

Client configs are typically generated by the server (`prrr server client export`) and imported with `prrr client import`.

### `[client]`

General client settings.

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Human-readable client name |
| `auto_connect` | bool | Auto-connect on startup |
| `log_level` | String | Log level directive |

### `[server]`

Server connection details.

| Field | Type | Description |
|-------|------|-------------|
| `endpoint` | String | Server address (e.g., `"vpn.example.com:443"`) |
| `public_key` | String | Server X25519 public key (base64, 32 bytes decoded) |
| `pq_public_key` | String | Server ML-KEM-768 public key (base64, 1184 bytes decoded) |

### `[interface]`

Client network interface settings.

| Field | Type | Description |
|-------|------|-------------|
| `private_key_path` | String | Path to client X25519 private key |
| `pq_private_key_path` | String | Path to client ML-KEM-768 private key |
| `address` | String | Assigned VPN IP address (CIDR, e.g., `"10.66.66.2/32"`) |
| `dns` | Array of String | DNS servers |
| `mtu` | u16 | Tunnel MTU |

### `[routing]`

Traffic routing rules.

| Field | Type | Description |
|-------|------|-------------|
| `all_traffic` | bool | Route all traffic through the VPN |
| `full_tunnel` | bool | Strict full-tunnel. When `true`, capture the local LAN too (disable the default RFC1918 local-LAN auto-exclusion). Defaults to `false`. |
| `allowed_ips` | Array of String | Allowed destination CIDRs (e.g., `["0.0.0.0/0"]`) |
| `excluded_ips` | Array of String | Excluded destination CIDRs (e.g., `["192.168.0.0/16"]`) |
| `resources` | Array of String | Hostnames or IPv4 literals routed through the VPN (e.g., `["chatgpt.com", "claude.ai"]`) |

#### Selected resource routing

`resources` provides selective split tunneling. Each entry is a hostname or
IPv4 literal. The client resolves hostnames when it starts and installs an
exact IPv4 `/32` route for every returned address in the VPN policy table.
Resources are therefore re-resolved by restarting the client after DNS changes.
Wildcards, URLs, CIDRs, and IPv6-only resources are rejected. The current
client TUN is IPv4-only; an IPv6 connection to a service is not covered by
this setting.

```toml
[routing]
resources = [
  "chatgpt.com",
  "api.openai.com",
  "claude.ai",
  "youtube.com",
  "googlevideo.com",
  "telegram.org",
  "t.me",
]
```

Use one entry for each hostname a service needs. Resource routes are active
only while the tunnel is up and do not change the existing LAN auto-exclusion
or full-tunnel settings.

#### Local-LAN auto-exclusion (default)

By default prrr keeps your active interface's RFC1918 local-LAN subnet
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) **out of the tunnel**, so
traffic to a device on the same LAN stays on the local link instead of being
swallowed by the full tunnel. This is a zero-config courtesy that lets companion
apps on the same Wi-Fi keep working while prrr is active. The detected LAN
prefixes are merged with any `excluded_ips` you set; the tunnel's own subnet is
never excluded.

Set `full_tunnel = true` to opt out and route the LAN through the tunnel too:

```toml
[routing]
full_tunnel = true   # capture the local LAN as well (strict full tunnel)
```

The `full_tunnel` flag and the computed `excluded_ips` set are also published to
the ecosystem registry so sibling apps on the same laptop can coexist with prrr.
See [ecosystem registry registration](ecosystem.md).

### `[transport]`

Client transport settings. The client uses a single transport at a time.

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | String | Transport protocol: `"harp"` (default) or `"masque"` |
| `keep_alive` | u64 | Keep-alive interval in seconds (MASQUE) |
| `insecure_skip_verify` | bool | Skip TLS certificate verification (dev/test only) |
| `preferred_binding` | String | HARP binding preference: `"stream"` (WebSocket), `"poll"` (HTTP polling), or `"h2"` (HTTP/2 streams) |
| `poll_interval_ms` | u64 | HARP polling interval in milliseconds |
| `reconnect_backoff_ms` | u64 | Initial reconnection backoff delay in ms (default: 1000) |
| `reconnect_max_backoff_ms` | u64 | Maximum reconnection backoff delay in ms (default: 30000) |
| `tls_profile` | String | TLS fingerprint profile: `"chrome"`, `"firefox"`, or `"default"`. When absent, defaults to Chrome. |
| `cdn_fronting_enabled` | bool | Enable CDN domain fronting fallback. When `true`, falls back to CDN if direct connection times out. Default: `false`. |
| `cdn_fronting_domain` | String | CDN fronting domain (e.g., `"prrr.tech"`). Used for DNS resolution and TLS SNI when routing through CDN. |
| `direct_timeout_secs` | u64 | Direct connection timeout in seconds before CDN fallback. Default: `5`. |
| `direct_retry_interval_secs` | u64 | Interval in seconds between probing direct connection when CDN is active. Default: `600`. |

### `[obfuscation]`

Client obfuscation settings.

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable traffic obfuscation |

### `[messaging]`

Client messaging settings.

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable Whisper messaging |

---

## Environment Variables

| Variable | Overrides | Description |
|----------|-----------|-------------|
| `PRRR_LISTEN` | `--listen` / `[server].listen_addr` | Server listen address |
| `PRRR_LOG_LEVEL` | `--log-level` / `[server].log_level` | Log level |
| `RUST_LOG` | All log level settings | Tracing filter directive (most specific) |

Precedence (highest to lowest): `RUST_LOG` > CLI flag > environment variable > config file > built-in default.

---

## Example: Minimal Server Config

```toml
[server]
server_name = "vpn.example.com"
```

Everything else uses defaults: listens on `0.0.0.0:443`, allocates from `10.66.66.0/24`, auto-generates keys.

## Example: Full Server Config

```toml
[server]
listen_addr = "0.0.0.0:443"
max_clients = 50
log_level = "info"
data_dir = "/var/lib/prrr"
server_name = "vpn.example.com"

[network]
subnet = "10.66.66.0/24"
dns_servers = ["1.1.1.1", "1.0.0.1"]
mtu = 1280

[crypto]
identity_key_path = "/etc/prrr/keys/server_identity.key"
pq_key_path = "/etc/prrr/keys/server_pq.key"
rekey_interval = 3600

[[transports]]
name = "harp"
enabled = true
websocket_enabled = true
polling_enabled = true
h2_streaming_enabled = true
session_idle_timeout = 300

[[transports]]
name = "masque"
enabled = true
max_idle_timeout = 300
keep_alive = 25
tls_cert = "/etc/prrr/tls/cert.pem"
tls_key = "/etc/prrr/tls/key.pem"

[obfuscation]
enabled = true
padding_strategy = "power-of-two"
timing_jitter_ms = 50
tls_profile = "chrome"

[obfuscation.probe_resist]
enabled = true
psk = "my-secret-psk"
tokens_per_second = 20
burst_capacity = 5

[web_admin]
enabled = true
listen_addr = "0.0.0.0:8443"
admin_password_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
session_timeout = 3600
# trust_proxy_headers = true  # Enable when behind Cloudflare CDN

[messaging]
enabled = true
relay_mode = "server"
max_message_size = 10485760
retention_days = 30

[monitoring]
metrics_enabled = true
prometheus_port = 9090
log_file = "/var/log/prrr/server.log"
log_rotation = "daily"
log_retention_days = 7
```

## Example: Client Config

```toml
[client]
name = "laptop"
auto_connect = false
log_level = "info"

[server]
endpoint = "vpn.example.com:443"
public_key = "base64-encoded-x25519-public-key"
pq_public_key = "base64-encoded-mlkem768-public-key"

[interface]
address = "10.66.66.2/32"
dns = ["1.1.1.1", "8.8.8.8"]
mtu = 1280

[routing]
all_traffic = true
allowed_ips = ["0.0.0.0/0", "::/0"]

[transport]
protocol = "harp"   # or "masque" for QUIC-based transport
# preferred_binding = "stream"  # HARP only: "stream" | "poll" | "h2"
# poll_interval_ms = 500         # HARP polling only
# keep_alive = 25                # MASQUE only
# reconnect_backoff_ms = 1000    # Initial reconnection backoff (ms)
# reconnect_max_backoff_ms = 30000  # Maximum reconnection backoff (ms)
# tls_profile = "chrome"           # TLS fingerprint: "chrome", "firefox", "default"
# cdn_fronting_enabled = false      # Enable CDN domain fronting fallback
# cdn_fronting_domain = "prrr.tech" # CDN fronting domain
# direct_timeout_secs = 5           # Timeout before CDN fallback (seconds)
# direct_retry_interval_secs = 600  # Probe direct interval when using CDN (seconds)

[obfuscation]
enabled = true

[messaging]
enabled = true
```
