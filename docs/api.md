# REST API Reference

The web admin API is available when `[web_admin].enabled = true` in the server configuration. All API endpoints use the `/api/v1/` prefix and return JSON responses.

## Authentication

The API uses JWT bearer tokens. Obtain a token by posting credentials to the login endpoint.

### POST `/api/v1/auth/login`

Authenticate and receive a JWT token.

**Request:**

```json
{
  "username": "admin",
  "password": "your-password"
}
```

**Response (200):**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}
```

**Response (401):**

```json
{
  "error": "invalid credentials"
}
```

The username is always `"admin"` (single-user model). The password is verified against the Argon2id hash in `[web_admin].admin_password_hash`. Tokens expire after `session_timeout` seconds (default: 3600).

### Using the Token

Include the token in the `Authorization` header for all protected endpoints:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## Server Endpoints

### GET `/api/v1/server/status`

Server status and uptime.

**Response:**

```json
{
  "status": "running",
  "uptime_seconds": 3600,
  "version": "0.1.0",
  "connected_clients": 3,
  "total_clients": 10,
  "active_harp_sessions": 2
}
```

### GET `/api/v1/server/config`

Non-sensitive server configuration.

**Response:**

```json
{
  "listen_addr": "0.0.0.0:443",
  "server_name": "vpn.example.com",
  "subnet": "10.66.66.0/24",
  "dns_servers": ["1.1.1.1", "8.8.8.8"],
  "mtu": 1280,
  "max_clients": 100,
  "version": "0.1.0",
  "transport_protocol": "masque",
  "obfuscation_enabled": true,
  "web_admin_enabled": true,
  "metrics_enabled": false
}
```

### GET `/api/v1/server/transports`

Enabled transport configurations.

**Response:**

```json
{
  "transports": [
    {
      "name": "harp",
      "protocol": "https+ws",
      "websocket_enabled": true,
      "polling_enabled": true,
      "session_idle_timeout": 300
    },
    {
      "name": "masque",
      "protocol": "quic+masque",
      "max_idle_timeout": 300,
      "keep_alive": 25
    }
  ]
}
```

Fields are transport-specific: HARP includes `websocket_enabled`, `polling_enabled`, `session_idle_timeout`; MASQUE includes `max_idle_timeout`, `keep_alive`. Absent fields are omitted from the JSON.

---

## Client Endpoints

### GET `/api/v1/clients`

List all non-revoked clients.

**Response:**

```json
{
  "clients": [
    {
      "id": "a1b2c3d4-...",
      "name": "alice",
      "public_key": "base64...",
      "ip_address": "10.66.66.2",
      "created_at": 1700000000,
      "last_seen": 1700003600,
      "status": "active",
      "bytes_sent": 1048576,
      "bytes_received": 524288
    }
  ]
}
```

### POST `/api/v1/clients`

Register a new client.

**Request:**

```json
{
  "name": "alice",
  "public_key": "base64...",
  "pq_public_key": "base64..."
}
```

The `public_key` and `pq_public_key` fields are optional. If omitted, keys are auto-generated.

**Response (201):**

```json
{
  "id": "a1b2c3d4-...",
  "name": "alice",
  "ip_address": "10.66.66.2",
  "public_key": "base64...",
  "private_key": "base64..."
}
```

The `private_key` is included only when keys are auto-generated. It is shown once and never stored on the server.

### GET `/api/v1/clients/{id}`

Get a single client by UUID.

**Response (200):** Same shape as a single item in the list response.

**Response (404):**

```json
{
  "error": "client not found: a1b2c3d4-..."
}
```

### DELETE `/api/v1/clients/{id}`

Revoke a client. The client can no longer authenticate and its IP address is released.

**Response (200):**

```json
{
  "status": "revoked"
}
```

### POST `/api/v1/clients/{id}/suspend`

Temporarily disable a client. The client cannot authenticate while suspended but retains its IP address.

**Response (200):**

```json
{
  "status": "suspended"
}
```

### POST `/api/v1/clients/{id}/resume`

Re-enable a suspended client.

**Response (200):**

```json
{
  "status": "active"
}
```

---

## Client-to-Client Sharing Pairs

By default the server is **deny-all** for inter-client traffic: a packet from one client
destined for another client's VPN IP is dropped. To let two clients reach each other, an
admin must mark them as an explicit *sharing pair*. The authorization is persisted in the
registry (SQLite) and survives a server restart. Removing the pair stops inter-client
forwarding immediately; egress (traffic to the internet) is never affected.

Pairs are stored unordered — `(A, B)` and `(B, A)` are the same authorization.

### GET `/api/v1/sharing-pairs`

List all allowed sharing pairs.

**Response (200):**

```json
{
  "pairs": [
    { "client_a": "11111111-1111-1111-1111-111111111111", "client_b": "22222222-2222-2222-2222-222222222222" }
  ]
}
```

### POST `/api/v1/sharing-pairs`

Mark two clients as an allowed sharing pair. Idempotent (allowing an existing pair succeeds).

**Request:**

```json
{
  "client_a": "11111111-1111-1111-1111-111111111111",
  "client_b": "22222222-2222-2222-2222-222222222222"
}
```

**Response (201):**

```json
{
  "status": "allowed"
}
```

Returns **400** if the two ids are equal (self-pair) or if either client id is unknown.

### DELETE `/api/v1/sharing-pairs/{a}/{b}`

Revoke a sharing pair. Idempotent — revoking a non-existent pair still returns 200. The next
inter-client packet between the two clients is dropped immediately.

**Response (200):**

```json
{
  "status": "revoked"
}
```

---

## Distribution Endpoints

These endpoints support client configuration distribution via TOML export, QR codes, and shareable URLs.

### GET `/api/v1/clients/{id}/config`

Export the client's complete TOML configuration.

**Content-Type:** `text/plain`

**Response:**

```toml
# prrr client configuration -- generated for "alice"

[client]
name = "alice"

[server]
endpoint = "vpn.example.com:443"
public_key = "base64..."
pq_public_key = "base64..."

[interface]
address = "10.66.66.2/32"
dns = ["1.1.1.1", "8.8.8.8"]
mtu = 1280
```

### GET `/api/v1/clients/{id}/qr`

Generate a QR code for the client's configuration.

**Content-Type:** `image/svg+xml`

The QR code encodes a `prrr://import?config=<base64>` URL. The client can scan this with a QR reader and import via `prrr client import "prrr://import?config=..."`.

### POST `/api/v1/clients/{id}/config-url`

Create a time-limited URL for config retrieval.

**Response (201):**

```json
{
  "token": "a1b2c3d4e5f67890abcdef1234567890",
  "url": "/c/a1b2c3d4e5f67890abcdef1234567890"
}
```

Tokens are 128-bit random values (32 hex characters) valid for 24 hours. The config can be retrieved without authentication via the public endpoint below.

### GET `/c/{token}` (Public -- No Auth)

Retrieve a client config by token. No `Authorization` header required.

**Content-Type:** `text/plain`

**Response (200):** The client TOML configuration.

**Response (404):** Token not found or expired.

---

## Statistics Endpoints

### GET `/api/v1/stats/overview`

Aggregate statistics.

**Response:**

```json
{
  "clients": {
    "total": 10,
    "connected": 3,
    "suspended": 1
  },
  "uptime_seconds": 3600
}
```

### GET `/api/v1/stats/traffic`

Aggregate traffic statistics across all clients.

**Response:**

```json
{
  "total_bytes_sent": 123456789,
  "total_bytes_received": 987654321,
  "client_count": 5
}
```

---

## HARP Session Management Endpoints (Admin)

These endpoints require JWT authentication and are used to monitor and
manage active HARP tunnel sessions from the web admin UI.

### GET `/api/v1/harp/sessions`

List all active HARP sessions.

**Response:**

```json
{
  "sessions": [
    {
      "session_id": "a1b2c3d4e5f67890",
      "client_name": "alice",
      "client_id": "a1b2c3d4-...",
      "created_at": 1700000000,
      "last_activity": 1700000060,
      "idle_seconds": 5
    }
  ]
}
```

The `session_id` is truncated to the first 16 hex characters for display
safety (the full cryptographic session ID is not exposed). `created_at` and
`last_activity` are Unix epoch seconds.

### DELETE `/api/v1/harp/sessions/{session_id_hex}`

Force-terminate an active HARP session.

**Response (200):**

```json
{
  "status": "terminated"
}
```

**Response (404):**

```json
{
  "error": "session not found"
}
```

The `session_id_hex` parameter is matched as a prefix against active sessions.

---

## Error Responses

All error responses follow a consistent format:

```json
{
  "error": "description of the error"
}
```

### HTTP Status Codes

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 201 | Resource created |
| 400 | Bad request (invalid input) |
| 401 | Unauthorized (missing or invalid JWT) |
| 404 | Resource not found |
| 409 | Conflict (duplicate name or public key) |
| 500 | Internal server error |

---

## SPA Frontend

The root path (`GET /`) serves an embedded single-page application built with Preact and HTM. The SPA uses hash-based routing (`#/login`, `#/`, `#/sessions`, `#/settings`) and communicates with the REST API described above.

The SPA is included in the binary via `include_str!` and has no runtime filesystem dependencies.

### Static Assets

Logo images are embedded in the binary via `include_bytes!` and served at:

| Route | Description | Content-Type |
|-------|-------------|-------------|
| `GET /assets/logo_w.png` | Cat logo (sidebar, favicon) | `image/png` |
| `GET /assets/logo_w_text.png` | Cat logo with text (login page) | `image/png` |

These routes do not require authentication.

---

## Metrics Endpoints

These endpoints are served on the monitoring port (default: 9090), separate from the web admin API. They are available when `[monitoring].metrics_enabled = true`.

### GET `/health`

Health check.

**Response:**

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 3600
}
```

### GET `/metrics`

Prometheus metrics in text exposition format.

**Available Metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `prrr_clients_total` | Gauge | Total registered (non-revoked) clients |
| `prrr_clients_connected` | Gauge | Currently connected clients |
| `prrr_clients_suspended` | Gauge | Suspended clients |
| `prrr_handshakes_total` | Counter | Successful handshakes |
| `prrr_handshakes_failed_total` | Counter | Failed handshakes |

---

## Usage Examples

### curl

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}' | jq -r .token)

# List clients
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/clients | jq

# Add a client
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"bob"}' \
  http://localhost:8443/api/v1/clients | jq

# Export client config
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/clients/$CLIENT_ID/config > bob.toml

# Server status
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/server/status | jq

# Health check (metrics port, no auth)
curl -s http://localhost:9090/health | jq
```

---

## HARP Session Endpoints

These endpoints handle VPN tunnel session establishment over HTTPS. They do
**not** require JWT authentication — authentication is performed via the
cryptographic handshake. All errors return `200 OK` with fake response data
to prevent DPI fingerprinting.

### POST `/api/v1/harp/session`

Establish a new HARP VPN session via hybrid Noise IK + ML-KEM-768 handshake.

**Request:**

```json
{
  "noise_msg1": "<base64-encoded Noise IK message 1>",
  "capabilities": ["stream", "poll"],
  "timestamp": 1708700000
}
```

**Response (200):**

```json
{
  "session_id": "<base64-encoded 32-byte session ID>",
  "noise_msg2": "<base64-encoded Noise IK message 2>",
  "transport": {
    "mode": "stream",
    "stream_endpoint": "/api/v1/harp/stream/<session_id>",
    "upload_endpoint": "/api/v1/harp/upload/<session_id>",
    "download_endpoint": "/api/v1/harp/download/<session_id>"
  },
  "config": {
    "rekey_interval": 3600,
    "keepalive_interval": 25,
    "max_frame_size": 65535,
    "poll_interval_ms": 100
  }
}
```

**Notes:**
- The `timestamp` must be within 30 seconds of the server's clock.
- Failed handshakes return `200 OK` with a fake response (random session_id
  and noise_msg2) that is structurally identical to a real response.
- The client completes the handshake by calling `HybridInitiator::finish()`
  with the returned `noise_msg2`.
- Transport endpoint paths use URL-safe base64 encoding (no `/`, `+`, `=`)
  for the session ID. The `session_id` field in the JSON body uses standard base64.

### GET `/api/v1/harp/stream/{session_id}` (WebSocket)

Bidirectional WebSocket streaming transport for an established HARP session.

**Prerequisites:** A valid session from `POST /api/v1/harp/session`.

**Request:** Standard HTTP Upgrade to WebSocket. The `{session_id}` path
parameter is the URL-safe base64 encoding of the 32-byte session ID
(as returned in `transport.stream_endpoint`).

**Behavior:**

- On successful upgrade, the server runs a bidirectional bridge:
  - Server → Client: frames from the session's `to_client` channel are sent
    as WebSocket `Binary` messages
  - Client → Server: WebSocket `Binary` messages are forwarded to the
    session's `from_client` channel
- Each frame sent or received updates the session's `last_activity` timestamp
- When the WebSocket closes (from either side), the session is removed from
  the store

**Error handling:**

- Unknown or invalid session ID: the server still performs the WebSocket
  upgrade (returning `101 Switching Protocols`) then immediately sends a
  `Close` frame. This prevents DPI from distinguishing valid vs invalid
  sessions at the HTTP level.
- Non-WebSocket requests to this endpoint are rejected by axum's
  WebSocket extractor.
