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
  "total_clients": 10
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

The root path (`GET /`) serves an embedded single-page application built with Preact and HTM. The SPA uses hash-based routing (`#/login`, `#/`, `#/clients`) and communicates with the REST API described above.

The SPA is included in the binary via `include_str!` and has no runtime filesystem dependencies.

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
