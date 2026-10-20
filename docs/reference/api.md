# Admin API reference

The admin router exposes `/api/v1/` when configured. It is distinct from the VPN's identity-authorized HARP endpoints.

## Listener and authentication

The separate admin listener is HTTP in the active `run_web_server` path. Keep it private, or put it behind an authenticated, correctly configured TLS termination path. Do not assume `web_admin.tls_cert` turns this listener into HTTPS. The dedicated HARP TLS server is a separate caller.

`POST /api/v1/auth/login` accepts `username` and `password`. The username is `admin`; the password is verified against the configured Argon2 hash. A successful response contains a bearer token. Protected routes require:

```text
Authorization: Bearer YOUR_TOKEN
```

Default session timeout is 3600 seconds. Treat tokens and first client-creation responses as secrets. Use a login request file with restricted permissions when scripting against your own HTTPS admin proxy.

## Core routes

| Method and path | Purpose |
| --- | --- |
| `GET /api/v1/server/status` | Server status and connection counts |
| `GET /api/v1/server/config` | Non-secret server configuration summary |
| `GET /api/v1/server/transports` | Enabled transport configuration |
| `GET /api/v1/clients` | Client records |
| `POST /api/v1/clients` | Create a client; capture first returned private material securely |
| `GET /api/v1/clients/{id}` | One client record |
| `DELETE /api/v1/clients/{id}` | Revoke a client |
| `POST /api/v1/clients/{id}/suspend` | Suspend an identity |
| `POST /api/v1/clients/{id}/resume` | Resume an identity |
| `GET /api/v1/clients/{id}/config` | Export connection configuration |
| `GET /api/v1/clients/{id}/qr` | QR representation |
| `POST /api/v1/clients/{id}/config-url` | Create a configuration-sharing URL |
| `GET /api/v1/stats/overview` | Overview counters |
| `GET /api/v1/stats/traffic` | Traffic statistics |
| `GET /api/v1/harp/sessions` | Active HARP sessions |
| `DELETE /api/v1/harp/sessions/{session_id_hex}` | Terminate a HARP session |

## VPN session routes

The HARP router contains `/api/v1/harp/session`, `/stream/{session_id}`, `/upload/{session_id}`, and `/download/{session_id}`. These are VPN transport endpoints, not a reason to expose an admin bearer token to VPN clients. Session creation processes the hybrid handshake and registry identity.

The cover page at `/`, SPA at `/admin`, and configuration token route `/c/{token}` have their own access and token semantics. A cover page is presentation, not an invisibility guarantee.

Sources: [router definitions](https://github.com/Mewplane/prrr/blob/191ebaf/src/web/mod.rs), [authentication](https://github.com/Mewplane/prrr/blob/191ebaf/src/web/auth.rs), [handlers](https://github.com/Mewplane/prrr/blob/191ebaf/src/web/handlers.rs), [HARP session processing](https://github.com/Mewplane/prrr/blob/191ebaf/src/web/harp.rs).
