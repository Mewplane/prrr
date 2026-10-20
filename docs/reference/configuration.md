# Configuration reference

prrr reads TOML. Client and server files have different schemas. These examples focus on settings used by the active caller paths; parsing a field is not proof that every advertised behavior is wired to it.

## Server configuration

This explicit MASQUE example accompanies the first-connection tutorial:

```toml
[server]
server_name = "vpn.example.net"
data_dir = "/var/lib/prrr"
max_clients = 100

[network]
subnet = "10.66.66.0/24"
dns_servers = ["1.1.1.1", "8.8.8.8"]
mtu = 1100

[crypto]
identity_key_path = "/etc/prrr/keys/server_identity.key"
pq_key_path = "/etc/prrr/keys/server_pq.key"

[[transports]]
name = "masque"
enabled = true
tls_cert = "/etc/letsencrypt/live/vpn.example.net/fullchain.pem"
tls_key = "/etc/letsencrypt/live/vpn.example.net/privkey.pem"
```

Start and provision with the same endpoint flags:

```sh
prrr server --config /etc/prrr/server.toml \
  --listen 0.0.0.0:443 --server-name vpn.example.net
```

| Setting | Behavior / default |
| --- | --- |
| `[server].data_dir` | Registry/state directory; default `/var/lib/prrr`. |
| `[server].max_clients` | Default 100. |
| `[network].subnet` | Default `10.66.66.0/24`. |
| `[network].mtu` | Default 1100; chosen to fit tunnel and datagram overhead. |
| `[crypto].identity_key_path` | Persistent X25519 identity key. |
| `[crypto].pq_key_path` | Persistent ML-KEM key. |
| `[[transports]].name` | `harp` or `masque`; `enabled = false` filters an entry. |
| MASQUE `keep_alive` / `max_idle_timeout` | Defaults 25 / 300 seconds. |
| HARP `websocket_enabled`, `polling_enabled`, `h2_streaming_enabled` | Default true when the transport is resolved. |
| HARP `session_idle_timeout` | Default 300 seconds. |
| Transport `tls_cert` / `tls_key` | Certificate chain and private-key paths; configure both for the real hostname. |

**The defaults differ:** an absent/empty server transport list resolves to HARP, while an unqualified client and the provisioning fallback use `masque`. Configure the transport explicitly before provisioning clients. A generated config chooses the first enabled configured transport.

## Client identity and connection

The first `client add` output includes `[server]` public keys and an inline `[interface].private_key`. Keep that configuration private. This fragment illustrates operational settings without substituting fake public/private keys for the generated ones:

```toml
[interface]
mtu = 1100
transport_protocol = "masque"

[transport]
insecure_skip_verify = false
reconnect_backoff_ms = 1000
reconnect_max_backoff_ms = 30000
```

Merge fields into the existing sections; do not append duplicate TOML table headers.

| Selection | Precedence |
| --- | --- |
| Client transport | `[interface].transport_protocol`, then `[transport].protocol`, then `masque`. |
| Server name | Client CLI `--server-name`, then `[server].server_name`, then an error if absent. |
| Server public keys | CLI key flags, then `[server].public_key` / `.pq_public_key`. |
| Client private key | Inline `[interface].private_key`, then configured file fallback. |

For HARP, `[transport].preferred_binding` selects `h2`, `stream` (WebSocket), or `poll`, subject to the negotiated capabilities and caller's fallback logic. `tls_profile` selects an approximate profile; it does not turn rustls into a browser TLS stack.

## Routing policies

Route IPv4 through the tunnel while preserving the detected local LAN:

```toml
[routing]
all_traffic = true
resources = []
full_tunnel = false
```

Route only named resources:

```toml
[routing]
all_traffic = false
resources = ["example.net", "203.0.113.10"]
full_tunnel = false
```

Resource names are resolved to IPv4 `/32` routes before activation. Names are exact entries; this does not recursively include subdomains or every address belonging to a service. Initial resolution failure prevents startup. Refresh happens separately, so a stalled resolver does not freeze the packet pump.

`all_traffic` defaults to false. `full_tunnel` controls local-LAN auto-exclusion; it is a different setting from routing the default IPv4 route. The transport endpoint must keep a bypass to avoid routing the tunnel into itself. Default fwmark/table is 51820; `hook_script` defaults to `/usr/local/bin/prrr-route`.

The current client path is IPv4-oriented. A full IPv4 route is not proof of IPv6 protection or a kill switch.

## DNS and recovery

Configured `[interface].dns` servers are pinned through the tunnel. The hook advertises responders when the DNS gate is healthy, withdraws the advertisement when necessary, and keeps pins in place for valid probing. Split mode scopes resolver domains to the configured resources; all-traffic mode can use the catch-all domain.

Default recovery values are 60-second resource refresh, 20-second refresh budget, 15-second DNS probes, 2-second probe timeout, 45-second verdict lease, and three black-hole strikes at 5-second intervals. See [recovery](../how-to/recover.md) and the [routing animation](../explanation/mechanics.md#routing-and-recovery).

## Admin listener

`[web_admin].enabled` defaults to false. When enabled, the separate listener requires `admin_password_hash` and defaults to `0.0.0.0:8443`. Bind it to a private/loopback address and terminate TLS through a controlled proxy before exposing it. `run_web_server` serves HTTP; the existence of TLS-related fields in a configuration struct does not make that listener HTTPS.

Sources: [schema and transport resolution](https://github.com/Mewplane/prrr/blob/191ebaf/src/config.rs), [active caller paths](https://github.com/Mewplane/prrr/blob/191ebaf/src/main.rs), [routing](https://github.com/Mewplane/prrr/blob/191ebaf/src/routing.rs), [reconnect](https://github.com/Mewplane/prrr/blob/191ebaf/src/reconnect.rs).
