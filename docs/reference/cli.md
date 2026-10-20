# CLI reference

Use `prrr --help` and the help of the relevant subcommand for the exact interface of your installed executable. The commands below are checked against revision `191ebaf`.

## Command map

| Command | Purpose |
| --- | --- |
| `prrr server` | Start the configured VPN server. |
| `prrr server doctor` | Inspect server configuration and prerequisites. |
| `prrr server client add NAME [--qr]` | Register a client and write its complete first configuration to stdout. |
| `prrr server client list` | List non-revoked client records. |
| `prrr server client export NAME [--qr] [--output PATH]` | Export public/connection configuration; the original client private key is not recovered. |
| `prrr server client remove NAME` | Revoke the named registry client. |
| `prrr client import SOURCE` | Import TOML or a `prrr://` configuration URL into the user's configuration directory. |
| `prrr client doctor` | Inspect client configuration and prerequisites. |
| `prrr client route add RESOURCE` | Add a hostname or IPv4 literal to configured resource routes. |
| `prrr client route remove RESOURCE` | Remove a configured resource. |
| `prrr client route list` | List configured resources. |
| `prrr sharing enable`, `disable`, `status` | Change or inspect the local persisted sharing opt-in state. |

## Placement of options

Options belong to their command. Put server/client options before the nested action:

```sh
prrr server --config /etc/prrr/server.toml client list
prrr client --config /etc/prrr/client.toml route list
prrr client --config /etc/prrr/client.toml doctor
```

There is no top-level `prrr doctor` command.

## Server options

| Option | Default / effect |
| --- | --- |
| `--listen ADDRESS:PORT` | `0.0.0.0:443`; bind address/port used by startup. |
| `--server-name NAME` | `localhost`; set the actual endpoint name when starting and provisioning. |
| `--config PATH` | Optional TOML file. |
| `--log-level LEVEL` | `info`; `PRRR_LOG_LEVEL` is also supported. |

`PRRR_LISTEN` can provide the listen address. Do not infer that a similarly named TOML field overrides every CLI default: startup and export resolve fields in different places. The tutorial supplies the endpoint flags explicitly.

## Client options

| Option | Effect |
| --- | --- |
| `--server ADDRESS:PORT` | Explicit socket endpoint; otherwise resolve configured endpoint. |
| `--server-name NAME` | TLS server name; otherwise read `[server].server_name`. |
| `--server-public-key BASE64` | Pinned 32-byte Noise server public key. |
| `--server-pq-public-key BASE64` | Pinned 1184-byte ML-KEM-768 encapsulation key. |
| `--config PATH` | Client TOML file. |
| `--insecure` | Disable certificate verification for controlled tests; keep verification on for deployed clients. |
| `--log-level LEVEL` | `info`; also `PRRR_LOG_LEVEL`. |

The server's public keys, client private key, and TLS server name serve different purposes. Importing a public-only export does not supply a missing client identity.

## Editing routes

```sh
prrr client --config /etc/prrr/client.toml route add example.net
prrr client --config /etc/prrr/client.toml route list
prrr client --config /etc/prrr/client.toml route remove example.net
```

Use the account/privileges appropriate to the selected config file. These commands edit configuration; restart the service when applying a changed resource policy to the running client. An exact hostname does not automatically include its subdomains.

Source: [argument definitions](https://github.com/Mewplane/prrr/blob/191ebaf/src/config.rs), [handlers](https://github.com/Mewplane/prrr/blob/191ebaf/src/cli.rs), [dispatch and precedence](https://github.com/Mewplane/prrr/blob/191ebaf/src/main.rs).
