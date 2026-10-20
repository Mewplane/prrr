# Install prrr

Build the current source, install the components used by the service, and prepare a matching server/client configuration. This guide uses repository scripts rather than assuming an installer domain or published binary exists.

## Requirements

- Linux with `/dev/net/tun`, IP routing tools, and systemd for the documented client service.
- A Rust toolchain compatible with the committed `Cargo.lock`, Git, a C toolchain, and `pkg-config`.
- A server whose domain, certificate, permitted port, forwarding, and NAT you administer.
- Administrative privileges for TUN creation, socket marks, and route changes.

The workspace declares Rust 1.85; resolved dependencies can require a newer compiler. Keep `Cargo.lock` and use a compatible current stable toolchain.

## Build from the real repository

```sh
git clone https://github.com/Mewplane/prrr.git
cd prrr
cargo build --locked --release --bin prrr
target/release/prrr --help
```

Use a binary built for your destination's CPU and libc. Copying a build from a newer distribution to an older server can fail before prrr starts.

## Deploy a server

Install the built binary and prepare private state directories:

```sh
sudo install -m 755 target/release/prrr /usr/local/bin/prrr
sudo install -d -m 700 /etc/prrr/keys /var/lib/prrr
```

Create `/etc/prrr/server.toml` from the complete [server example](../reference/configuration.md#server-configuration), replacing the domain and certificate paths. Keep it readable only by the account running the server. Use an already valid certificate for the actual server name and keep client certificate verification enabled.

On the server, enable IPv4 forwarding and arrange your firewall's forwarding/NAT policy for the selected tunnel subnet (`10.66.66.0/24` in the example) through its intended Internet interface. Integrate those rules with the server's existing firewall manager rather than flushing its policy. The server process creates TUN devices; it does not replace the administrator's egress and firewall configuration.

Start the server in the foreground for the first verification:

```sh
sudo /usr/local/bin/prrr server --config /etc/prrr/server.toml \
  --listen 0.0.0.0:443 --server-name vpn.example.net
```

Use your real name and keep another administrator session available. Once the connection and forwarding checks pass, put that same command under your chosen service manager. Select a transport explicitly instead of relying on the differing fallback defaults.

The repository also contains server installer scripts. Some write legacy sections such as `[keys]` and `[database]`, while the current runtime reads `[crypto]` and `[server].data_dir`. This guide uses the current manual configuration instead of treating those generated files as verified setup.

| Transport | Network path | What must be reachable |
| --- | --- | --- |
| HARP | HTTPS-based HTTP/2, WebSocket, or polling | The selected TCP endpoint, commonly 443 |
| MASQUE | QUIC with datagram framing | The selected UDP endpoint, commonly 443 |

Run `prrr server --config /etc/prrr/server.toml doctor` to inspect configuration and dependencies. Keep any web admin listener private; its separate listener is plain HTTP unless TLS is terminated in front of it. See [admin API boundaries](../reference/api.md).

## Install the Linux client

First obtain a [complete client configuration](provision-client.md), then run:

```sh
sudo ./deploy/client/install-client.sh ./my-laptop.toml
sudo systemctl start prrr-client
```

The installed paths are `/usr/local/bin/prrr`, `/usr/local/bin/prrr-route`, `/etc/prrr/client.toml`, and `/etc/systemd/system/prrr-client.service`. The configuration is copied with mode 600.

`make install` and `cargo install --path .` target `~/.cargo/bin`; they do not update the service's executable or routing hook. To update a service installation while preserving its existing configuration:

```sh
make install-system
sudo systemctl restart prrr-client
```

## Verify and undo

Follow [your first connection](../tutorials/first-tunnel.md#4-verify-the-data-plane). Stop the service with `sudo systemctl stop prrr-client` and disable it with `sudo systemctl disable prrr-client` when it should not start at boot. Preserve identity/configuration files until you intentionally revoke or migrate the client.
