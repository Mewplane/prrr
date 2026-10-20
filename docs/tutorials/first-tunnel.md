# Make your first tunnel connection

You will provision one client, connect it to a server, verify that traffic crosses the tunnel, and disconnect cleanly. Use two Linux hosts and an administrator-controlled server; this tutorial does not change the machine running the documentation checks.

## Prerequisites

Complete [installation](../how-to/install.md). The server needs a reachable endpoint, a certificate trusted by the client for its real DNS name, configured forwarding/NAT, and a permitted transport port. The client needs TUN support and administrative privileges. Keep another working connection to the host available.

Select the same transport explicitly on both ends. This tutorial uses MASQUE on UDP 443. The minimal server transport entry is:

```toml
[[transports]]
name = "masque"
enabled = true
tls_cert = "/etc/letsencrypt/live/vpn.example.net/fullchain.pem"
tls_key = "/etc/letsencrypt/live/vpn.example.net/privkey.pem"
```

`vpn.example.net` is an example name: replace it with your server's domain and certificate paths. See [server configuration](../reference/configuration.md#server-configuration) for the accompanying server, network, and key settings.

## 1. Save the first client configuration

On the server, register a client using the same configuration and endpoint as the running server:

```sh
umask 077
sudo prrr server --config /etc/prrr/server.toml \
  --listen 0.0.0.0:443 --server-name vpn.example.net \
  client add my-laptop > my-laptop.toml
```

The command writes a complete client TOML to standard output, including its private key. Save this first result securely; a later `client export` does not recover that private key. Transfer the file to your client through an authenticated private channel.

## 2. Choose the traffic to carry

For a first IPv4 egress check, add or edit the existing routing section in the client file:

```toml
[routing]
all_traffic = true
resources = []
```

This selects the VPN default route for IPv4. Detected private local-LAN networks remain excluded unless you also choose `full_tunnel = true`. It does not prove IPv6 traffic is tunneled. See [routing policies](../reference/configuration.md#routing-policies) before using a different mode.

## 3. Install the client service

From a current source checkout on the client:

```sh
cargo build --locked --release --bin prrr
sudo ./deploy/client/install-client.sh ./my-laptop.toml
sudo systemctl start prrr-client
```

The installer copies the built binary, routing hook, systemd service, and mode-600 configuration to their system paths. It also scopes NetworkManager's unmanaged-interface rule to `prrr*`. The service uses `/usr/local/bin/prrr`, not the copy installed by `cargo install` into your home directory.

## 4. Verify the data plane

```sh
systemctl status prrr-client
ip -4 addr show prrr0
ip -4 rule
resolvectl status
curl -4 --fail https://api.ipify.org
```

Confirm that the tunnel has its assigned address, policy rules exist, DNS ownership matches the selected routing mode, and the final command reports your server's public egress address. A running service or a completed handshake alone does not prove packet forwarding works.

Review logs with `journalctl -u prrr-client -n 100`. Once the checks pass, `sudo systemctl enable prrr-client` enables it for subsequent boots.

## 5. Disconnect and verify recovery

```sh
sudo systemctl stop prrr-client
ip -4 rule
resolvectl status
```

The routing hook removes tunnel rules and DNS advertisements so the host's ordinary network can take over. This is availability-oriented recovery, not an Internet-blocking kill switch.

## Next steps

Watch the [handshake and packet walkthroughs](../explanation/mechanics.md), learn [resource routing](../reference/configuration.md#routing-policies), or use the [recovery guide](../how-to/recover.md).

<!-- Tutorial structure informed by the Good Docs Project; original source-checked prose. -->
