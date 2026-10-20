# Provision and revoke a client

Create an identity that the server registry can authorize, transfer its complete configuration, and retain control over its access.

## Create the client once

On the server:

```sh
umask 077
sudo prrr server --config /etc/prrr/server.toml \
  --listen 0.0.0.0:443 --server-name vpn.example.net \
  client add my-laptop > my-laptop.toml
```

Use the server's real endpoint and configured transport. The first output includes the client's inline private key and the server's public identity/KEM keys. Treat the entire TOML and any QR code derived from it as credentials.

Add `--qr` to `client add` if you need an SVG QR code for the Android scanner. Keep the generated SVG private and remove transferred copies when they are no longer needed.

## Import or install

For a per-user CLI configuration:

```sh
umask 077
prrr client import ./my-laptop.toml
chmod 600 "$HOME/.config/prrr/client.toml"
prrr client --config "$HOME/.config/prrr/client.toml" doctor
```

Import validates the TOML structure and writes the configuration to the user's configuration directory. Applying a restrictive umask and permissions is still appropriate: the configuration can contain an inline private key.

For the system service, use the [client installer](install.md#install-the-linux-client), which copies configuration to `/etc/prrr/client.toml`. On Android, use the scanner/import flow described in [the Android guide](android.md).

## List and export

```sh
sudo prrr server --config /etc/prrr/server.toml client list
sudo prrr server --config /etc/prrr/server.toml \
  --listen 0.0.0.0:443 --server-name vpn.example.net \
  client export my-laptop --output exported.toml
```

Export reproduces connection/public configuration without recovering the private key from the initial registration. Preserve the original client credential if you need to move it; otherwise provision a new identity and revoke the old one.

## Revoke

```sh
sudo prrr server --config /etc/prrr/server.toml client remove my-laptop
```

Removal marks the registry identity as revoked for authorization. Do not infer that every existing encrypted session has been synchronously terminated: active session management is a separate server/API concern. Verify the registry and active connection state when immediate disconnection matters.

Source: [CLI handlers](https://github.com/Mewplane/prrr/blob/191ebaf/src/cli.rs), [client configuration generator](https://github.com/Mewplane/prrr/blob/191ebaf/src/distribution.rs).
