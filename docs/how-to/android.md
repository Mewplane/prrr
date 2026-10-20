# Use the Android companion

The Android app uses the shared Rust mobile library and Android's VPN service. It imports a client configuration and establishes the tunnel on the phone.

## Build

Use the checked-in Gradle wrapper and Android build scripts. Install the Android SDK/NDK and the Rust targets used by the script, then run:

```sh
make android-debug
make android-install
```

`NDK_HOME=/path/to/ndk make android-debug` selects an explicit NDK. `make android-debug-apk` rebuilds only the Kotlin app and requires an already current native library; it is not a substitute for rebuilding changed Rust code.

## Import and connect

Provision a [complete client configuration](provision-client.md). Scan its QR code or use the application's import controls, check the server name and selected transport, and approve Android's VPN permission prompt. Keep the configuration and QR private: they may contain the client's private key.

Confirm traffic reaches the intended server, rather than relying only on the connected indicator. Android routing and background restrictions differ from the Linux systemd service; use the app's diagnostics and status screens for that platform.

## Change or remove an identity

Keep the original credential securely if you need it again. An exported public-only server configuration cannot recreate a lost client private key. Provision a replacement and revoke the old identity when migrating credentials.

Source: [VPN service](https://github.com/Mewplane/prrr/blob/191ebaf/prrr-android/app/src/main/kotlin/com/prrr/vpn/android/vpn/PrrrVpnService.kt), [build targets](https://github.com/Mewplane/prrr/blob/191ebaf/Makefile), [mobile crate](https://github.com/Mewplane/prrr/tree/191ebaf/prrr-mobile).
