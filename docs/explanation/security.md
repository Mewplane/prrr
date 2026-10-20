# Security boundaries

prrr encrypts a tunnel between a client and an operator-controlled server. Its protocol and transport choices address specific threats; they do not establish anonymity, universal censorship resistance, or an indistinguishable browser fingerprint.

## Who can observe what

| Boundary | What remains relevant |
| --- | --- |
| Local device | Private configuration, identity keys, process memory, installed binary, and OS route policy. |
| Network path | Endpoint addresses, timing, volume, packet sizes, and observable transport characteristics. |
| TLS terminator / relay | Outer transport information; assess where TLS actually terminates in your deployment. |
| VPN server | Client authorization and recovered IP packets, forwarding metadata, and any unencrypted application traffic. |
| Destination | The server's egress address and application traffic presented to it. |

Application-level HTTPS is still valuable across and beyond the VPN server. A VPN does not make a compromised endpoint trustworthy.

## Identity, session encryption, and certificates

The inspected client and server paths integrate Noise IK and ML-KEM-768. The registry authorizes a client identity, and the session KDF binds keys to the handshake transcript and static identities. The packet channel uses directional ChaCha20-Poly1305 keys, authenticated counters, and replay tracking. Read [the exact mechanics](mechanics.md), including the KDF inputs, instead of inferring a stronger property from the label “hybrid.”

Certificate verification and pinned protocol identities are separate checks. Use the real server name and a valid chain. `--insecure` disables TLS certificate verification; reserve it for controlled experiments, not the documented deployment path.

Private server keys and client configurations are files. A configuration or QR code containing an inline private key is a credential. Restrict permissions, transfer it through an authenticated channel, and avoid logging it. Secret zeroization on drop reduces some memory lifetime; it does not protect against arbitrary access to a running process or a compromised host.

## Traffic disguise has limits

The TLS mimicry module explicitly describes approximate control over cipher/group ordering and the limitations of stock rustls. Browser profiles do not reproduce every browser extension, fingerprint, HTTP behavior, or traffic distribution. Padding, decoy pages, and HTTP carriage each change observable characteristics; their existence is not evidence that a censor cannot classify or block a deployment.

The source contains probing-resistance and traffic-shaping components. Configuration parsing alone does not prove that every component is enabled on every transport/caller path. This site avoids the older blanket “undetectable” claims.

## Routing is part of the security boundary

Check what your actual OS policy captures. Resource routes select exact IPv4 addresses; full IPv4 routing does not establish IPv6 coverage. Local-LAN exclusions and the server-endpoint bypass intentionally leave paths outside the tunnel.

The reconnect loop withdraws tunnel routes and unhealthy DNS advertisements so the ordinary host path can recover. That behavior is **not a kill switch**. If blocking all untunneled traffic is your requirement, evaluate and test an explicit host firewall policy separately; do not assume reconnect implements it.

## Admin and configuration distribution

The separate web admin listener serves HTTP in its active caller. Keep it loopback/private and use a controlled TLS proxy if exposing administration remotely. Bearer tokens, initial creation responses, QR codes, and configuration-sharing URLs need appropriate access control. HARP's VPN session authorization and the admin JWT are separate mechanisms.

Revoking a registry identity is not the same operation as terminating every already established session. Inspect active sessions and test your operational revocation procedure.

## Client-to-client sharing

Sharing is opt-in and has local state plus server-side pair/registry checks. The current remote-enable verifier uses a keyed BLAKE3 MAC behind a verifier interface. Do not describe that implementation as an Ed25519 verification chain or infer hardware-backed biometric authentication from an interface name.

Built-in Whisper messaging was removed from the inspected source revision. Historical messaging explanations do not describe the current application.

## Source and verification

- [TLS profile limitations](https://github.com/Mewplane/prrr/blob/191ebaf/src/obfuscation/tls_mimicry.rs)
- [TLS verification](https://github.com/Mewplane/prrr/blob/191ebaf/src/transport/tls.rs)
- [Admin listener](https://github.com/Mewplane/prrr/blob/191ebaf/src/web/mod.rs) and [authentication](https://github.com/Mewplane/prrr/blob/191ebaf/src/web/auth.rs)
- [Sharing verifier](https://github.com/Mewplane/prrr/blob/191ebaf/src/sharing.rs)
- [Routing](https://github.com/Mewplane/prrr/blob/191ebaf/src/routing.rs) and [recovery](https://github.com/Mewplane/prrr/blob/191ebaf/src/reconnect.rs)

Run the project's tests and dependency checks for your selected revision. Passing documentation/browser tests establishes that the guides and illustrations work; it does not constitute a cryptographic audit of the protocol.
