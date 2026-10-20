---
hide:
  - toc
---

# How the tunnel works

There are three separate questions: how the peers establish a session, how an IP packet crosses that session, and how the host chooses and recovers its network path. The walkthroughs keep those boundaries visible.

[Session setup](#establish-a-session) · [Packet round trip](#follow-a-packet-and-its-reply) · [Routing and recovery](#routing-and-recovery)

All illustrated values are examples. The diagrams do not open connections, inspect your network, or generate credentials. Playback starts paused; use chapter buttons to inspect a state, or **Play** and the speed control to follow messages. Reduced motion preserves chapter navigation and stops moving envelopes. Complete transcripts follow each scene.

## Establish a session

<div class="sy-mechanics" data-flow="handshake"></div>

1. **Pinned identities.** The client holds a private Noise identity and the server's known Noise and ML-KEM public keys. The server maintains an authorization registry for client identities. Knowing how to speak the protocol does not make an identity authorized.
2. **Outer transport.** HARP uses its HTTPS endpoint and HTTP/2, WebSocket, or polling bindings. MASQUE uses the QUIC/datagram path. Both sides must choose compatible transport settings and the client must verify the real server certificate/name.
3. **Noise message one.** The client encapsulates a secret to the server's ML-KEM-768 key. It includes the 1088-byte KEM ciphertext inside the first Noise IK message payload. The outer transport carries that handshake message.
4. **Authorize the client.** The server processes the first message, obtains the client's static identity, checks authorization, and decapsulates the KEM payload. Rejection prevents an application tunnel even if an outer connection exists.
5. **Noise message two.** The server sends the second authenticated Noise message. The client completes the transcript using its pinned responder identity.
6. **Derive directional keys.** HKDF-SHA256 uses the Noise handshake hash as salt, the ML-KEM shared secret as input, and an identity-bound info string. Its 96-byte output becomes three 32-byte keys. The encrypted packet channel uses the two directional keys; client-send is server-receive.
7. **Tunnel ready.** The connected client installs its selected routing policy and starts the packet pipeline. A successful handshake establishes session state; successful forwarding still depends on TUN configuration, routes, and the server's network setup.

The actual KDF inputs and literal info prefix are listed in [protocol reference](../reference/protocol.md#hybrid-handshake). This describes the implementation; it is not a substitute for an independent protocol security analysis.

## Follow a packet and its reply

<div class="sy-mechanics" data-flow="packets"></div>

1. **Application to TUN.** The host routes an application IP packet to the virtual interface when the configured policy selects that destination. Excluded destinations take the ordinary host route.
2. **Seal the packet.** ChaCha20-Poly1305 encrypts the packet. The inner record contains an 8-byte big-endian absolute counter, ciphertext, and a 16-byte authentication tag. Four zero bytes plus the epoch-local counter form the 12-byte nonce; the encoded absolute counter is also authenticated as additional data.
3. **Wrap the ciphertext.** HARP adds a 4-byte header before HTTP carriage. MASQUE adds its HTTP Datagram framing with quarter-stream and context IDs. These are alternative carriers of the inner channel, not additional rounds of the hybrid handshake.
4. **Cross the network.** The outer TLS/QUIC path carries the inner ciphertext. Endpoint addresses, packet sizes, and timing remain observable. TLS termination is a separate trust boundary from inner tunnel decryption.
5. **Verify and forward.** The server checks replay state and the AEAD tag before passing recovered IP data to the client TUN. Host forwarding and NAT move the packet toward its destination. The VPN server can observe this recovered packet; application-level HTTPS adds its own protection beyond that hop.
6. **Destination replies.** The return IP packet reaches the server. The server uses the opposite-direction key and its independent counter to protect it for the client.
7. **Open the return packet.** The client verifies, decrypts, and injects the accepted reply into its TUN device, where the host delivers it to the application.
8. **Reject a replay.** Duplicate or sufficiently old counters are rejected. The default sliding window tolerates reordering across 2048 counters. Altered ciphertext fails authentication and is not forwarded as a valid IP packet.

The channel's counter field is shown inside the outer carrier. It is not a claim that an ordinary network observer can read that field through outer TLS. See [exact packet and transport framing](../reference/protocol.md).

## Routing and recovery

<div class="sy-mechanics" data-flow="routing"></div>

1. **Select a policy.** Configure resource destinations, explicit prefixes, or the IPv4 default route. `all_traffic` and the separate `full_tunnel` LAN-exclusion switch have different jobs.
2. **Route a resource.** Hostnames resolve to IPv4 destinations installed as `/32` routes. A separate refresh task updates them while the packet pump continues running. Initial resolution failure prevents startup; refresh failure does not justify deleting the working route set immediately.
3. **Preserve bypasses.** Firewall marks keep the tunnel's own transport connection on the host path rather than feeding it into itself. Detected private local-LAN networks are excluded by default; `full_tunnel` can disable that automatic exclusion.
4. **Gate tunnel DNS.** Independent probes measure configured tunnel resolver paths. Advertise responders while healthy, withdraw stale/unusable tunnel DNS when required, and retain the pinning routes so the measurement still follows the tunnel. Split routing scopes DNS ownership to the selected resources.
5. **Detect a black hole.** The watchdog looks for repeated outbound progress without inbound progress. An established socket is not proof of working traffic. DNS probes and resource resolution run without blocking the packet pump.
6. **Back off and reconnect.** On failure, remove tunnel routing, wait with bounded exponential backoff and jitter, and try a new connection/handshake. Ordinary host routes can apply while the tunnel is down. This is availability-oriented fallback, not fail-closed traffic blocking.
7. **Restore the session.** A successful handshake supplies fresh keys, resets backoff, and installs routes again. The client retains its TUN across reconnects, preserving the interface and assigned client address.

The [recovery guide](../how-to/recover.md) gives diagnostic commands and measured defaults. Do not treat the animation as a complete operating-system routing policy or a promise of IPv6 capture.

## Source trail

These observations are pinned to revision `191ebaf`:

- [Client transport and handshake paths](https://github.com/Mewplane/prrr/blob/191ebaf/src/client.rs)
- [Hybrid handshake and session keys](https://github.com/Mewplane/prrr/blob/191ebaf/src/handshake/hybrid.rs)
- [HARP session authorization](https://github.com/Mewplane/prrr/blob/191ebaf/src/web/harp.rs)
- [Encrypted channel](https://github.com/Mewplane/prrr/blob/191ebaf/src/transport/encrypted_channel.rs)
- [Routing manager](https://github.com/Mewplane/prrr/blob/191ebaf/src/routing.rs) and [reconnect loop](https://github.com/Mewplane/prrr/blob/191ebaf/src/reconnect.rs)
