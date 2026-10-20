---
hide:
  - toc
---

<div class="sy-hero" markdown>
<img class="sy-hero__mascot" src="assets/prrr.png" alt="prrr pixel cat carrying a gold key">
<div markdown>
<p class="sy-eyebrow">PRIVATE TUNNELS · PUBLIC INTERNET</p>

# A quieter way through.

Understand the tunnel you run. prrr carries encrypted IP traffic over HTTPS-based HARP or QUIC-based MASQUE, with a hybrid handshake and explicit routing and recovery policies.

[Make your first connection](tutorials/first-tunnel.md){ .md-button .md-button--primary }
[Watch the mechanics](explanation/mechanics.md){ .md-button }

</div>
</div>

## Follow one packet

<div class="sy-mechanics" data-flow="packets"></div>

1. Your application's IP packet reaches the TUN interface.
2. prrr encrypts it with a directional session key and authenticates its counter.
3. HARP or MASQUE carries the ciphertext to the server.
4. The server verifies and decrypts it, then passes the packet to its configured network path.
5. The reply travels back through the encrypted channel. A duplicate counter is rejected.

These are illustrative sample packets, not your traffic. Playback starts paused; choose **Play** or a chapter. The explanation remains readable without JavaScript.

## Choose your path

<div class="sy-card-grid" markdown>
<div class="sy-card" markdown>
### Get connected

[Install](how-to/install.md), [provision one client](how-to/provision-client.md), then follow [your first tunnel](tutorials/first-tunnel.md).
</div>
<div class="sy-card" markdown>
### Understand what happens

Explore [the handshake, encrypted packet path, and recovery](explanation/mechanics.md), then read [the security boundaries](explanation/security.md).
</div>
<div class="sy-card" markdown>
### Keep the route working

Diagnose the data plane with [recovery checks](how-to/recover.md); use [configuration](reference/configuration.md) to choose full or resource routing.
</div>
<div class="sy-card" markdown>
### Look up the details

Find the [CLI](reference/cli.md), [wire formats](reference/protocol.md), [admin API](reference/api.md), and [glossary](reference/glossary.md).
</div>
</div>

## What this protects—and what stays visible

The tunnel encrypts traffic between its client and server. A network observer can still see the endpoint, connection timing, and traffic volume; the server remains a trust boundary. Browser-like TLS settings do not establish indistinguishability from a browser, and reconnecting is not a kill switch. See [security boundaries](explanation/security.md) before deployment.

These pages describe the source at revision [`191ebaf`](https://github.com/Mewplane/prrr/tree/191ebaf). That revision removed built-in Whisper messaging. Earlier flat guides remain in the repository as historical material; this site's navigation uses the new source-checked guides.

[Source](https://github.com/Mewplane/prrr) · [Report a problem](https://github.com/Mewplane/prrr/issues) · [Contribute to the docs](contributing/documentation.md)
