# DPI Hardening Phase 2: UDP Obfuscation and DNS-over-HTTPS (DoH)

## 1. Overview
As Deep Packet Inspection (DPI) systems become more advanced, simply relying on standard protocols like QUIC/TLS with a spoofed SNI (Server Name Indication) is no longer sufficient in highly restricted environments. Firewalls can block connections based on TLS handshakes, SNI mismatches, or even general UDP traffic heuristics.

This specification outlines two complementary hardening mechanisms to defeat advanced DPI and DNS-based censorship:
1. **Pre-Shared Key (PSK) UDP Obfuscation**
2. **Built-in DNS-over-HTTPS (DoH) Client**

---

## 2. Pre-Shared Key (PSK) UDP Obfuscation (Outer Wrapper)

### 2.1. Objective
Hide the QUIC/TLS handshake entirely from the ISP's DPI appliances. Make the UDP traffic look like unidentifiable, random noise, preventing any protocol fingerprinting.

### 2.2. Architecture
Instead of sending standard QUIC packets over UDP, `prrr` will wrap the UDP payload in an obfuscation layer.

1. **The Shared Secret**: The server and the client share a symmetric key (PSK). This key is generated securely when the client is created (`client add`) and distributed out-of-band within the client configuration file (`client.toml`).
2. **Obfuscation Cipher**: Apply a fast, non-expanding stream cipher (e.g., ChaCha20) or a deterministic XOR mask using the PSK to the raw QUIC packets *before* they hit the network socket.
3. **Decapsulation**: The receiving end reads the UDP datagram, applies the reverse cipher using the PSK, and passes the decrypted payload to the QUIC engine (`quinn`).

### 2.3. Implementation Details
* **Cipher Selection**: Since the QUIC protocol itself is already authenticated and encrypted via TLS 1.3, the outer obfuscation does *not* need an AEAD (like AES-GCM or ChaCha20-Poly1305) which would add overhead bytes. A simple ChaCha20 stream cipher using the PSK and a randomized nonce (sent in the first few bytes of the packet) is sufficient to randomize the payload.
* **Packet Structure**:
  * `[Nonce (8 bytes)] + [Obfuscated QUIC Payload]`
* **Configuration**:
  * Added to `[obfuscation]` section in `server.toml` and `client.toml`.
  * `psk_obfuscation = true`
  * `obfuscation_key = "<base64_encoded_key>"`

### 2.4. Trade-offs
* **Pros**: 100% defeats SNI inspection. The TLS ClientHello is never visible in plaintext. The traffic has zero recognizable protocol signatures.
* **Cons**: Small CPU overhead for double-encryption (QUIC TLS + Outer Obfuscation). Adds a few bytes (nonce) to every packet, slightly reducing the effective MTU available for the inner payload.

---

## 3. Built-in DNS-over-HTTPS (DoH) Client

### 3.1. Objective
Bypass ISP-level DNS hijacking, filtering, and poisoning. Ensure the client can always resolve the real IP address of the `prrr` server endpoint, even if the local network's DNS server blocks or lies about the domain.

### 3.2. Architecture
Instead of relying on the operating system's DNS resolver (which typically sends plaintext UDP port 53 requests to the local router or ISP), `prrr` will perform its own DNS resolution over an encrypted HTTPS connection to a trusted provider.

1. **Resolution Hook**: When the client attempts to connect to `endpoint = "prrr.tech:443"`, it intercepts the DNS resolution step.
2. **Encrypted Query**: The client sends a DoH query (RFC 8484) over TLS/HTTPS to a hardcoded or configured trusted resolver (e.g., Cloudflare `1.1.1.1` or Google `8.8.8.8`).
3. **Connection**: Once the true IP is resolved via the secure DoH channel, the QUIC engine connects directly to that IP.

### 3.3. Implementation Details
* **Resolver Integration**: Utilize a lightweight Rust DoH library or implement a simple HTTPS client using `reqwest`/`hyper` (if already in dependency tree) to query `https://cloudflare-dns.com/dns-query`.
* **Fallback Mechanism**:
  1. Try configured DoH provider.
  2. If unreachable (e.g., DoH is blocked), fallback to standard OS resolution as a last resort.
* **Configuration**:
  * Added to `[client]` or `[network]` section in `client.toml`.
  * `use_doh = true`
  * `doh_provider = "https://cloudflare-dns.com/dns-query"`

### 3.4. Trade-offs
* **Pros**: completely immune to local DNS poisoning. Prevents the ISP from even knowing which domain the client *intends* to connect to via DNS logs.
* **Cons**: The initial connection takes slightly longer due to the HTTPS overhead of the DoH query. DoH endpoints themselves can technically be IP-blocked by extremely restrictive regimes (though rarely done due to collateral damage).

---

## 4. Synergy
When used together, these two features create a highly resilient connection pipeline:
1. The client securely discovers the server's IP via **DoH**, bypassing DNS blocks.
2. The client establishes a connection to that IP using **PSK UDP Obfuscation**, bypassing SNI filters and generic protocol fingerprinting.
