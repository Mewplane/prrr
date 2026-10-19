# Understanding prrr: A Censorship-Resistant VPN

**Building Undetectable, Post-Quantum Secure Network Tunnels**

---

## Preface

This book will take you on a journey from understanding why censorship happens and how VPNs work, all the way to the cutting-edge cryptography and network engineering that makes prrr unique. You don't need to know anything about cryptography, networking, or VPNs to start—we'll build that knowledge together.

By the end, you'll understand:
- Why traditional VPNs fail in censorship environments
- How cryptography protects your data (even from future quantum computers)
- How network traffic can be made invisible to censors
- The complete architecture of a production VPN system

---

# Part I: Foundations

## Chapter 1: The Problem—Internet Censorship

### What is Internet Censorship?

Imagine you're trying to visit a website, but your internet provider blocks it. Not because it's malicious, but because your government decided you shouldn't see it. This is internet censorship.

**How Censorship Works:**

1. **DNS Blocking** - When you type "google.com", your computer asks a DNS server "what's the IP address for google.com?" The censor can lie and give you the wrong address.

2. **IP Address Blocking** - Even if you know the real IP address (like 142.250.80.46), the censor can block all traffic to that specific address.

3. **Deep Packet Inspection (DPI)** - This is the most sophisticated approach. The censor examines the *content* of your network traffic, looking for patterns that identify what you're doing.

### Example: Reading an Email

When you check your email without encryption, here's what travels across the internet:

```
From: alice@example.com
To: bob@example.com
Subject: Meeting tomorrow
Body: Let's meet at the café at 3pm
```

Anyone along the path (your ISP, government, network operators) can read this. With DPI, they can:
- See you're using Gmail
- Read your email content
- Block access if they don't like what you're doing

### The Solution: Encryption and Tunneling

A VPN (Virtual Private Network) creates an encrypted tunnel. Instead of sending readable emails, you send scrambled data that looks like random noise:

```
87a3f2d91b4e...c39f1a2d (encrypted data)
```

The censor can see you're sending data, but can't read it or easily tell what service you're using.

**But there's a problem:** If the censor can *identify* that you're using a VPN, they can block it entirely.

This is where prrr comes in. Its default transport, HARP, tunnels VPN traffic over standard HTTPS — making it impossible to block without breaking the entire web.

---

## Chapter 2: How VPNs Work (The Basics)

### The Tunnel Metaphor

Imagine you want to send a letter from your house to your friend's house, but there's a nosy neighbor who reads everyone's mail.

**Without a VPN:** You put the letter in an envelope and drop it in the mailbox. The neighbor intercepts it, reads it, and decides whether to let it through.

**With a VPN:** 
1. You put your letter in an envelope (your actual data)
2. You put that envelope inside a second, locked envelope addressed to a trusted courier (the VPN server)
3. The courier receives the locked envelope, opens it, and forwards the original letter to your friend
4. Your friend's reply goes back through the courier to you

The nosy neighbor sees you sending mail to the courier, but can't read the contents or see who the final recipient is.

### Technical Components

A VPN has three main parts:

1. **Client** - Software on your computer that encrypts your data and sends it to the VPN server

2. **Server** - A computer (usually in another country) that receives your encrypted data, decrypts it, and forwards it to the actual destination

3. **Tunnel** - The encrypted connection between client and server

### What Happens When You Visit a Website with a VPN

Let's say you want to visit `https://news-site.com`:

**Step 1: Your Computer**
```
"I want to visit news-site.com"
  ↓
[VPN Client encrypts request]
  ↓
Encrypted data sent to VPN server
```

**Step 2: VPN Server**
```
[VPN Server receives encrypted data]
  ↓
[Decrypts and sees: "visit news-site.com"]
  ↓
Connects to news-site.com on your behalf
  ↓
Receives the website content
  ↓
Encrypts and sends it back to you
```

**Step 3: Your Computer Again**
```
[Receives encrypted response]
  ↓
[VPN Client decrypts]
  ↓
You see the news website
```

### What Your ISP (or Censor) Sees

Without a VPN:
```
Alice's computer → "connecting to news-site.com" → Internet
                   (completely visible)
```

With a VPN:
```
Alice's computer → "encrypted blob to VPN server" → VPN Server → news-site.com
                   (ISP can't see final destination)
```

The ISP sees you connecting to the VPN server, but not what websites you're actually visiting.

---

## Chapter 3: Why Traditional VPNs Fail Against Censorship

### The Identification Problem

Even though your data is encrypted, censors can still *identify* that you're using a VPN by looking at patterns in your network traffic.

**Example 1: OpenVPN**

OpenVPN has a distinctive "handshake" when you connect:

```
Client: "Hello, I'm an OpenVPN client"
Server: "Hello, I'm an OpenVPN server"
[They exchange specific codes and patterns]
```

A censor using DPI can recognize these patterns and say: "Aha! This is OpenVPN. Block it!"

**Example 2: WireGuard**

WireGuard is very efficient but uses a custom protocol. It sends packets that look different from normal web traffic:

```
Normal web traffic:    [HTTP/HTTPS headers visible]
WireGuard traffic:     [Strange binary pattern that doesn't match anything else]
```

Again, DPI can identify this: "This doesn't look like a website, email, or anything normal. It's probably a VPN. Block it!"

### The Active Probing Attack

Some censors are even more clever. When they suspect a server might be a VPN, they actively probe it:

```
Censor sends: "Hello, are you a VPN server?"
VPN server responds: "Yes, I am" (by behaving like a VPN)
Censor: "Blocked!"
```

### What We Need Instead

To defeat modern censorship, a VPN must:

1. **Look like normal HTTPS traffic** - Indistinguishable from browsing websites
2. **Use standard ports** - Port 443 (the HTTPS port everyone uses)
3. **Resist active probing** - Not respond to probes in a way that identifies it as a VPN
4. **Use modern cryptography** - Protect against both current and future attacks

This is exactly what prrr does.

---

## Chapter 4: Cryptography Basics (For Everyone)

Before we dive into how prrr works, we need to understand some cryptography basics. Don't worry—we'll use simple analogies.

### Encryption: Making Data Unreadable

**Analogy:** A lockbox

- **Plaintext** - Your message before encryption ("Meet me at 3pm")
- **Ciphertext** - The encrypted version (looks like random garbage: "x7k9$mP2...")
- **Key** - The secret needed to encrypt and decrypt (like a physical key to the lockbox)

**Symmetric Encryption** - Same key for locking and unlocking

```
Alice has key #42
Message: "Hello" → Encrypt with key #42 → "9f3a2b"
Send "9f3a2b" to Bob
Bob has key #42
Receive "9f3a2b" → Decrypt with key #42 → "Hello"
```

**Problem:** How do Alice and Bob agree on key #42 without someone intercepting it?

### Key Exchange: Sharing Secrets Over Public Channels

**Analogy:** The color mixing trick

Imagine Alice and Bob want to share a secret color, but Eve is watching everything they do:

1. Alice and Bob publicly agree on a "base color" (say, yellow) - Eve hears this
2. Alice picks a secret color (red) and mixes it with yellow → orange. Sends orange to Bob
3. Bob picks a secret color (blue) and mixes it with yellow → green. Sends green to Alice
4. Alice receives green, adds her secret red → final color
5. Bob receives orange, adds his secret blue → final color
6. Alice and Bob both end up with the same final color (brownish mix)
7. Eve saw yellow, orange, and green, but can't figure out the final color without knowing the secrets

**In real cryptography:** This is called Diffie-Hellman key exchange, using math instead of colors. The math makes it impossible for Eve to figure out the secret even though she sees the public exchange.

### X25519: Modern Key Exchange

X25519 is a modern, fast algorithm for key exchange:

```
Alice generates: 
  - Secret key (random number, kept private)
  - Public key (derived from secret, safe to share)

Bob generates:
  - Secret key (different random number, kept private) 
  - Public key (derived from secret, safe to share)

Alice and Bob exchange public keys
Both use math to derive the same shared secret
This shared secret becomes the encryption key
```

**Why it's secure:** The math problem (elliptic curve discrete logarithm) is so hard that even supercomputers would take billions of years to break it.

### Authenticated Encryption: Preventing Tampering

What if someone intercepts your encrypted message and changes it?

```
Original ciphertext: "x7f3a92k..."
Attacker changes it: "x7f3HACK..."
```

Even though they can't read it, they might cause problems. **Authenticated Encryption** solves this by adding a "seal":

```
Message: "Hello"
  ↓
Encrypt: "9f3a2b"
  ↓
Add authentication tag: "9f3a2b" + "seal:a8c4d2"
```

If anyone changes even one bit of the ciphertext, the seal won't match, and decryption will fail. You know the message has been tampered with.

**ChaCha20-Poly1305** is the algorithm prrr uses for this. It:
- Encrypts data with ChaCha20 (the "lock")
- Adds an authentication tag with Poly1305 (the "seal")

### The Quantum Computer Threat

**What's a quantum computer?** A theoretical computer that uses quantum mechanics to solve certain math problems exponentially faster than regular computers.

**The problem:** Quantum computers could break X25519 and most current encryption in seconds.

**The solution:** Post-quantum cryptography—new algorithms that even quantum computers can't break efficiently.

**ML-KEM-768** is a post-quantum algorithm based on lattice mathematics (imagine trying to find a specific needle in a billion haystacks where each haystack keeps moving). Even quantum computers find this intractable.

### Hybrid Cryptography: Best of Both Worlds

What if ML-KEM turns out to be breakable? What if quantum computers take longer to build than expected?

**Hybrid approach:** Use both!

```
Shared secret = X25519 output + ML-KEM output combined
```

An attacker would need to break BOTH algorithms to read your data. If quantum computers break X25519, ML-KEM protects you. If ML-KEM has a flaw, X25519 still protects you.

This is what prrr does.

### Hashing: Fingerprinting Data

A hash function takes any data and produces a fixed-size "fingerprint":

```
Hash("Hello") = "a3f8c9..."
Hash("Hello!") = "b2d4e1..." (completely different!)
Hash(entire book) = "7f2a3c..." (still same size output)
```

**Properties:**
- Same input always gives same output
- Tiny change in input completely changes output
- Impossible to reverse (can't get original data from hash)
- No two different inputs produce the same output (practically)

**BLAKE2s** is prrr's hash function—fast, secure, and modern.

### Key Derivation: Making Many Keys from One Secret

Sometimes you need multiple keys (one for encryption, one for authentication, etc.) but only have one shared secret.

**HKDF (Hash-based Key Derivation Function):**

```
Secret: "x7a3f9b2..."
  ↓ HKDF
Key 1 (for encryption): "a8c3d2..."
Key 2 (for authentication): "f4e9b1..."
Key 3 (for headers): "c7f2a3..."
```

Each key is mathematically independent—knowing one doesn't help you figure out the others.

---

# Part II: Network Architecture

## Chapter 5: The Internet Protocol Stack

To understand how prrr works, we need to understand how internet communication is layered.

### The Layer Cake Model

Think of sending data across the internet like sending a package through multiple delivery services:

**Layer 7: Application (What you actually want to send)**
```
"GET /index.html" - your web request
```

**Layer 4: Transport (Breaking it into packages)**
```
Package 1: "GET /in"
Package 2: "dex.htm"
Package 3: "l"
```

**Layer 3: Network (Addressing)**
```
From: 192.168.1.5
To: 142.250.80.46
Data: "GET /in"
```

**Layer 2: Link (Physical network)**
```
[Ethernet frame with physical addresses and data]
```

**Layer 1: Physical (Actual wires/wireless)**
```
Electrical signals: 010110111...
```

### How a VPN Fits In

A traditional VPN operates at Layer 3 (Network):

```
Your computer:
  Application: "Visit website"
  → Layer 3: IP packet to website
  → VPN intercepts
  → Encrypts entire IP packet
  → Wraps in new IP packet addressed to VPN server
  → Sends encrypted package

VPN Server:
  Receives encrypted package
  → Decrypts
  → Gets original IP packet
  → Forwards to actual destination
```

This is called **tunneling**—putting one packet inside another.

### TUN Devices: Virtual Network Interfaces

Your computer has physical network interfaces (WiFi, Ethernet). A **TUN device** is a *virtual* interface created by software.

**Physical interface:**
```
eth0: Connected to WiFi router
      IP: 192.168.1.100
      Sends real network packets
```

**Virtual TUN interface:**
```
prrr0: Created by prrr software
       IP: 10.0.0.2
       Packets written here are captured by prrr
```

When you configure your computer to route traffic through the TUN device:

```
Application says: "Send to google.com"
  ↓
Operating system: "Route this through prrr0"
  ↓
prrr software captures packet from prrr0
  ↓
Encrypts and sends via real network interface
```

This is how prrr intercepts all your traffic.

---

## Chapter 6: QUIC and HTTP/3

### The Evolution of Web Protocols

**HTTP/1.1 (1997):** 
```
Client: "GET /page.html"
Server: "Here's the page"
[Connection must wait for response before next request]
```

**HTTP/2 (2015):**
```
[Multiple requests at once over one connection]
Client: "GET /page.html" + "GET /style.css" + "GET /image.jpg"
Server: [Sends all responses in parallel]
```

**HTTP/3 (2020):**
Built on QUIC instead of TCP. This is revolutionary.

### TCP vs UDP: Reliability vs Speed

**TCP (Transmission Control Protocol):**
```
Client: "Here's packet 1"
Server: "Got it"
Client: "Here's packet 2"
Server: "Got it"
[One packet lost]
Client: "Here's packet 3"
Server: "Didn't get packet 3"
[Resend packet 3]
[Everything waits until packet 3 arrives]
```

TCP guarantees delivery and order, but one lost packet stalls everything (head-of-line blocking).

**UDP (User Datagram Protocol):**
```
Client: "Here's packet 1"
Client: "Here's packet 2"
Client: "Here's packet 3"
[No acknowledgments, no retries, no ordering]
```

UDP is fast but unreliable—perfect for live video where losing a frame doesn't matter.

### QUIC: Best of Both Worlds

**QUIC (Quick UDP Internet Connections)** is built on UDP but adds:
- Reliability (like TCP)
- Multiple independent streams (no head-of-line blocking)
- Built-in encryption (TLS 1.3)
- Connection migration (switch from WiFi to cellular without reconnecting)

```
QUIC connection over UDP:
  Stream 1: Web page HTML [packet lost, retransmit]
  Stream 2: Image loading [continues independently]
  Stream 3: JavaScript loading [continues independently]
```

**Why this matters for prrr:** QUIC traffic is everywhere (used by Google, Facebook, CloudFlare). If prrr uses QUIC, it looks like normal web traffic!

### HTTP/3: QUIC + HTTP

HTTP/3 is HTTP over QUIC:

```
Traditional:
  HTTP → TLS → TCP → IP → Network

HTTP/3:
  HTTP → QUIC (includes TLS) → UDP → IP → Network
```

**ALPN (Application-Layer Protocol Negotiation):**
During the TLS handshake, client and server agree on which protocol to use:

```
Client: "I support h3 (HTTP/3), h2 (HTTP/2), http/1.1"
Server: "Let's use h3"
```

prrr uses ALPN `h3` to look exactly like a web browser.

---

## Chapter 7: MASQUE—Hiding in Plain Sight

### What is MASQUE?

**MASQUE (Multiplexed Application Substrate over QUIC Encryption)** is an IETF standard (RFCs 9297, 9298) for proxying UDP traffic over HTTP/3.

Think of it as "VPN over web traffic."

### Why MASQUE is Perfect for Censorship Resistance

**Traditional VPN traffic:**
```
[Custom protocol that looks suspicious]
Censor: "This doesn't match any known pattern. Block it."
```

**MASQUE traffic:**
```
[Looks exactly like HTTP/3 web traffic]
Censor: "This is just someone browsing websites. Allow it."
```

MASQUE is a *legitimate standard* used by companies. Blocking MASQUE means blocking normal web traffic.

### How MASQUE Works

**Step 1: CONNECT-UDP Handshake**

Client opens a QUIC connection and makes an HTTP request:

```http
CONNECT-UDP /tunnel HTTP/3
Host: vpn.example.com
```

Server responds:

```http
HTTP/3 200 OK
```

Now they have an established tunnel.

**Step 2: Datagram Exchange**

The client and server exchange UDP packets wrapped as HTTP datagrams:

```
Client application: "IP packet to google.com"
  ↓
prrr wraps as HTTP Datagram:
  [Stream ID][Context ID][IP packet data]
  ↓
Sent via QUIC DATAGRAM frame
  ↓
Server receives, extracts IP packet, forwards to google.com
```

### HTTP Datagram Format

```
┌─────────────────┬────────────┬─────────────┐
│ Quarter Stream  │ Context ID │  Payload    │
│      ID         │    (0)     │  (IP packet)│
└─────────────────┴────────────┴─────────────┘
   (varint)         (varint)      (variable)
```

- **Quarter Stream ID:** The HTTP request stream ID divided by 4 (QUIC spec detail)
- **Context ID:** 0 for raw UDP proxying
- **Payload:** The actual data you're sending

**Varint encoding:** Variable-length integer encoding from QUIC spec. Small numbers take 1 byte, larger numbers take 2/4/8 bytes.

### The Beautiful Trick

To any observer (ISP, censor, DPI system):

```
Port: 443 (standard HTTPS port)
Protocol: QUIC (standard web protocol)
ALPN: h3 (standard HTTP/3)
Packets: HTTP Datagrams (standard MASQUE)

Conclusion: Normal web traffic ✓
```

But actually:
```
Inside those HTTP datagrams: Encrypted VPN traffic
```

This is **protocol camouflage**—hiding one thing inside another legitimate thing.

---

# Part III: The prrr Protocol

## Chapter 8: Architecture Overview

Now that we understand the building blocks, let's see how prrr puts them together.

### The Complete Stack

prrr supports two transports. HARP (the default) uses standard HTTPS,
while MASQUE (legacy) uses QUIC/HTTP/3. Both share the same encryption
and tunnel pipeline layers.

```
┌─────────────────────────────────────┐
│  Your Application (browser, etc.)   │
└──────────────┬──────────────────────┘
               │ IP packets
               ↓
┌─────────────────────────────────────┐
│     TUN Device (prrr0)              │
│     Captures all traffic            │
└──────────────┬──────────────────────┘
               │
               ↓
┌─────────────────────────────────────┐
│  Tunnel Pipeline                    │
│  - Reads from TUN                   │
│  - Writes to encrypted channel      │
└──────────────┬──────────────────────┘
               │
               ↓
┌─────────────────────────────────────┐
│  Encrypted Channel                  │
│  - ChaCha20-Poly1305 encryption     │
│  - Replay protection                │
│  - Automatic rekeying               │
└──────────────┬──────────────────────┘
               │
       ┌───────┴───────┐
       ↓               ↓
┌──────────────┐ ┌──────────────┐
│ HARP         │ │ MASQUE       │
│ (default)    │ │ (legacy)     │
│ WebSocket or │ │ HTTP Datagram│
│ HTTP polling │ │ framing      │
└──────┬───────┘ └──────┬───────┘
       ↓               ↓
┌──────────────┐ ┌──────────────┐
│ HTTPS/TLS1.3 │ │ QUIC/TLS1.3  │
│ TCP Port 443 │ │ UDP Port 443 │
└──────────────┘ └──────────────┘
```

### The Two Phases

**Phase 1: Handshake (Establishing the connection)**
```
Client                          Server
  │                               │
  ├─── Hybrid Handshake ────────→│
  │    (X25519 + ML-KEM-768)     │
  │                               │
  │←──── Handshake Response ─────┤
  │                               │
  └─── Both derive session keys ─┘
```

**Phase 2: Data Transfer (VPN operation)**
```
Client                          Server
  │                               │
  ├──── Encrypted IP packets ────→│──→ Internet
  │                               │
  │←─── Encrypted IP packets ────┤←── Internet
  │                               │
```

### Key Innovation: Defense in Depth

prrr uses **layers of protection**:

1. **HARP over HTTPS (default)** - Indistinguishable from regular web traffic (TCP)
2. **MASQUE over QUIC (legacy)** - Looks like HTTP/3 web traffic (UDP)
3. **TLS fingerprint mimicry** - Looks like Chrome/Firefox
4. **Traffic morphing** - Packet sizes and timing look natural
5. **Active probing resistance** - Won't respond to probes
6. **Post-quantum crypto** - Secure against future attacks
7. **Multiple encryption layers** - TLS + ChaCha20-Poly1305

If one layer is compromised, others still protect you.

---

## Chapter 9: The Hybrid Handshake

When a client connects to a prrr server, they must securely agree on encryption keys. This is called the **handshake**.

### The Noise Protocol Framework

**Noise** is a framework for building cryptographic handshake protocols. Think of it as a recipe book for secure handshakes.

**Noise IK pattern:** (IK = "Identity Known")
- Client knows server's public key in advance
- Server learns client's identity during handshake
- Provides mutual authentication and forward secrecy

### The Handshake Flow (Simplified)

**Before handshake:**
```
Client knows:
  - Own identity keypair (X25519)
  - Server's public key (X25519)
  - Server's ML-KEM public key

Server knows:
  - Own identity keypair (X25519)
  - Own ML-KEM keypair
```

**Message 1: Client → Server**
```
Client generates ephemeral key (temporary, just for this session)
Performs Diffie-Hellman with server's public key
Encrypts own identity with resulting key
Encapsulates ML-KEM shared secret
Sends: [ephemeral pub key][encrypted identity][KEM ciphertext]
```

**Message 2: Server → Client**
```
Server decrypts client identity
Server generates own ephemeral key
Performs Diffie-Hellman exchanges
Decapsulates KEM ciphertext to get ML-KEM shared secret
Sends: [ephemeral pub key][encrypted confirmation]
```

**Result:**
Both sides now have:
- Shared secret from X25519 (classical security)
- Shared secret from ML-KEM-768 (quantum security)
- Combined into session keys using HKDF

### The Math (Simplified)

**Diffie-Hellman:**
```
Client secret: a (random number)
Server secret: b (random number)

Client public: A = g^a (math using elliptic curves)
Server public: B = g^b

Shared secret: 
  Client computes: B^a = (g^b)^a = g^(ab)
  Server computes: A^b = (g^a)^b = g^(ab)
  
Both get same result: g^(ab)
```

**KEM (Key Encapsulation Mechanism):**
```
Server has: public key PK, secret key SK

Client:
  Random shared secret: ss
  Encrypt ss with PK → ciphertext ct
  Send ct to server

Server:
  Decrypt ct with SK → recovers ss

Both have same secret: ss
```

**Hybrid combination:**
```
Classical secret: dh_secret (from X25519)
Quantum secret: kem_secret (from ML-KEM-768)

Final keys = HKDF(dh_secret || kem_secret)

Result:
  - tx_key (client-to-server encryption)
  - rx_key (server-to-client encryption)
  - header_key (header encryption)
```

### Why This is Secure

**Forward Secrecy:** Each handshake uses new ephemeral keys. If someone records today's traffic and steals the server's long-term key tomorrow, they still can't decrypt today's traffic.

**Post-Quantum Security:** An attacker with a quantum computer would need to break:
1. X25519 (which quantum computers can do)
2. AND ML-KEM-768 (which they can't)

Since both secrets are combined, breaking one isn't enough.

**Mutual Authentication:** 
- Client verifies server has the correct private key (only real server can decrypt)
- Server verifies client's identity signature

### What Gets Sent (Wire Format)

**Message 1 (client → server):**
```
┌──────────────────────────────────────────────┐
│ Noise handshake message                      │
│   - Ephemeral public key (32 bytes)         │
│   - Encrypted identity (32 + 16 bytes tag)   │
│                                              │
│ Payload:                                     │
│   - ML-KEM ciphertext (1088 bytes)          │
└──────────────────────────────────────────────┘
Total: ~1168 bytes
```

**Message 2 (server → client):**
```
┌──────────────────────────────────────────────┐
│ Noise handshake message                      │
│   - Ephemeral public key (32 bytes)         │
│   - Encrypted confirmation (16 bytes tag)    │
└──────────────────────────────────────────────┘
Total: ~48 bytes
```

After these two messages, both sides have identical session keys and can start encrypted communication.

---

## Chapter 10: The Encrypted Channel

After the handshake, all VPN traffic flows through an **Encrypted Channel**—a bidirectional encrypted pipe with built-in protection against attacks.

### Core Responsibilities

1. **Encryption** - Make data unreadable
2. **Authentication** - Prove data hasn't been tampered with
3. **Replay Protection** - Prevent old messages from being re-sent
4. **Key Management** - Automatically rotate keys for long-term security

### ChaCha20-Poly1305: The Encryption Algorithm

**ChaCha20** (encryption) + **Poly1305** (authentication) = **AEAD** (Authenticated Encryption with Associated Data)

**How it works:**

```
Input:
  - Plaintext: "Hello Bob"
  - Key: [32 bytes from handshake]
  - Nonce: [12 bytes, unique for each message]
  - AAD: [additional authenticated data, not encrypted]

ChaCha20 encryption:
  "Hello Bob" + Key + Nonce → Ciphertext: "x7f3a92k5b"

Poly1305 authentication:
  Hash(AAD || Ciphertext) + Key → Tag: "a8c4d2f9"

Output:
  Ciphertext: "x7f3a92k5b"
  Tag: "a8c4d2f9"
```

**Decryption:**
```
Input:
  - Ciphertext: "x7f3a92k5b"
  - Tag: "a8c4d2f9"
  - Key, Nonce, AAD (same as encryption)

Poly1305 verification:
  Recompute: Hash(AAD || Ciphertext) + Key
  Compare with received tag
  If match: continue
  If mismatch: REJECT (data was tampered with)

ChaCha20 decryption:
  "x7f3a92k5b" + Key + Nonce → "Hello Bob"
```

**Critical rule:** NEVER reuse the same (Key, Nonce) pair. That would compromise security.

### Nonce Management: The Counter Strategy

A **nonce** is a "number used once." prrr uses a simple counter:

```
Message 1: Nonce = 0
Message 2: Nonce = 1
Message 3: Nonce = 2
...
```

Each direction (client→server, server→client) has its own counter:

```
Client:
  tx_counter = 0, 1, 2, 3, ...  (sending)
  rx_counter = 0, 1, 2, 3, ...  (receiving)

Server:
  tx_counter = 0, 1, 2, 3, ...  (sending)
  rx_counter = 0, 1, 2, 3, ...  (receiving)
```

**Wire format:**
```
┌────────────┬─────────────────┬──────────┐
│  Counter   │   Ciphertext    │   Tag    │
│  8 bytes   │   (variable)    │ 16 bytes │
└────────────┴─────────────────┴──────────┘
```

The counter is sent in the clear (unencrypted) because it's needed for decryption. But it's authenticated as AAD, so tampering is detected.

**Nonce construction:**
```
8-byte counter → 12-byte nonce for ChaCha20

[0x00 0x00 0x00 0x00] [counter: 8 bytes big-endian]
 ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  4 bytes padding       actual counter value
```

### Replay Protection: The Sliding Window

**The attack:**
```
Attacker records encrypted message #5
Later, attacker resends message #5
Server sees message #5 again
Without replay protection: processes it twice (BAD!)
```

**The defense:** Track which messages we've seen:

```
Sliding window (size 64):

Current highest: 100
Window: [64-100]

Message 95 arrives:
  Check: Is 95 in range [64-100]? Yes.
  Check: Have we seen 95 before? No.
  → Accept, mark 95 as seen

Message 95 arrives again:
  Check: Is 95 in range? Yes.
  Check: Have we seen 95 before? YES!
  → Reject (replay attack)

Message 50 arrives:
  Check: Is 50 in range [64-100]? No (too old).
  → Reject (outside window)

Message 101 arrives:
  Check: Is 101 in range? No (higher than current).
  → Accept, update highest to 101
  → Window advances to [65-101]
```

**Implementation:** A bitmap tracks seen messages:

```
Bitmap for window [64-100]:
Position 0 (nonce 64):  1 (seen)
Position 1 (nonce 65):  0 (not seen)
Position 2 (nonce 66):  1 (seen)
...
Position 36 (nonce 100): 1 (seen)
```

Each bit represents whether that nonce has been used.

### Automatic Rekeying

Encrypting too much data with one key can become a security risk. prrr automatically generates new keys:

**When:** After 2^32 messages (~4 billion)

**How:** Derive new key from old key:
```
old_key = [current encryption key]
new_key = HKDF(salt=old_key, info="prrr-rekey-v1")
```

**Process:**
```
Counter reaches 2^32:
  Derive new key from old key
  Reset counter to 0
  Continue with new key
```

This happens transparently—applications don't notice.

**Security:** Even if an attacker breaks the old key, they can't derive the new key (HKDF is one-way).

---

## Chapter 11: Traffic Obfuscation

Even with MASQUE camouflage, subtle patterns can leak information. Traffic obfuscation makes prrr traffic indistinguishable from normal web browsing.

### The Three Pillars of Obfuscation

1. **TLS Fingerprint Mimicry** - Look like popular browsers
2. **Traffic Morphing** - Natural packet sizes and timing
3. **Active Probing Resistance** - Don't respond to probes

### TLS Fingerprinting: The Problem

When you connect via TLS, your client announces its capabilities:

```
Client Hello:
  TLS Version: 1.3
  Cipher suites: [AES-256-GCM, CHACHA20-POLY1305, AES-128-GCM]
  Key exchange: [X25519, secp256r1, secp384r1]
  Extensions: [server_name, supported_groups, ...]
```

The **order and selection** of these parameters creates a unique fingerprint.

**JA3 fingerprinting:** Hash of TLS parameters:
```
JA3 = MD5(version, cipher_suites, extensions, elliptic_curves, ec_formats)

Chrome:   "ac1c37a506602b121faa14f64b40ef97"
Firefox:  "b20b311af6b3c4ba3f80a5c65eec0d00"
Python:   "14f19c37c8d7f3c5b92f8d4f1b76a1c3"
prrr:     ?
```

If prrr's fingerprint doesn't match a known browser, censors can identify and block it.

### Fingerprint Mimicry Strategy

prrr reorders its TLS parameters to match popular browsers:

**Chrome profile:**
```
Cipher suites: [AES_256_GCM, CHACHA20_POLY1305, AES_128_GCM]
Key exchange:  [X25519, secp256r1, secp384r1]
```

**Firefox profile:**
```
Cipher suites: [AES_128_GCM, CHACHA20_POLY1305, AES_256_GCM]
Key exchange:  [X25519, secp256r1, secp384r1]
```

Same algorithms, different order = different fingerprint.

**Limitation:** The underlying TLS library (rustls) has constraints:
- Extension ordering is randomized (can't control)
- Only 3 cipher suites available (browsers advertise 15+)
- Can't match browsers exactly, but can avoid looking like a unique VPN

**Result:** Approximate mimicry that reduces detectability.

### Traffic Morphing: Padding and Timing

Real web traffic has characteristic patterns:

**Web page load:**
```
Request:  120 bytes   (small)
Response: 1460 bytes  (full packet)
Request:  85 bytes
Response: 512 bytes
Request:  200 bytes
Response: 1024 bytes
```

**VPN without obfuscation:**
```
All packets: Exactly 1280 bytes (fixed MTU)
Timing: Perfectly regular intervals
```

This regularity is suspicious!

### Padding Strategies

**PowerOfTwo:**
```
Payload: 100 bytes → Pad to 128 bytes
Payload: 300 bytes → Pad to 512 bytes
Payload: 600 bytes → Pad to 1024 bytes
```

**HttpSizes:**
```
Payload: 100 bytes → Pad to 128 bytes
Payload: 300 bytes → Pad to 512 bytes
Payload: 900 bytes → Pad to 1024 bytes
Payload: 1200 bytes → Pad to 1460 bytes
```

Mimics typical HTTP response sizes.

**Padding format:**
```
┌──────────────┬─────────────┬──────────────┐
│ Length       │  Payload    │  Random      │
│ (2 bytes BE) │  (n bytes)  │  Padding     │
└──────────────┴─────────────┴──────────────┘

Length = size of payload (not including padding)
Padding = cryptographically random bytes
```

**Why random padding?** If padding were zeros, an attacker could distinguish padding from real data.

### Timing Jitter

**Without jitter:**
```
Send packet every exactly 10ms:
Time: 0ms, 10ms, 20ms, 30ms, 40ms...
```

**With jitter:**
```
Send packet every 10ms ± random(0-5ms):
Time: 0ms, 12ms, 19ms, 33ms, 41ms...
```

Jitter is added before sending:
```rust
let jitter = random(0..max_jitter_ms);
sleep(jitter).await;
send_packet();
```

### Dummy Traffic

Sometimes, not sending traffic is suspicious:

```
User idle for 30 seconds → No packets
Censor: "Real web browsing has periodic keepalives"
```

**Dummy packets:** Packets with zero payload, pure padding:
```
┌──────────────┬──────────────┐
│ Length: 0    │  Random      │
│ (2 bytes)    │  Padding     │
└──────────────┴──────────────┘
```

Encrypted and sent like real packets, but discarded on receipt.

### Active Probing Resistance

**The attack:**
```
Censor suspects: "That server might be a VPN"
Censor connects: "Hello VPN server, are you there?"
VPN responds: "Yes I am" (by opening a VPN connection)
Censor: "Gotcha! Blocked."
```

**The defense:** Cookie authentication

**Pre-shared secret (PSK):** A secret key known to both client and server, distributed out-of-band (via secure channel).

**Authentication token:**
```
Nonce: [16 random bytes]
Timestamp: [current Unix time]
MAC: HMAC-BLAKE2s(key=PSK, data="prrr-probe-resist-token-v1" || nonce || timestamp)

Token = [Nonce][Timestamp][MAC]
Encode as base64url
```

**Client request:**
```http
CONNECT-UDP /tunnel HTTP/3
Authorization: Bearer <base64url_token>
```

**Server validation:**
```
1. Rate limit: Has this IP sent too many requests? → 403
2. Parse token: Valid format? → Decoy response
3. Check timestamp: Within ±30 seconds? → Decoy response  
4. Verify MAC: HMAC correct? → Decoy response
5. Check nonce: Already seen (replay)? → Decoy response
6. All checks pass → Proceed with tunnel
```

**Decoy response (on failure):**
```http
HTTP/3 200 OK
Content-Type: text/html; charset=utf-8
Server: nginx/1.24.0

<html>
<head><title>Welcome</title></head>
<body><h1>It works!</h1></body>
</html>
```

Looks like a default nginx web server—nothing suspicious.

**Why this works:**

Without the PSK:
- Attacker can't generate valid tokens
- All probes get the decoy response
- Server looks like a regular web server

With the PSK:
- Real clients can authenticate
- Get access to VPN tunnel

**Rate limiting:** Token bucket per IP:
```
Each IP starts with 5 tokens
Tokens refill at 20/second
Each request consumes 1 token
No tokens left → reject immediately
```

Prevents brute-force authentication attempts.

---

## Chapter 12: The Tunnel Pipeline

The **Tunnel Pipeline** is where everything comes together—connecting the TUN device to the encrypted transport channel (HARP or MASQUE).

### Two Concurrent Loops

**Inbound loop (TUN → Network):**
```
┌─────────────────────────────────────┐
│ 1. Read IP packet from TUN device   │
│    └─ Application sent data         │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 2. Check MTU (drop if too large)    │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 3. Encrypt with EncryptedChannel    │
│    └─ ChaCha20-Poly1305             │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 4. Frame for transport              │
│    └─ HARP: 4-byte header + WS/HTTP │
│    └─ MASQUE: HTTP Datagram frame   │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 5. Send via transport               │
│    └─ To VPN server                 │
└─────────────────────────────────────┘
```

**Outbound loop (Network → TUN):**
```
┌─────────────────────────────────────┐
│ 1. Receive from transport           │
│    └─ From VPN server               │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 2. Deframe transport data           │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 3. Decrypt with EncryptedChannel    │
│    └─ Verify auth tag               │
│    └─ Check for replay              │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 4. Write IP packet to TUN device    │
│    └─ OS delivers to application    │
└─────────────────────────────────────┘
```

Both loops run **concurrently** (at the same time using async/await).

### Example: Visiting a Website

**Step-by-step flow:**

```
1. Browser requests: "GET https://news-site.com/"

2. OS creates IP packet:
   From: 10.0.0.2 (TUN interface)
   To: 142.250.80.46 (news-site.com)
   Data: [HTTP request]

3. OS routes packet to prrr0 (TUN device)

4. prrr reads packet from TUN

5. Inbound pipeline:
   Packet (1200 bytes)
   → Check MTU: OK (< 1280)
   → Encrypt: [counter][ciphertext][tag] (1224 bytes)
   → Frame: [stream_id][ctx=0][encrypted] (1227 bytes)
   → Send via QUIC to server

6. Server receives:
   QUIC datagram arrives
   → Deframe: Extract encrypted payload
   → Decrypt: Get original IP packet
   → Forward to internet (to 142.250.80.46)

7. news-site.com responds:
   Returns HTML content

8. Server outbound pipeline:
   IP packet from news-site.com
   → Encrypt
   → Frame
   → Send via QUIC to client

9. Client receives:
   QUIC datagram arrives
   → Deframe
   → Decrypt: Get IP packet
   → Write to TUN device

10. OS receives packet from TUN

11. OS delivers to browser

12. Browser displays news site
```

All of this happens in milliseconds!

### MTU (Maximum Transmission Unit)

**MTU:** The largest packet size allowed.

**Problem:** Adding encryption and framing increases packet size:
```
Original packet:  1280 bytes (IPv6 minimum)
Encrypted:        1280 + 8 (counter) + 16 (tag) = 1304 bytes
MASQUE frame:     1304 + 3 (headers) = 1307 bytes
```

If the network only allows 1280-byte packets, this won't fit!

**Solutions:**

1. **Set TUN MTU lower:** 1280 - overhead = ~1230 bytes
   - Applications generate smaller packets
   - After encryption/framing, fits within limit

2. **Fragment:** Split large packets into multiple smaller ones
   - More complex
   - prrr uses solution #1 (simpler)

**MTU enforcement:**
```
if packet_size > tun_mtu {
    log::warn!("Packet too large, dropping");
    return;  // Drop packet
}
```

Dropping oversized packets is safe—TCP will automatically retransmit with smaller packets.

### Traffic Statistics

The pipeline tracks bytes sent/received:

```rust
struct TrafficStats {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}
```

**Atomic:** Can be updated from multiple threads safely without locks.

```
Inbound loop:
  Send 1200 bytes → bytes_sent += 1200

Outbound loop:
  Receive 800 bytes → bytes_received += 800
```

Used for:
- Monitoring (how much data transferred?)
- Billing (if running commercial service)
- Diagnostics (is traffic flowing?)

### Graceful Shutdown

**Cancellation token:** Signal to stop the pipeline

```
User presses Ctrl+C
  ↓
Main program signals cancellation
  ↓
Inbound loop: Check token → Stop
Outbound loop: Check token → Stop
  ↓
Both loops exit cleanly
  ↓
TUN device closed
QUIC connection closed
```

**Without graceful shutdown:**
```
Kill process → Abrupt termination
→ QUIC connection left in weird state
→ Might leak resources
```

**With graceful shutdown:**
```
Cancel → Clean exit
→ Send QUIC close frame
→ Server knows client disconnected
→ No leaks
```

---

## Chapter 13: Client and Server Architecture

### Client Architecture

**Components:**

```
┌─────────────────────────────────────┐
│         Client Application          │
│  - CLI argument parsing             │
│  - Configuration loading            │
│  - Logging setup                    │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│         QUIC Connection             │
│  - Connect to server                │
│  - TLS handshake                    │
│  - ALPN: h3                         │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│         MASQUE Client               │
│  - CONNECT-UDP handshake            │
│  - Authentication token             │
│  - Datagram send/recv               │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│       Hybrid Handshake              │
│  - Noise IK + ML-KEM-768            │
│  - Derive session keys              │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│      Encrypted Channel              │
│  - ChaCha20-Poly1305                │
│  - Replay protection                │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│      TUN Device (prrr0)             │
│  - Created with sudo privileges     │
│  - IP: 10.0.0.2/24                  │
│  - Routes configured                │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│      Tunnel Pipeline                │
│  - Inbound: TUN → Network           │
│  - Outbound: Network → TUN          │
└─────────────────────────────────────┘
```

**Startup sequence:**

```
1. Parse config file or CLI arguments
2. Set up logging (level, format)
3. Load or generate client keys
4. Connect to server via QUIC
5. Perform MASQUE handshake with auth token
6. Perform hybrid cryptographic handshake
7. Create TUN device (requires root/sudo)
8. Configure routes (send all traffic through TUN)
9. Start tunnel pipeline
10. Run until Ctrl+C or error
```

**Configuration example:**
```toml
[client]
server_address = "vpn.example.com:443"
server_name = "vpn.example.com"
psk = "base64-encoded-pre-shared-key"
private_key_path = "/home/user/.config/prrr/client.key"

[tunnel]
interface_name = "prrr0"
ip_address = "10.0.0.2"
netmask = "255.255.255.0"
mtu = 1280

[obfuscation]
tls_profile = "chrome"
padding_strategy = "http-sizes"
max_jitter_ms = 50
```

### Server Architecture

**Components:**

```
┌─────────────────────────────────────┐
│      Server Application             │
│  - CLI/config parsing               │
│  - Web admin API (optional)         │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│       QUIC Server (Port 443)        │
│  - Listen for connections           │
│  - TLS certificate                  │
│  - ALPN: h3                         │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│    Connection Accept Loop           │
│  - For each client connection       │
│  - Spawn per-client task            │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│     Per-Client Task                 │
│  ┌───────────────────────────────┐  │
│  │ MASQUE Proxy                  │  │
│  │ - Accept CONNECT-UDP          │  │
│  │ - Validate auth token         │  │
│  └──────────┬────────────────────┘  │
│             ↓                        │
│  ┌───────────────────────────────┐  │
│  │ Hybrid Handshake (responder)  │  │
│  │ - Authenticate client         │  │
│  │ - Derive session keys         │  │
│  └──────────┬────────────────────┘  │
│             ↓                        │
│  ┌───────────────────────────────┐  │
│  │ Encrypted Channel             │  │
│  └──────────┬────────────────────┘  │
│             ↓                        │
│  ┌───────────────────────────────┐  │
│  │ TUN Device (unique per client)│  │
│  │ - IP: 10.0.0.3 (allocated)    │  │
│  └──────────┬────────────────────┘  │
│             ↓                        │
│  ┌───────────────────────────────┐  │
│  │ Tunnel Pipeline               │  │
│  │ - Forward to internet         │  │
│  │ - NAT outgoing packets        │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

**Multi-client handling:**

```
Client A connects:
  → Spawn task A
  → Create TUN device prrr-client-a (IP: 10.0.0.3)
  → Forward traffic for A

Client B connects:
  → Spawn task B
  → Create TUN device prrr-client-b (IP: 10.0.0.4)
  → Forward traffic for B

Client C connects:
  → Spawn task C
  → Create TUN device prrr-client-c (IP: 10.0.0.5)
  → Forward traffic for C
```

Each client is isolated—can't see each other's traffic.

### Client Registry

**SQLite database** tracks clients:

```sql
CREATE TABLE clients (
    id TEXT PRIMARY KEY,           -- UUID
    name TEXT UNIQUE NOT NULL,     -- Human-readable name
    public_key BLOB NOT NULL,      -- X25519 public key
    kem_public_key BLOB NOT NULL,  -- ML-KEM-768 public key
    ip_address TEXT NOT NULL,      -- Assigned IP (10.0.0.x)
    status TEXT NOT NULL,          -- active, suspended, revoked
    created_at INTEGER NOT NULL,   -- Unix timestamp
    last_seen INTEGER              -- Last connection time
);
```

**IP allocation:**
```
Subnet: 10.0.0.0/24
  10.0.0.0   - Network address (reserved)
  10.0.0.1   - Gateway (server)
  10.0.0.2   - First client
  10.0.0.3   - Second client
  ...
  10.0.0.254 - Last client
  10.0.0.255 - Broadcast (reserved)

Available: 253 client IPs
```

**Client lifecycle:**

```
1. Admin runs: prrr server client add alice
   → Generate keypair
   → Allocate IP: 10.0.0.2
   → Store in database
   → Output private key (shown once!)

2. Admin exports config:
   prrr server client export alice > alice.toml
   → Contains: server address, public keys, assigned IP

3. Alice imports and connects:
   prrr client import alice.toml
   → Store config in ~/.config/prrr/
   → Connect using stored keys

4. Server authenticates:
   → Verify client public key matches database
   → Check status (active/suspended/revoked)
   → If revoked: reject connection

5. Admin can suspend:
   prrr server client suspend alice
   → Status = suspended
   → Future connections rejected
   → Current connection stays active (until disconnect)

6. Admin can revoke:
   prrr server client revoke alice
   → Status = revoked
   → IP released for reuse
   → Immediate disconnect
```

### Network Address Translation (NAT)

**Problem:** Client packets have source IP 10.0.0.x (private), but internet servers need real IPs.

**Solution:** NAT at the server

```
Client packet:
  From: 10.0.0.2
  To: 142.250.80.46 (google.com)

Server NAT:
  Replace source: 10.0.0.2 → Server's public IP (203.0.113.5)
  Track: (10.0.0.2, port X) ↔ (203.0.113.5, port Y)

Sent to internet:
  From: 203.0.113.5
  To: 142.250.80.46

Reply from google.com:
  From: 142.250.80.46
  To: 203.0.113.5 (port Y)

Server reverse NAT:
  Look up: port Y → client 10.0.0.2
  Replace destination: 203.0.113.5 → 10.0.0.2

Sent to client:
  From: 142.250.80.46
  To: 10.0.0.2
```

The client thinks it's directly talking to google.com. Google thinks it's talking to the server. NAT makes it work.

---

# Part IV: Advanced Features

## Chapter 15: Web Administration

prrr includes an embedded web admin panel for server management.

### Architecture

```
┌────────────────────────────────────────┐
│  Browser (localhost:8443)              │
│  - Preact SPA (Single Page App)       │
│  - No build step, embedded in binary  │
└──────────────┬─────────────────────────┘
               │ HTTPS
               ↓
┌────────────────────────────────────────┐
│  REST API Server (Axum framework)     │
│  - JWT authentication                  │
│  - CORS headers                        │
└──────────────┬─────────────────────────┘
               │
               ↓
┌────────────────────────────────────────┐
│  Server State (Arc<Mutex<...>>)       │
│  - Client registry                     │
│  - Active connections                  │
│  - Metrics                             │
└────────────────────────────────────────┘
```

### Authentication: JWT (JSON Web Tokens)

**Login flow:**

```
1. User enters password in browser

2. Browser: POST /api/v1/auth/login
   {
     "password": "admin-password"
   }

3. Server:
   - Hash provided password
   - Compare with stored hash (constant-time)
   - If match:
       token = JWT(payload={user:"admin", exp:24h_from_now}, key=secret)
       Return: {"token": "eyJhbGci..."}

4. Browser stores token in localStorage

5. Future requests:
   GET /api/v1/clients
   Authorization: Bearer eyJhbGci...

6. Server:
   - Verify JWT signature
   - Check expiration
   - If valid: process request
   - If invalid: 401 Unauthorized
```

**JWT structure:**
```
Header.Payload.Signature

Header (base64):
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload (base64):
{
  "user": "admin",
  "exp": 1735689600  (Unix timestamp)
}

Signature:
HMAC-SHA256(Header + "." + Payload, secret_key)
```

**Why JWT?**
- Stateless (server doesn't store sessions)
- Tamper-proof (signature validation)
- Standard (works with all HTTP clients)

### API Endpoints

**Client management:**
```
GET    /api/v1/clients          - List all clients
POST   /api/v1/clients          - Add new client
GET    /api/v1/clients/:id      - Get client details
PUT    /api/v1/clients/:id      - Update client
DELETE /api/v1/clients/:id      - Revoke client
POST   /api/v1/clients/:id/suspend   - Suspend client
POST   /api/v1/clients/:id/resume    - Resume client
```

**Metrics:**
```
GET /api/v1/metrics             - Prometheus format metrics
GET /api/v1/health              - Health check endpoint
```

**Example request:**
```http
GET /api/v1/clients HTTP/1.1
Host: localhost:8443
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Response:
HTTP/1.1 200 OK
Content-Type: application/json

{
  "clients": [
    {
      "id": "a3f8c9d2-...",
      "name": "alice-laptop",
      "ip": "10.0.0.2",
      "status": "active",
      "last_seen": 1735680000,
      "bytes_sent": 1048576,
      "bytes_received": 2097152
    },
    {
      "id": "b2d4e1f7-...",
      "name": "bob-phone",
      "ip": "10.0.0.3",
      "status": "suspended",
      "last_seen": 1735650000,
      "bytes_sent": 512000,
      "bytes_received": 1024000
    }
  ]
}
```

### Client Distribution

**Problem:** How to get config to clients securely?

**Solutions:**

1. **TOML file:**
   ```bash
   prrr server client export alice > alice.toml
   # Securely transfer alice.toml to Alice
   ```

2. **QR code:**
   ```bash
   prrr server client qr alice
   # Displays QR code in terminal
   # Alice scans with phone camera
   ```

3. **URL token:**
   ```bash
   prrr server client url alice
   # Returns: https://vpn.example.com/import?t=eyJhbGci...
   # One-time use URL, expires in 1 hour
   ```

**Config content (alice.toml):**
```toml
[client]
server_address = "vpn.example.com:443"
server_name = "vpn.example.com"
client_name = "alice-laptop"
assigned_ip = "10.0.0.2"

[keys]
server_public_key = "base64-encoded..."
server_kem_public_key = "base64-encoded..."
client_public_key = "base64-encoded..."
# Client private key must be added manually (not exported for security)

[psk]
probe_resist_key = "base64-encoded..."
```

**Security notes:**
- Private keys never transmitted over network
- Shown only once during `client add`
- User must save and add to config manually
- Prevents private key leakage if server compromised

---

# Part V: Operations and Security

## Chapter 16: Deployment

### System Requirements

**Server:**
- Linux (Ubuntu 22.04+, Debian 11+, Fedora 38+)
- 1 GB RAM (for ~10 clients)
- Root access (for TUN device creation)
- TCP port 443 open (HARP, default); optionally UDP port 443 (MASQUE)
- Public IP address
- Domain name (for TLS certificate)

**Client:**
- Linux (any modern distro)
- Sudo access (for TUN device and routes)
- Internet connection allowing HTTPS (TCP 443)

### Installation Script

**Server installation:**
```bash
curl -fsSL https://install.prrr.dev/server | sudo bash -s -- \
  --admin-pass "your-secure-password" \
  --domain vpn.example.com
```

**What it does:**
```
1. Detect OS (Ubuntu/Debian/Fedora)
2. Install dependencies:
   - Rust toolchain
   - Build tools
   - SQLite
3. Download prrr source
4. Compile release binary
5. Install to /usr/local/bin/prrr
6. Generate server keys
7. Create systemd service:
   [Unit]
   Description=prrr VPN Server
   After=network.target

   [Service]
   Type=simple
   ExecStart=/usr/local/bin/prrr server --config /etc/prrr/server.toml
   Restart=on-failure
   User=prrr

   [Install]
   WantedBy=multi-user.target
8. Start service:
   systemctl enable prrr
   systemctl start prrr
```

### TLS Certificate Setup

**Option 1: Self-signed (dev/test only)**
```bash
prrr server --generate-cert --domain vpn.example.com
```

**Option 2: Let's Encrypt (production)**
```bash
# Install certbot
apt-get install certbot

# Get certificate
certbot certonly --standalone -d vpn.example.com

# Certificate files:
/etc/letsencrypt/live/vpn.example.com/fullchain.pem  (certificate)
/etc/letsencrypt/live/vpn.example.com/privkey.pem    (private key)

# Configure prrr
[tls]
cert_path = "/etc/letsencrypt/live/vpn.example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/vpn.example.com/privkey.pem"

# Auto-renewal (certbot sets up cron job automatically)
```

### Firewall Configuration

**UFW (Ubuntu/Debian):**
```bash
# Allow SSH
ufw allow 22/tcp

# Allow prrr (TCP 443 for HARP, UDP 443 for MASQUE)
ufw allow 443/tcp
ufw allow 443/udp

# Allow web admin (optional, bind to localhost and use SSH tunnel instead)
# ufw allow 8443/tcp

# Enable firewall
ufw enable
```

**iptables (manual):**
```bash
# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow prrr (HARP + MASQUE)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp --dport 443 -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Drop everything else
iptables -P INPUT DROP

# NAT for client traffic
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
```

### Terraform Deployment (DigitalOcean)

**terraform.tfvars:**
```hcl
digitalocean_token = "dop_v1_..."
ssh_key_fingerprint = "ab:cd:ef:..."
admin_password = "secure-password"
domain_name = "vpn.example.com"
region = "nyc3"
```

**Apply:**
```bash
cd deploy/terraform
terraform init
terraform apply

# Outputs:
# server_ip = "192.0.2.100"
# admin_url = "https://192.0.2.100:8443"
```

**What it creates:**
- Droplet (VPS) with prrr installed
- Firewall rules
- Reserved IP (static)
- DNS A record (if using DO DNS)

### Client Setup

**Import config:**
```bash
# Receive alice.toml from admin
prrr client import alice.toml

# Add private key (from initial client add output)
echo -n "BASE64_PRIVATE_KEY" | base64 -d > ~/.local/share/prrr/keys/client.key
chmod 600 ~/.local/share/prrr/keys/client.key

# Update config to reference key
echo 'private_key_path = "/home/alice/.local/share/prrr/keys/client.key"' >> ~/.config/prrr/client.toml
```

**Connect:**
```bash
sudo prrr client --config ~/.config/prrr/client.toml
```

**Verify connection:**
```bash
# Check interface
ip addr show prrr0

# Check route
ip route | grep prrr0

# Test connectivity
curl ifconfig.me  # Should show VPN server's IP
```

---

## Chapter 17: Diagnostics and Troubleshooting

### Built-in Doctor Command

**Server diagnostics:**
```bash
prrr server doctor

Checking configuration:
  ✓ Config file: /etc/prrr/server.toml
  ✓ Listen address: 0.0.0.0:443
  ✓ TLS certificate: valid until 2025-06-01
  ✓ PSK configured

Checking keys:
  ✓ Server private key: present
  ✓ Server KEM key: present

Checking network:
  ✓ Port 443/UDP: open
  ✓ IP forwarding: enabled
  ✓ NAT configured

Checking system:
  ✓ TUN device support: available
  ✓ Memory: 2 GB available
  ✓ Disk space: 10 GB available

Checking database:
  ✓ SQLite: accessible
  ✓ Clients registered: 5
  ✓ Active connections: 2
```

**Client diagnostics:**
```bash
prrr client doctor

Checking configuration:
  ✓ Config file: ~/.config/prrr/client.toml
  ✓ Server address: vpn.example.com:443
  ✓ Private key: present

Checking network:
  ✓ DNS resolution: vpn.example.com → 192.0.2.100
  ✓ UDP 443: reachable
  ✓ Internet connectivity: OK

Checking system:
  ✓ TUN device support: available
  ✓ Sudo access: available
  ✗ Route conflicts: detected (10.0.0.0/24 already routed)

Recommendations:
  - Remove conflicting route: ip route del 10.0.0.0/24
```

### Common Issues

**Issue: "Permission denied" creating TUN device**

```
Error: TunnelError::TunIo(Os { code: 13, kind: PermissionDenied, message: "Permission denied" })
```

**Solution:**
```bash
# Must run with sudo
sudo prrr client --config ~/.config/prrr/client.toml

# Or: Set capabilities (allows running without sudo)
sudo setcap cap_net_admin=eip /usr/local/bin/prrr
```

**Issue: "Connection refused"**

```
Error: TransportError::QuicConnection("connection refused")
```

**Checklist:**
```
1. Server running?
   systemctl status prrr

2. Firewall allows UDP 443?
   sudo ufw status
   sudo iptables -L -n | grep 443

3. Correct server address in client config?
   cat ~/.config/prrr/client.toml | grep server_address

4. DNS resolution working?
   nslookup vpn.example.com
```

**Issue: "Authentication failed"**

```
Error: MASQUE handshake failed: invalid token
```

**Causes:**
```
1. PSK mismatch:
   - Server PSK != Client PSK
   - Regenerate and redistribute PSK

2. Time skew:
   - Client time != Server time (>30s difference)
   - Sync clocks: ntpdate pool.ntp.org

3. Token already used (replay):
   - Restart client to generate new nonce
```

**Issue: "Handshake failed: KemFailed"**

```
Error: HandshakeError::KemFailed("decapsulation failed")
```

**Cause:** Client KEM public key doesn't match server's expectation

**Solution:**
```
1. Verify client registered on server:
   prrr server client list | grep alice

2. Re-export config:
   prrr server client export alice > alice.toml

3. Re-import on client:
   prrr client import alice.toml
```

**Issue: "Packet too large, dropping"**

```
WARN tunnel::pipeline - Packet size 1400 exceeds MTU 1280, dropping
```

**Solution:**
```
# Reduce application MTU
# For TCP connections, OS will auto-adjust
# For UDP applications, configure manually

# Example: adjust MTU for interface
sudo ip link set prrr0 mtu 1280
```

### Logging Configuration

**Log levels:**
```toml
[logging]
level = "info"  # trace, debug, info, warn, error

# Per-module levels
[logging.module_levels]
"prrr::transport" = "debug"
"prrr::tunnel" = "trace"
"quinn" = "warn"  # Reduce noise from QUIC library
```

**Output:**
```
2024-12-30 14:23:45 INFO  prrr::server - Server starting on 0.0.0.0:443
2024-12-30 14:23:45 DEBUG prrr::transport::quic - QUIC endpoint bound
2024-12-30 14:24:10 INFO  prrr::server - Client connected: alice-laptop (10.0.0.2)
2024-12-30 14:24:10 DEBUG prrr::handshake::hybrid - Hybrid handshake complete
2024-12-30 14:24:11 TRACE prrr::tunnel::pipeline - Inbound packet: 1200 bytes
```

### Metrics and Monitoring

**Prometheus metrics:**
```
# Server exports metrics at /metrics
curl http://localhost:8443/api/v1/metrics

# Sample output:
prrr_clients_total{status="active"} 5
prrr_clients_total{status="suspended"} 1
prrr_connections_active 3
prrr_bytes_sent_total 104857600
prrr_bytes_received_total 52428800
prrr_packets_encrypted_total 81920
prrr_packets_decrypted_total 40960
prrr_handshakes_total{result="success"} 15
prrr_handshakes_total{result="failure"} 2
```

**Grafana dashboard:**
```json
{
  "dashboard": {
    "title": "prrr VPN",
    "panels": [
      {
        "title": "Active Connections",
        "targets": [{"expr": "prrr_connections_active"}]
      },
      {
        "title": "Throughput",
        "targets": [
          {"expr": "rate(prrr_bytes_sent_total[5m])"},
          {"expr": "rate(prrr_bytes_received_total[5m])"}
        ]
      }
    ]
  }
}
```

---

## Chapter 18: Security Considerations

### Threat Model

**What prrr protects against:**

1. **Passive surveillance** - ISP/government reading your traffic
2. **DPI (Deep Packet Inspection)** - Identifying VPN usage
3. **Traffic analysis** - Correlating encrypted flows
4. **Active probing** - Detecting VPN servers
5. **Quantum computers** - Future attacks on encryption
6. **Replay attacks** - Resending old packets
7. **Tampering** - Modifying encrypted data

**What prrr doesn't protect against:**

1. **Endpoint compromise** - Malware on your device
2. **Server compromise** - If VPN server is hacked, your traffic is visible
3. **Correlation attacks** - Timing patterns (enter VPN at X, emerge at Y)
4. **Legal pressure** - Server operator forced to log
5. **Targeted attacks** - Nation-state actors with unlimited resources
6. **DNS leaks** - If DNS queries bypass VPN
7. **WebRTC leaks** - Browser revealing real IP

### Best Practices

**Operational security:**

```
1. Server hardening:
   - Minimal OS installation
   - Disable unnecessary services
   - Keep system updated
   - Use strong SSH keys (no passwords)
   - Firewall: only SSH + VPN ports
   - Monitor logs for suspicious activity

2. Key management:
   - Generate strong PSK (32+ random bytes)
   - Rotate PSK periodically (monthly)
   - Store server keys encrypted at rest
   - Backup keys securely (encrypted)
   - Never transmit private keys over network

3. Client distribution:
   - Use QR codes for mobile (auto-delete after scan)
   - Use one-time URLs (expire after 1 hour)
   - Verify fingerprints out-of-band
   - Revoke compromised clients immediately

4. Monitoring:
   - Watch for failed authentication attempts
   - Alert on unusual traffic patterns
   - Monitor system resource usage
   - Regular log review

5. Updates:
   - Subscribe to prrr security announcements
   - Apply security patches promptly
   - Test updates in staging first
   - Have rollback plan
```

**Client-side security:**

```
1. DNS leak prevention:
   # Use VPN server's DNS
   echo "nameserver 10.0.0.1" > /etc/resolv.conf

   # Or use systemd-resolved
   resolvectl dns prrr0 10.0.0.1

2. IPv6 leak prevention:
   # Disable IPv6 (if not supported by VPN)
   sysctl -w net.ipv6.conf.all.disable_ipv6=1

3. Kill switch (block traffic if VPN drops):
   #!/bin/bash
   # Allow loopback
   iptables -A OUTPUT -o lo -j ACCEPT
   # Allow VPN
   iptables -A OUTPUT -o prrr0 -j ACCEPT
   # Block everything else
   iptables -A OUTPUT -j REJECT

4. Verify connection:
   # Check IP
   curl ifconfig.me
   # Check DNS
   curl https://dnsleaktest.com/

5. Private key protection:
   chmod 600 ~/.local/share/prrr/keys/client.key
   # Store on encrypted disk
   # Don't copy to cloud storage
```

### Cryptographic Key Lifecycle

**Server identity key:**
```
Generation:
  prrr server init
  → Generate X25519 keypair
  → Generate ML-KEM-768 keypair
  → Store in /etc/prrr/keys/

Rotation:
  Not recommended (breaks all existing client configs)
  If necessary:
    1. Generate new server
    2. Migrate clients gradually
    3. Decommission old server

Revocation:
  If compromised:
    1. Immediately shutdown server
    2. Generate new keys
    3. Redistribute to all clients
    4. Investigate breach
```

**Client keys:**
```
Generation:
  prrr server client add alice
  → Generate X25519 keypair
  → Generate ML-KEM-768 keypair
  → Store public keys in database
  → Display private keys once

Rotation:
  Manual:
    prrr server client rotate alice
    → Generate new keypair
    → Old config invalid
    → Export new config to client

Revocation:
  prrr server client revoke alice
  → Mark as revoked in database
  → Future connections rejected
  → IP released for reuse
```

**Session keys:**
```
Lifecycle:
  Handshake → Derive keys
  Use for data transfer
  Rekey after 2^32 packets (automatic)
  Disconnect → Keys discarded and zeroized

No persistence:
  Session keys exist only in memory
  Never written to disk
  Zeroized on drop
```

**PSK (probe resistance):**
```
Generation:
  head -c 32 /dev/urandom | base64

Distribution:
  - Include in client config export
  - Or: send via secure channel (Signal, PGP email)

Rotation:
  Monthly or after suspected compromise:
    1. Generate new PSK
    2. Update server config
    3. Redistribute to all clients
    4. Old PSK expires after grace period (24h)
```

### Defense in Depth

prrr uses **multiple layers** of protection. If one fails, others remain:

```
Layer 1: HARP/HTTPS camouflage (default) or MASQUE/QUIC camouflage
  If defeated → Still protected by layers 2-7

Layer 2: TLS 1.3 (transport encryption)
  If defeated → Still protected by layers 3-7

Layer 3: Hybrid handshake (X25519 + ML-KEM)
  If one algorithm broken → Other still protects

Layer 4: ChaCha20-Poly1305 (packet encryption)
  If broken → Handshake keys still secure

Layer 5: Traffic obfuscation (padding, timing, dummy)
  If pattern detected → Crypto still intact

Layer 6: Active probing resistance (token auth)
  If bypassed → Handshake still authenticates

Layer 7: Pluggable transports (switch HARP ↔ MASQUE)
  If one transport blocked → Switch to the other
```

**Principle:** No single point of failure in cryptography.

---

## Conclusion

### What We've Learned

You now understand:

1. **Why censorship resistance is hard** - Censors use DPI, active probing, and traffic analysis
2. **How VPNs work** - Tunneling, encryption, key exchange
3. **Why traditional VPNs fail** - Identifiable patterns, no active probing resistance
4. **How cryptography protects data** - Encryption, authentication, key exchange
5. **Post-quantum security** - Hybrid cryptography (classical + quantum-resistant)
6. **Network protocols** - QUIC, HTTP/3, MASQUE
7. **Traffic obfuscation** - Fingerprint mimicry, padding, timing jitter
8. **The complete prrr architecture** - From TUN device to encrypted packets
9. **Operational security** - Deployment, monitoring, troubleshooting

### The prrr Philosophy

prrr is built on these principles:

**1. Standards-based** - Uses IETF protocols (HTTPS, QUIC, MASQUE) not custom formats
**2. Defense in depth** - Multiple layers of protection
**3. Post-quantum ready** - Hybrid cryptography for future-proofing
**4. Operational simplicity** - Single binary, built-in diagnostics
**5. No unsafe code** - Memory safety guaranteed by Rust
**6. Transparent** - Open source, well-documented, auditable

### Further Reading

**Cryptography:**
- "The Joy of Cryptography" by Mike Rosulek (free textbook)
- "Serious Cryptography" by Jean-Philippe Aumasson
- Noise Protocol Framework: https://noiseprotocol.org/

**Networking:**
- "Computer Networks" by Andrew Tanenauer
- QUIC RFC 9000: https://www.rfc-editor.org/rfc/rfc9000
- MASQUE RFC 9297: https://www.rfc-editor.org/rfc/rfc9297

**Censorship resistance:**
- "How Governments Block Content" (Great Firewall analysis)
- Tor Project research papers: https://research.torproject.org/
- GFW Report: https://gfw.report/

**prrr specifics:**
- Source code: https://github.com/prrr-vpn/prrr
- Architecture docs: `/docs/overview.md`
- Security audit reports: `/docs/security.md`

---

## Appendix A: Quick Reference

### Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│                 Your Application                     │
│           (Browser, Email, Chat, etc.)               │
└───────────────────┬─────────────────────────────────┘
                    │ IP packets (plaintext)
                    ↓
┌─────────────────────────────────────────────────────┐
│            TUN Device (prrr0)                        │
│            Virtual Network Interface                 │
│            IP: 10.0.0.2/24                          │
└───────────────────┬─────────────────────────────────┘
                    │
                    ↓
┌─────────────────────────────────────────────────────┐
│          Tunnel Pipeline                             │
│  Inbound:  TUN → Encrypt → Transport → Network      │
│  Outbound: Network → Transport → Decrypt → TUN      │
└───────────────────┬─────────────────────────────────┘
                    │
                    ↓
┌─────────────────────────────────────────────────────┐
│        Encrypted Channel                             │
│  • ChaCha20-Poly1305 encryption                     │
│  • Nonce counter (prevents reuse)                   │
│  • Replay protection (sliding window)               │
│  • Automatic rekeying (every 2^32 packets)          │
└───────────────────┬─────────────────────────────────┘
                    │
          ┌─────────┴─────────┐
          ↓                   ↓
┌──────────────────┐ ┌──────────────────────────────┐
│  HARP (default)  │ │  MASQUE (legacy)              │
│  • WebSocket or  │ │  • HTTP Datagram framing      │
│    HTTP polling  │ │  • QUIC DATAGRAMs (quinn)     │
│  • 4-byte frame  │ │  • ALPN: h3 (HTTP/3)          │
│    header        │ │  • Connection migration        │
└────────┬─────────┘ └──────────────┬───────────────┘
         ↓                          ↓
┌──────────────────┐ ┌──────────────────────────────┐
│  TCP Port 443    │ │  UDP Port 443                 │
│  (HTTPS traffic) │ │  (HTTP/3 traffic)             │
└──────────────────┘ └──────────────────────────────┘
```

### Command Cheatsheet

**Server commands:**
```bash
# Initialize server
prrr server init

# Start server
prrr server --config /etc/prrr/server.toml

# Add client
prrr server client add alice

# List clients
prrr server client list

# Export config
prrr server client export alice > alice.toml

# Generate QR code
prrr server client qr alice

# Suspend client
prrr server client suspend alice

# Revoke client
prrr server client revoke alice

# Server diagnostics
prrr server doctor
```

**Client commands:**
```bash
# Import config
prrr client import alice.toml

# Connect
sudo prrr client --config ~/.config/prrr/client.toml

# Client diagnostics
prrr client doctor

# Check status
prrr client status
```

### Configuration Templates

**Server config (`/etc/prrr/server.toml`):**
```toml
[server]
listen_address = "0.0.0.0:443"
server_name = "vpn.example.com"
max_clients = 100

[network]
subnet = "10.0.0.0/24"
gateway = "10.0.0.1"

[tls]
cert_path = "/etc/prrr/cert.pem"
key_path = "/etc/prrr/key.pem"

[keys]
server_key_path = "/etc/prrr/keys/server.key"
kem_key_path = "/etc/prrr/keys/server_kem.key"
psk_path = "/etc/prrr/keys/psk.key"

[database]
path = "/var/lib/prrr/clients.db"

[web_admin]
enabled = true
listen = "127.0.0.1:8443"
admin_password_hash = "argon2id$v=19$..."

[obfuscation]
tls_profile = "chrome"
padding_strategy = "http-sizes"
max_jitter_ms = 50
enable_probe_resistance = true

[logging]
level = "info"
```

**Client config (`~/.config/prrr/client.toml`):**
```toml
[client]
server_address = "vpn.example.com:443"
server_name = "vpn.example.com"
client_name = "alice-laptop"

[keys]
private_key_path = "/home/alice/.local/share/prrr/keys/client.key"
server_public_key = "base64..."
server_kem_public_key = "base64..."

[tunnel]
interface_name = "prrr0"
ip_address = "10.0.0.2"
netmask = "255.255.255.0"
mtu = 1280

[psk]
probe_resist_key = "base64..."

[obfuscation]
tls_profile = "chrome"

[logging]
level = "info"
```

### Wire Format Reference

**Hybrid handshake message 1:**
```
┌────────────────────────────────────┐
│ Noise IK message 1                 │
│  - Ephemeral public key (32 bytes) │
│  - Encrypted identity (48 bytes)   │
├────────────────────────────────────┤
│ Payload:                           │
│  - ML-KEM ciphertext (1088 bytes)  │
└────────────────────────────────────┘
Total: ~1168 bytes
```

**Encrypted packet:**
```
┌──────────┬─────────────────┬──────────┐
│ Counter  │   Ciphertext    │   Tag    │
│ 8 bytes  │   (variable)    │ 16 bytes │
└──────────┴─────────────────┴──────────┘
```

**MASQUE datagram:**
```
┌─────────────────┬────────────┬─────────┐
│ Quarter Stream  │ Context ID │ Payload │
│      ID         │   (0)      │   ...   │
└─────────────────┴────────────┴─────────┘
   (varint)         (varint)     (variable)
```

**Traffic morphing frame:**
```
┌──────────────┬─────────────┬─────────────┐
│ Length       │  Payload    │  Padding    │
│ (2 bytes BE) │  (n bytes)  │  (random)   │
└──────────────┴─────────────┴─────────────┘
```

**Authentication token:**
```
┌────────────┬────────────┬──────────────┐
│   Nonce    │ Timestamp  │     MAC      │
│  16 bytes  │  8 bytes   │   32 bytes   │
└────────────┴────────────┴──────────────┘
Total: 56 bytes → base64url encoded
```

---

## Appendix B: Glossary

**AEAD** - Authenticated Encryption with Associated Data. Encryption that also authenticates, preventing tampering.

**ALPN** - Application-Layer Protocol Negotiation. TLS extension for choosing which protocol to use (h3, h2, etc.).

**ChaCha20-Poly1305** - Modern AEAD cipher. ChaCha20 encrypts, Poly1305 authenticates.

**DPI** - Deep Packet Inspection. Technology that examines packet contents to identify traffic type.

**Forward Secrecy** - Property where compromising long-term keys doesn't reveal past session keys.

**HARP** - HTTPS API Relay Protocol. prrr's default transport that tunnels VPN traffic over standard HTTPS using WebSocket or HTTP polling (TCP port 443).

**HKDF** - HMAC-based Key Derivation Function. Standard way to derive multiple keys from one secret.

**HTTP/3** - Latest HTTP version, built on QUIC instead of TCP.

**Hybrid KEX** - Key exchange using both classical (X25519) and post-quantum (ML-KEM-768) algorithms.

**JA3/JA4** - TLS fingerprinting techniques that hash handshake parameters.

**KEM** - Key Encapsulation Mechanism. Public-key encryption specialized for sharing secrets.

**MASQUE** - Multiplexed Application Substrate over QUIC Encryption. Standard for proxying over HTTP/3.

**ML-KEM-768** - Post-quantum KEM standardized by NIST (formerly Kyber).

**MTU** - Maximum Transmission Unit. Largest packet size allowed.

**NAT** - Network Address Translation. Remapping IP addresses (private ↔ public).

**Noise Protocol** - Framework for building cryptographic handshake protocols.

**Nonce** - Number used once. Ensures same key+nonce never encrypts multiple messages.

**Post-Quantum** - Cryptography resistant to quantum computer attacks.

**PSK** - Pre-Shared Key. Secret known to both parties before communication.

**QUIC** - Quick UDP Internet Connections. Modern transport protocol (UDP + reliability + encryption).

**Replay Attack** - Resending old valid messages to cause unwanted effects.

**TLS** - Transport Layer Security. Standard for encrypted connections.

**TUN Device** - Virtual network interface that captures IP packets for processing by software.

**Varint** - Variable-length integer encoding. Small numbers use fewer bytes.

**X25519** - Elliptic curve Diffie-Hellman using Curve25519.

---

**End of Book**

*You now have a complete understanding of how prrr works, from basic concepts to advanced cryptography. Welcome to the world of censorship-resistant, post-quantum secure VPNs!*
