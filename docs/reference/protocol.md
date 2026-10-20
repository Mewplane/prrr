# Protocol reference

This page describes the inspected implementation, not a wire-compatibility commitment with every external MASQUE or Noise implementation. Message sizes below refer to the inner prrr layer unless stated otherwise.

## Hybrid handshake

The active client and server paths use Noise IK with ML-KEM-768. The initiator knows the server's X25519 static public key and 1184-byte ML-KEM encapsulation key. The client encapsulates a 32-byte KEM secret and puts the 1088-byte KEM ciphertext into the first Noise message's encrypted payload. The server decrypts, checks the initiator identity against its registry, decapsulates, and returns the second Noise message.

The session KDF is **HKDF-SHA256**. The Noise handshake pattern is `Noise_IK_25519_ChaChaPoly_BLAKE2s`; these names refer to different layers.

| KDF input/output | Value |
| --- | --- |
| Salt | Noise handshake hash |
| Input keying material | ML-KEM shared secret |
| Info | Literal `PhantomVPN v1`, then initiator static public key, then responder static public key |
| Output | 96 bytes: three 32-byte keys |
| First key | Initiator-to-responder encryption key |
| Second key | Responder-to-initiator encryption key |
| Third key | Derived header key |

The responder reverses the send/receive use of the directional keys. Describing a derived header key does not imply the packet format below encrypts its counter.

## Encrypted packet

```text
+----------------------+-------------------------+------------------+
| counter: 8 bytes BE  | encrypted IP payload    | Poly1305: 16 B   |
+----------------------+-------------------------+------------------+
```

- Cipher: ChaCha20-Poly1305.
- Nonce: four zero bytes followed by the 8-byte epoch-local counter, making 12 bytes. The wire counter stays absolute across rekey epochs; the channel derives the epoch and local counter from it.
- Additional authenticated data: the encoded counter.
- Minimum packet length: 24 bytes.
- Replay window: 2048 counters by default; duplicates and sufficiently old packets are rejected, while limited reordering is supported.
- Default channel rekey threshold: `2^32` sent packets. This differs from a parsed interval or session-info field measured in seconds; do not infer that an advertised seconds field drives a timer in every caller.

The channel lives inside an outer transport. This diagram does not mean an ordinary observer outside outer TLS can read these fields.

## HARP framing and bindings

HARP frames have a 4-byte header:

| Byte(s) | Contents |
| --- | --- |
| 0, high nibble | Version 1 |
| 0, low nibble | Type: data `0`, keepalive `1`, close `2` |
| 1 | Reserved zero |
| 2–3 | Payload length, unsigned 16-bit big-endian |

The maximum payload is 65535 bytes. Bindings carry these frames through HTTP/2 upload/download streams, WebSocket streaming, or HTTP polling. The HARP session response advertises supported capabilities. This is a prrr application protocol over HTTP; using HTTPS alone does not prove a browser-equivalent traffic fingerprint.

## MASQUE datagrams

The implementation frames payloads with QUIC variable integers for the Quarter Stream ID and Context ID zero before the encrypted-channel payload. The client uses its MASQUE connection layer and QUIC datagrams. UDP reachability and a sufficient datagram-size budget are necessary; a TCP-only firewall rule does not permit this path.

The default TUN MTU is 1100. The client checks the payload plus encrypted-channel and MASQUE overhead against the connection's datagram budget; increasing MTU can make a connection unusable even when handshaking works.

## Source map

- [Hybrid handshake](https://github.com/Mewplane/prrr/blob/191ebaf/src/handshake/hybrid.rs)
- [KDF implementation](https://github.com/Mewplane/prrr/blob/191ebaf/src/crypto/kdf.rs)
- [Encrypted channel](https://github.com/Mewplane/prrr/blob/191ebaf/src/transport/encrypted_channel.rs)
- [HARP framing](https://github.com/Mewplane/prrr/blob/191ebaf/src/transport/harp.rs)
- [MASQUE framing](https://github.com/Mewplane/prrr/blob/191ebaf/src/transport/masque.rs)

Watch the same layers in [the animated mechanics guide](../explanation/mechanics.md).
