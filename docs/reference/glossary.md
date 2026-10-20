# Glossary

| Term | Meaning in these guides |
| --- | --- |
| TUN | Virtual interface through which prrr receives and injects IP packets. |
| HARP | prrr's HTTP-based relay transport, with HTTP/2, WebSocket, and polling bindings. |
| MASQUE | prrr's QUIC/datagram transport and associated request/framing implementation. |
| Noise IK | Authenticated two-message handshake whose initiator knows the responder's static public key. |
| ML-KEM-768 | Key-encapsulation mechanism included in prrr's hybrid session setup. |
| HKDF | Extract/expand key derivation; prrr's session KDF uses SHA-256. |
| AEAD | Authenticated encryption: payload privacy plus integrity of authenticated fields. |
| Counter | The monotonic per-direction value encoded into the encrypted channel's nonce and AAD. |
| Replay window | Record of recently received counters, rejecting duplicates while allowing bounded reordering. |
| Registry | Server-side identity and address records used during client authorization. |
| fwmark | Linux socket/packet mark used to keep transport traffic out of its own tunnel route. |
| Resource route | A selected hostname/IP resolved to exact IPv4 destination routes. |
| DNS gate | Whether tunnel DNS responders are currently advertised to the host resolver. |
| Verdict lease | Maximum age of a DNS health verdict before its advertisement is withdrawn. |
| Black hole | An established-looking tunnel that consumes outbound packets without inbound progress. |
| Kill switch | Policy that blocks ordinary egress when a tunnel is unavailable; do not infer this from prrr's reconnect behavior. |

See [mechanics](../explanation/mechanics.md) for the relationships and [protocol](protocol.md) for exact fields.
