// FRD: specs/frds/FRD-010.md, specs/frds/FRD-011.md, specs/frds/FRD-013.md

/// Active probing resistance: HMAC cookie authentication, decoy responses, rate limiting.
pub mod probe_resist;

/// TLS fingerprint mimicry via cipher suite and key exchange group reordering.
pub mod tls_mimicry;

/// Traffic morphing: packet padding, timing jitter, and dummy traffic.
pub mod traffic_morph;
