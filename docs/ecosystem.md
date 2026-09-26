# Ecosystem registry registration

prrr coexists on one laptop with sibling components (`sy`, `syauth`,
`cathouse`). For zero-configuration coexistence, prrr advertises a **descriptor**
to the ecosystem registry so siblings can learn what prrr is, which exclusive
resources it owns (the Android `VpnService` slot, port 443, the tunnel
interface), and the current routing flags. This is defined in the ecosystem
SPEC §3.

This is a **separate concept** from prrr's server-side client registry (the
SQLite database of authorized VPN clients). The ecosystem registry is a
read-only coordination surface on the laptop.

## When prrr registers

The prrr **client** writes its descriptor on **tunnel up** and updates it on
**tunnel down**:

- On tunnel up: the descriptor reflects the connected state — the live
  `full_tunnel` flag and the effective `excluded_cidrs` (the LAN
  auto-exclusion set, see [configuration](configuration.md#local-lan-auto-exclusion-default)).
- On tunnel down: the descriptor is rewritten with no excluded CIDRs to
  reflect that prrr is no longer capturing traffic.

Registration is **best-effort**. If the registry transport is unavailable
(see below), prrr logs at debug/warn and continues; tunnel bring-up is never
blocked or failed by registration.

## Transport (file fallback)

The ecosystem registry is hosted by `sy`. Components prefer a `sy` IPC op, but
SPEC §9.1 blesses a **file fallback** for components that run before `sy`:

```
$XDG_RUNTIME_DIR/sy/ecosystem/prrr.json
```

prrr currently uses the file fallback. The descriptor is written **atomically**
(temp file + rename) so a sibling never reads a partially written file. If
`$XDG_RUNTIME_DIR` is unset or the directory is unwritable, registration is
skipped silently (best-effort).

## Descriptor shape (SPEC §3)

```json
{
  "component": "prrr",
  "role": "vpn-egress",
  "owns": ["android:VpnService", "udp:443", "iface:prrr0"],
  "endpoints": { "lan": "vpn.example.com:443" },
  "identity": { "peer_id": "<blake3-of-pubkey hex>" },
  "flags": {
    "full_tunnel": false,
    "excluded_cidrs": ["192.168.1.0/24"],
    "client_to_client": false,
    "mesh_peer_addr": null
  }
}
```

- `owns` lists the port token for the **active transport**: `udp:443` for MASQUE,
  `tcp:443` for HARP, plus the Android `VpnService` slot and the tunnel `iface:`.
- `identity.peer_id` is the lowercase hex blake3 digest of the client's Noise
  static public key.
- `flags.client_to_client` **follows the Step 4 sharing toggle** (FRD-004): it is
  `true` when the client has opted into inter-client routing (`prrr sharing
  enable`, the Android toggle, or an authorized remote enable) and `false`
  otherwise. The daemon reads the persisted sharing state
  (`$HOME/.config/prrr/sharing.json`) when building the descriptor, so the flag
  tracks the live opt-in. Default is `false` (sharing off).
- `flags.mesh_peer_addr` carries the authorized peer's reachable mesh address
  (`host:port`) when client-to-client sharing is **established and probed**, and
  is `null` otherwise. See "Publishing the mesh peer address" below.

## Publishing the mesh peer address (SPEC §5b/§6)

When sharing is established, prrr publishes the authorized peer's reachable mesh
address into `flags.mesh_peer_addr` so a sibling (cathouse) reaches the laptop
off-LAN **with no cathouse-side configuration** — it just reads the registry.

- **Probe before publish.** prrr advertises the address **only after** confirming
  the inter-client route is actually up. The reachability check is the
  `MeshProbe` trait (default `TcpMeshProbe`: a bounded TCP connect with a
  `750 ms` timeout). If the probe fails, `mesh_peer_addr` stays/returns to
  `null` and prrr logs at debug — a non-routable address is never advertised
  (SPEC §7: publish only routable facts; fail-closed).
- **Set on established.** With sharing enabled and the peer's address probed
  reachable, prrr records it in the persisted sharing state
  (`SharingState.peer_mesh_addr`) and propagates it into `flags.mesh_peer_addr`
  via the same `EcosystemRegistrar` publish path. The canonical representation is
  a single `host:port` string shared by the sharing state and the descriptor.
- **Clear on drop.** `prrr sharing disable` clears the address, and the
  tunnel-down publish path rewrites the descriptor with `mesh_peer_addr = null`.
  Both transitions return the field to `null`, so a sibling never reaches a
  stale address (it also re-verifies liveness on its own channel per SPEC §7).

### Sharing enforcement (FRD-004, SPEC §9.4)

prrr is the enforcement point for the sharing switch. A remote enable request
relayed from `sy`/cathouse flips `client_to_client` **only** when both hold,
re-checked live:

1. the **server-side** sharing-pair authorization exists (Step 3
   `is_pair_allowed`), AND
2. the request carries a **per-use biometric signature** that verifies against
   the trusted key.

A missing pair authorization, a missing signature, or a bad signature is refused
with no state change (fail-closed, SPEC §7). The per-use biometric signature is
verified with prrr's existing keyed-MAC primitive (BLAKE3-keyed + constant-time
compare) behind a `BiometricVerifier` trait; prrr ships no Ed25519 of its own
(that lives in syauth), and the trait keeps the verifier swappable when syauth's
asymmetric key material is threaded through. prrr never trusts the relay alone.

## Trust model

Per SPEC §7, the registry carries **shared facts, not authority**. A sibling
treats prrr's descriptor as a hint and still authenticates and authorizes on
its own channel. Because the descriptor is rewritten on state change and may
linger if prrr is killed, consumers should re-verify liveness rather than trust
a stale "connected" record.
</content>
