# dig-relay-protocol

Canonical **DIG relay protocol** — the single source of truth for the wire between a
DIG node and a relay (and, later, between relays). Defines the RLY message set,
framing, and state machines that today are vendored byte-for-byte across `dig-gossip`
(`src/relay/relay_types.rs`) and `dig-relay` (`src/wire.rs`).

**v1 scope: NODE-TO-RELAY only** (RLY-001 Register … the persistent-reservation +
GetPeers + peer-notice frames). Relay-to-relay (the decentralized relay mesh) is a
later addition (DIG-Network/dig_ecosystem#873).

Consumed by: **dig-relay** (server), **dig-nat** (relay client / transport), and
**dig-gossip** (peer discovery/pool) — each depends on this crate instead of a
vendored copy (eliminates the byte-drift risk; aligns the canonical-crate convergence
epic #838). chia-wallet-sdk-aware for canonical Chia types. Normative `SPEC.md` +
KATs forthcoming.

Design: DIG-Network/dig_ecosystem#873 (mesh) / #870 (node↔relay connect).
