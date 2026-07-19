# dig-relay-protocol

The canonical **relay-boundary** wire protocol for the DIG Network relay (`relay.dig.net`): the
**node↔relay** control wire AND the **relay↔relay** mesh wire, in one crate. This README is the full
interface reference (for humans and LLMs); [`SPEC.md`](SPEC.md) is the normative, byte-level contract.

A DIG Node behind NAT cannot accept inbound dials, so it holds a constant registered connection with
a publicly-reachable relay and speaks the **RLY-001 … RLY-007** message set. In v2 the control wire is
additionally **recipient-sealed** to a relay's **BLS G1 identity key**, and relays coordinate among
themselves over the **mesh** frame set. The larger decentralized-relay NETWORK (on-chain discovery,
relay-PEX routing, relay-switch policy) is epic dig_ecosystem #873, which CONSUMES this wire.

## Single source of truth

This crate is the ONE definition of the relay-boundary wire. The v1 node↔relay types are extracted
**byte-identical** from the copies previously vendored across `dig-gossip` (`src/relay/relay_types.rs`,
authoritative shape + client), `dig-relay` (`src/wire.rs`, server) and `dig-nat` (`src/relay.rs`,
client). A consumer that swaps its vendored copy for this crate observes **zero** v1 wire change —
proven by the golden fixtures in [`tests/kat.rs`](tests/kat.rs).

## Features

| Feature | Pulls in | Gives you |
|---------|----------|-----------|
| *(default)* | `serde` only | The pure wire TYPES: `RelayMessage`, `RelayPeerInfo`, `RelayDescriptor`, `MeshMessage`, the `ids` band map. Parse/emit the wire with zero crypto deps. |
| `seal` | `dig-message`, `dig-identity` | The [`seal`] module: derive a relay BLS identity, sign/verify a `RelayDescriptor`, and seal/open the band-`0x0800` control + band-`0x0900` mesh frames. |

```toml
[dependencies]
dig-relay-protocol = "0.3"                                 # wire types only
dig-relay-protocol = { version = "0.3", features = ["seal"] } # + recipient-seal machinery
```

## Message map

### Node↔relay — `RelayMessage` (JSON over WebSocket, `#[serde(tag = "type")]`)

| `type` | RLY | Dir | Sealed (v2)? | Purpose |
|--------|-----|-----|--------------|---------|
| `register` | RLY-001 | C→R | **yes → relay** | Register / hold a reservation. |
| `register_ack` | RLY-001 | R→C | **yes → node** | Acknowledge a registration. |
| `unregister` | RLY-001 | C→R | **yes → relay** | Release the reservation. |
| `relay_message` | RLY-002 | C→R→C | no (already node↔node-sealed) | Relayed directed transport. |
| `broadcast` | RLY-003 | C→R→* | no (§5.4 public carve-out) | Fan-out to all peers. |
| `peer_connected` | — | R→C | no (semi-public discovery) | A peer connected. |
| `peer_disconnected` | — | R→C | no | A peer left. |
| `get_peers` | RLY-005 | C→R | no | Request the peer list. |
| `peers` | RLY-005 | R→C | no | The peer-list response. |
| `ping` / `pong` | RLY-006 | ↔ | no (plaintext) | Keepalive. |
| `hole_punch_request` | RLY-007 | C→R | **yes → relay** | Ask to coordinate a hole punch. |
| `hole_punch_coordinate` | RLY-007 | R→C | **yes → node** | Counterpart's address to dial. |
| `hole_punch_result` | RLY-007 | C→R | **yes → relay** | Outcome of a hole punch. |
| `error` | — | R→C | no (plaintext) | Error notification. |
| `relay_hello` | v2 | R→C | signed, not sealed | The relay's signed `RelayDescriptor`, sent FIRST. |
| `sealed` | v2 | ↔ | — | Transport for a sealed control/mesh frame (see below). |

### Relay↔relay — `MeshMessage` (band `0x0900`, ALL sealed to the peer relay's G1)

`mesh_hello` / `mesh_hello_ack` (mutual handshake advertising each descriptor) · `mesh_peer_exchange`
(relay-PEX frame) · `mesh_forward` (forward a node↔node payload — **doubly opaque**) · `mesh_keepalive`
· `mesh_handoff` / `mesh_switch` (reservation handoff/load-shed) · `mesh_error`.

### `RelayDescriptor` (anti-substitution identity record)

`relay_did` (32B on-chain DID) · `bls_g1_pub` (48B BLS G1 identity key) · `peer_id_spki_hash`
(`SHA-256(TLS SPKI DER)`) · `network_id` · `capabilities` · `addresses` (IPv6-first, §5.2) ·
`protocol_version` · `timestamp_ms` · `expires_at` · `sig` (96B BLS G2 over all the above).
`RelayDescriptor::verify(presented_spki, now_ms)` checks the signature + that the presented mTLS SPKI
hashes to `peer_id_spki_hash`, so a relay cannot present another relay's descriptor.

## The v2 handshake + seal (chicken-and-egg resolution)

1. On connect, the relay sends **`relay_hello { descriptor }`** FIRST — plaintext but BLS-signed.
2. The node calls `descriptor.verify(presented_spki, now_ms)` against the live mTLS SPKI, authenticating
   the relay's BLS G1 key BEFORE trusting it.
3. The node then **seals** its `register` to that now-authenticated key and sends it as a `sealed` frame.

A `sealed` frame carries an encoded `dig-message` envelope whose `message_type` is a band-`0x0800`
(control) or band-`0x0900` (mesh) id. Opening it (`dig-message` `open_message`) gives sender-signature
verification, anti-replay, expiry, and G1 subgroup checks for free. A frame sealed to relay A decaps to
the wrong key at relay B and is discarded (non-transferability). See the [`ids`] module for the exact
id allocation (sealed control lives in `0x0800_00xx`, leaving `0x0800_01xx` for the retainer economy
#1202).

## Example (`seal` feature)

```rust
# #[cfg(feature = "seal")] {
use dig_relay_protocol::seal::{RelayIdentity, SealContext, seal_control, open_control, Bytes32, ReplayGuard};
use dig_relay_protocol::RelayMessage;

let node  = RelayIdentity::from_master_seed(Bytes32::new([1; 32]), b"node-seed");
let relay = RelayIdentity::from_master_seed(Bytes32::new([2; 32]), b"relay-seed");

let register = RelayMessage::Register {
    peer_id: "deadbeef".into(),
    network_id: "DIG_MAINNET".into(),
    protocol_version: 2,
    listen_addrs: vec![],
};
let ctx = SealContext { correlation_id: Bytes32::new([9; 32]), counter: 0, timestamp_ms: 1_700_000_000_000, expires_at: 0 };

// Node seals `register` to the relay's BLS G1 key → a `RelayMessage::Sealed`.
let sealed = seal_control(&node, relay.did(), &relay.public_key(), &register, &ctx).unwrap();

// The relay opens it (only the relay's key can); `resolve` maps sender DID → G1 (dig-identity on chain).
let resolve = |_did, _epoch| Some(node.public_key());
let mut guard = ReplayGuard::new();
let opened = open_control(&relay, &sealed, resolve, &mut guard, 1_700_000_000_000).unwrap();
assert!(matches!(opened.message, RelayMessage::Register { .. }));
# }
```

## Back-compat

The v2 additions are new `type` variants + new optional fields — additive-only (§5.1). Every v1 KAT is
unchanged and still passes; a v1 peer simply never emits `relay_hello`/`sealed`. `protocol_version` is
negotiated in the signed handshake; a v2↔v1 pairing falls back to plaintext control, and a v2 node in
`SealMode::Required` refuses a downgraded session (fail-closed).

## License

Apache-2.0 OR MIT.
