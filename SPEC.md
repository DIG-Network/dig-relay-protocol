# dig-relay-protocol — SPECIFICATION

Normative specification of the **node↔relay** wire protocol for the DIG Network relay
(`relay.dig.net`). This is the authoritative contract an independent reimplementation is built
against. The key words MUST, MUST NOT, SHOULD, and MAY are used per RFC 2119.

**Scope.** This document specifies the whole relay-boundary protocol: the **node↔relay** control wire
(RLY-001..007 + the v2 recipient-sealed control frames, §8) AND the **relay↔relay** mesh wire (§9). It
does NOT specify the decentralized-relay NETWORK that DRIVES the mesh (on-chain relay discovery,
relay-PEX routing, relay-switch policy) — that is dig_ecosystem #873, which consumes this wire.

**Protocol version.** This document specifies **protocol_version 2**. v2 is a strict, additive superset
of v1 (§7): a v1 peer interoperates unchanged, never emitting the v2 `relay_hello`/`sealed` frames.

**Provenance / byte-identity.** These message shapes are byte-identical to the wire previously
vendored across `dig-gossip` (`src/relay/relay_types.rs`, the authoritative shape),
`dig-relay` (`src/wire.rs`), and consumed by `dig-nat` (`src/relay.rs`). This crate is now the single
source of truth; the golden fixtures in `tests/kat.rs` pin every byte. A consumer replacing its
vendored copy with this crate MUST observe no wire change. Cross-repo interaction is recorded in the
superproject `SYSTEM.md`.

---

## 1. Transport & framing

- **Transport.** Messages are carried over a **WebSocket**, established over **mTLS** (both parties
  authenticate; the node presents a client cert whose SPKI DER hashes to its `peer_id`). The relay
  endpoint is `wss://relay.dig.net:9450` by default (canonical `DIG_RELAY_URL`), overridable via the
  `DIG_RELAY_URL` environment variable, and disabled with `DIG_RELAY_URL=off`/`disabled`.
- **Encoding.** Each message is a single JSON object. Implementations SHOULD send it as a WebSocket
  **text** frame; a receiver MUST also accept the identical JSON bytes in a **binary** frame.
- **Discriminator.** The JSON object carries a leading `"type"` field (serde internally-tagged
  representation, `#[serde(tag = "type")]`). The `type` value selects the message; remaining fields
  are the message's payload, in the field order given in §3. A receiver MUST reject an object with an
  unknown `type`, a missing `type`, a missing required field, or a wrongly-typed field.
- **Identity encoding.** `peer_id` fields are lowercase hex **strings** (`peer_id = SHA-256(TLS SPKI
  DER)`), NOT a binary 32-byte value. This is a wire invariant: to preserve byte-identity the wire
  transmits the hex string form.
- **Addresses.** `external_addr` fields are `SocketAddr` rendered as their standard string form —
  `IP:PORT` for IPv4, `[IP]:PORT` for IPv6. Per ecosystem rule §5.2 (IPv6-first) an implementation
  SHOULD advertise IPv6 candidates first; the wire representation is family-agnostic and round-trips
  both.

---

## 2. Message set

The complete node↔relay message set is the `RelayMessage` enum. Direction is C→R (node→relay),
R→C (relay→node), or ↔ (either).

| `type` | RLY | Dir | Purpose |
|--------|-----|-----|---------|
| `register` | RLY-001 | C→R | Register / hold a reservation. |
| `register_ack` | RLY-001 | R→C | Acknowledge a registration. |
| `unregister` | RLY-001 | C→R | Release the reservation. |
| `relay_message` | RLY-002 | C→R→C | Relayed (last-resort) directed transport. |
| `broadcast` | RLY-003 | C→R→* | Fan-out to all peers. |
| `peer_connected` | — | R→C | A peer connected to the relay. |
| `peer_disconnected` | — | R→C | A peer left the relay. |
| `get_peers` | RLY-005 | C→R | Request the connected-peer list. |
| `peers` | RLY-005 | R→C | The peer-list response. |
| `ping` | RLY-006 | ↔ | Keepalive request. |
| `pong` | RLY-006 | ↔ | Keepalive response. |
| `hole_punch_request` | RLY-007 | C→R | Ask the relay to coordinate a hole punch. |
| `hole_punch_coordinate` | RLY-007 | R→C | Counterpart's external address to dial. |
| `hole_punch_result` | RLY-007 | C→R | Outcome of a coordinated hole punch. |
| `error` | — | R→C | Error notification. |
| `relay_hello` | v2 | R→C | The relay's signed `RelayDescriptor`, sent first (§8). |
| `sealed` | v2 | ↔ | Transport for a recipient-sealed control/mesh frame (§8/§9). |

The `sealed` variant is `{"type":"sealed","envelope":[<u8>...]}`, where `envelope` is the encoded
`dig-message` `DigMessageEnvelope` bytes. `relay_hello` is `{"type":"relay_hello","descriptor":{…}}`
(§8). Both are additive v2 variants; a v1 receiver rejects an unknown `type` (§1), so they are only
sent to a peer that negotiated v2.

---

## 3. Message shapes (byte-level)

Field order is normative (it is the JSON emission order). Golden examples are the exact bytes.

### RLY-001 — Registration

- **`register`** — `peer_id: string`, `network_id: string`, `protocol_version: u32`,
  `listen_addrs: SocketAddr[]` (§2.9a, additive since v1 — omitted when empty).
  `{"type":"register","peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1}` (empty
  `listen_addrs` omitted) /
  `{"type":"register","peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1,"listen_addrs":["[2001:db8::1]:9445","203.0.113.1:9445"]}`
- **`register_ack`** — `success: bool`, `message: string`, `connected_peers: usize`.
  `{"type":"register_ack","success":true,"message":"registered","connected_peers":3}`
- **`unregister`** — `peer_id: string`.
  `{"type":"unregister","peer_id":"a"}`

### RLY-002 — Directed relayed transport

- **`relay_message`** — `from: string`, `to: string`, `payload: bytes` (JSON array of `u8`),
  `seq: u64`. `payload` is END-TO-END SEALED (see §5 NC-1).
  `{"type":"relay_message","from":"a","to":"b","payload":[1,2],"seq":9}`

### RLY-003 — Broadcast

- **`broadcast`** — `from: string`, `payload: bytes`, `exclude: string[]`.
  `{"type":"broadcast","from":"a","payload":[7],"exclude":["c"]}`

### Peer notifications

- **`peer_connected`** — `peer: RelayPeerInfo` (§4).
  `{"type":"peer_connected","peer":{"peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1,"connected_at":100,"last_seen":200}}`
- **`peer_disconnected`** — `peer_id: string`.
  `{"type":"peer_disconnected","peer_id":"a"}`

### RLY-005 — Peer discovery

- **`get_peers`** — `network_id: string | null` (a filter; `null` means all networks).
  `{"type":"get_peers","network_id":"DIG_MAINNET"}` / `{"type":"get_peers","network_id":null}`
- **`peers`** — `peers: RelayPeerInfo[]`.
  `{"type":"peers","peers":[ ... ]}`

### RLY-006 — Keepalive

- **`ping`** — `timestamp: u64`. `{"type":"ping","timestamp":5}`
- **`pong`** — `timestamp: u64` (echoes the ping). `{"type":"pong","timestamp":5}`

### RLY-007 — NAT traversal

- **`hole_punch_request`** — `peer_id: string`, `target_peer_id: string`, `external_addr: SocketAddr`.
  `{"type":"hole_punch_request","peer_id":"a","target_peer_id":"b","external_addr":"203.0.113.1:9444"}`
- **`hole_punch_coordinate`** — `peer_id: string`, `external_addr: SocketAddr`.
  `{"type":"hole_punch_coordinate","peer_id":"a","external_addr":"203.0.113.1:9444"}`
- **`hole_punch_result`** — `peer_id: string`, `success: bool`.
  `{"type":"hole_punch_result","peer_id":"a","success":true}`

### Error

- **`error`** — `code: u32`, `message: string`.
  `{"type":"error","code":3,"message":"nope"}`

---

## 4. `RelayPeerInfo`

A peer as tracked by the relay, carried in `peers` and `peer_connected`. Fields, in order:

| Field | Type | Meaning |
|-------|------|---------|
| `peer_id` | string (hex) | Stable identity, `SHA-256(TLS SPKI DER)`. |
| `network_id` | string | Network the peer registered under. |
| `protocol_version` | u32 | Relay protocol version advertised. |
| `connected_at` | u64 | Unix seconds the peer first connected. |
| `last_seen` | u64 | Unix seconds of the peer's last activity. |
| `addresses` | SocketAddr[] | Relay-resolved dialable candidates (§2.9a); omitted when empty. |

The `RelayPeerInfo::new(peer_id, network_id, protocol_version)` constructor stamps `connected_at` ==
`last_seen` == the current unix time and leaves `addresses` empty (the relay populates it, §2.9a).

---

## 2.9a Connect-leg addressing — `listen_addrs` + `addresses` (additive since v1, NC-6 soft-fork)

The connect leg turns a relay-DISCOVERED peer into a directly-dialable one (dig_ecosystem #924, B1).
Two additive optional fields carry the dialable candidates; everything else is unchanged.

- **`register.listen_addrs: SocketAddr[]`** — the node's advertised gossip LISTEN candidate
  address(es), IPv6-first (§5.2). The host is typically the unspecified dual-stack address (`[::]`);
  the load-bearing part the relay keeps is the PORT.
- **`RelayPeerInfo.addresses: SocketAddr[]`** — the relay-resolved dialable candidate(s) it hands a
  peer in `peers`/`peer_connected`, IPv6-first. For each advertised `listen_addr` whose host is
  unspecified/loopback/private, the relay substitutes the peer's OBSERVED reflexive IP and keeps the
  advertised port, yielding a real `reflexive_IP:port` another node direct-dials over the existing
  mTLS path; a public advertised host passes through unchanged.

**Soft-fork contract (NC-6).** Both fields are serialized with `#[serde(default, skip_serializing_if
= "Vec::is_empty")]`:

- An implementation MUST tolerate their ABSENCE: a payload without them decodes with the field
  defaulting to empty. Pre-#924 peers/relays therefore interoperate unchanged, falling back to
  identity-only relayed reachability.
- An EMPTY field MUST be OMITTED from serialization, so the bytes are byte-identical to what a
  pre-#924 peer emits — no wire drift for existing peers.
- A NON-EMPTY field enables the B1 direct-dial path. It appears LAST in each shape's field order
  (after the fields specified in §3 / §4), preserving the emission order of all prior fields.

This is additive-only per §7 / §5.1 (NC-6): no existing `type`, field, order, or type is removed,
renamed, or repurposed. The `tests/kat.rs` golden fixtures pin both the omitted-when-empty bytes and
the non-empty round-trip.

---

## 5. Security contracts

### NC-1 — Directed payloads are end-to-end sealed to the recipient (on top of mTLS)

The relay terminates the mTLS transport and can see every envelope, so the transport channel alone
does NOT protect message contents from the relay. Therefore, per ecosystem rule §5.4, every
**directed** payload MUST be END-TO-END ENCRYPTED (sealed) to the recipient's DID-anchored identity
key BEFORE it is placed on this wire. This applies in two layers:

- **`relay_message` (RLY-002)** — the `payload` bytes MUST already be node↔node-sealed to the
  destination node's key by a higher layer; the relay forwards ciphertext. An implementation MUST NOT
  put recipient-specific plaintext in a `relay_message` payload.
- **v2 sealed control + mesh frames** — the directed node↔relay control frames (§8) and ALL mesh
  frames (§9) are sealed to the recipient RELAY's (or node's) BLS G1 identity key, carried inside a
  `sealed` envelope. `mesh_forward` is therefore **doubly opaque**: its inner `payload` is already
  node↔node-sealed, and the whole frame is then relay↔relay-sealed — no relay on the path can read it.

The relay MUST NOT be able to decrypt any of the above. A conformance test MUST assert the on-wire
sealed bytes are ciphertext, not plaintext (see `tests/seal.rs` — the plaintext marker MUST NOT appear
in the `sealed` envelope bytes).

`broadcast` (RLY-003) is a public all-peers fan-out (no single recipient) and is therefore NOT
e2e-sealed to one key; it remains mTLS-authenticated and, where the higher layer requires it, signed.
Likewise `get_peers`/`peers`/`peer_connected`/`peer_disconnected` are semi-public discovery the relay
MUST read, and `ping`/`pong`/`error` are plaintext. The sealing scheme (G1-DHKEM/AEAD composition +
KATs) is specified by `dig-message`/`dig-identity`, not here; this protocol only carries the sealed
bytes and allocates the band ids.

### NC-4 — Envelope-only routing

The relay routes purely on ENVELOPE fields — `from`, `to`, `network_id`, and the `type` — and MUST
NOT inspect, depend on, or branch on the opaque `payload` contents. For a `sealed` frame this is the
`dig-message` envelope's cleartext header (sender/recipient DID, `message_type`); the frame BODY is
ciphertext. `get_peers.network_id` filters the returned set by network; routing decisions derive only
from these envelope fields. This keeps the relay a content-agnostic forwarder and is what makes NC-1
sufficient (the relay never needs the plaintext to route).

## 6. Protocol state machine (node side)

A node's relay session progresses through four observable states. The states are node-side connection
status (not a wire message), driven by the messages above:

- **Disabled** — reservation off (`DIG_RELAY_URL=off`); no connection attempted.
- **Connecting** — dialing / registering; a `register` (RLY-001) has been or is about to be sent.
- **Connected** — a `register_ack` with `success: true` has arrived; the reservation is held and the
  node is reachable to peers.
- **Disconnected** — not connected; backing off and retrying with capped exponential backoff. The
  graceful-fallback resting state; the node keeps serving regardless.

Session lifecycle over one held connection:

1. Connect the WebSocket (mTLS) → send `register` (RLY-001) → send an initial `get_peers` (RLY-005).
2. On `register_ack{success:true}` → **Connected**; on `success:false` or `error` → fail the session.
3. Periodically send `ping` (RLY-006) as keepalive; answer an inbound `ping` with a matching `pong`.
4. Periodically re-send `get_peers` over the SAME socket; fold `peers`, `peer_connected`, and
   `peer_disconnected` into the node's peer view.
5. On close/error → **Disconnected**, clear the per-session peer view, back off, and reconnect.

A relay-registered node MUST tolerate the relay being unreachable indefinitely: the reservation loop
MUST NOT block startup, panic, or busy-loop (every retry waits a bounded, capped backoff).

---

## 7. Versioning & compatibility

- `protocol_version` is advertised in `register` / `RelayPeerInfo` / the `relay_hello` descriptor.
  v1 = plaintext RLY-001..007; v2 = adds the BLS relay identity + recipient-sealed control/mesh (§8/§9).
- The wire is **additive-only**: new `type` variants and new optional fields MAY be added; an existing
  `type`, field name, field order, or field type MUST NOT be removed, renamed, repurposed, or
  re-typed (doing so breaks byte-identity with deployed nodes). The v2 `relay_hello`/`sealed` variants
  and the §8/§9 frames are additive; every v1 KAT is unchanged.
- **Capability negotiation + downgrade rule.** A v2 peer advertises seal capability in its signed
  `relay_hello` / `register`. A session seals iff BOTH peers speak ≥ v2 and advertise seal support; a
  v2↔v1 pairing falls back to plaintext control. A node/relay MAY run in **required-seal** mode, in
  which it MUST REFUSE a session that cannot seal (fail-closed) — so an on-path attacker cannot strip
  sealing by forging a v1 downgrade. `SealMode::Optional` permits the plaintext fallback.
- The relay↔relay mesh (§9) uses `type` values disjoint from §2 (band `0x0900`); the decentralized
  relay NETWORK that drives them is #873, which consumes this wire without changing it.


---

## 8. v2 — relay BLS identity, `RelayDescriptor`, and recipient-sealed control

### 8.1 Relay identity

A relay has a node-level **BLS12-381 G1 identity key** — the SAME model as a node (`dig-identity`
slot `0x0010`, EIP-2333 path `m/12381'/8444'/9'/0'`). A relay is a node with a relay role. The key is
NOT fund-moving (a future payment-for-connections $DIG venue is out of scope). The relay's `peer_id`
remains the transport id (`SHA-256(TLS SPKI DER)`); the BLS G1 key is the SEAL/signing identity.

### 8.2 `RelayDescriptor` (anti-substitution binding)

A relay describes itself with a BLS-G2-signed `RelayDescriptor` binding, under one signature:
`relay_did` (32B on-chain DID) · `bls_g1_pub` (48B G1 identity key) · `peer_id_spki_hash` (32B,
`SHA-256(TLS SPKI DER)`) · `network_id` · `capabilities` · `addresses` (IPv6-first, §5.2) ·
`protocol_version` · `timestamp_ms` · `expires_at` · `sig` (96B G2 over all the preceding fields, in
declared order, length-prefixed under the domain `DIGNET-RELAY-DESCRIPTOR:v2`).

A verifier MUST, fail-closed: (1) subgroup-check `bls_g1_pub`; (2) verify `sig` over the transcript;
(3) confirm the presented mTLS SPKI hashes to `peer_id_spki_hash`; (4) confirm the descriptor is not
past `expires_at`. Where chain access exists, it MUST additionally resolve `relay_did → G1` and
confirm it equals `bls_g1_pub`. Any failure → discard (substitution attempt).

### 8.3 Handshake (chicken-and-egg resolution)

1. On a v2 session the relay sends **`relay_hello { descriptor }`** FIRST — plaintext but BLS-signed.
2. The node verifies the descriptor (§8.2) against the live mTLS SPKI, authenticating the relay's G1
   key BEFORE trusting it.
3. The node then SEALS its `register` to that authenticated key and sends it as a `sealed` frame.

### 8.4 Sealed control frames (band `0x0800`)

The directed control frames are sealed to the recipient's G1 key, carried in a `sealed` envelope whose
`message_type` is a band-`0x0800` id. SEAL to the **relay** (C→R): `register`, `unregister`,
`hole_punch_request`, `hole_punch_result`. SEAL to the **node** (R→C): `register_ack`,
`hole_punch_coordinate`. Opening (`dig-message` `open_message`) provides sender-signature verification,
anti-replay, expiry, and subgroup checks. A frame sealed to relay A decaps to the wrong key at relay B
and MUST be discarded.

**Band id allocation** (disjoint from the deferred retainer economy #1202): sealed control occupies
`0x0800_0001..0x0800_0006`; `0x0800_0100..0x0800_01FF` is RESERVED for #1202's `RTN-*` ids. Mesh (§9)
uses band `0x0900`.

---

## 9. v2 — relay↔relay mesh (band `0x0900`)

Relays coordinate over the `MeshMessage` frame set, EVERY frame sealed to the peer relay's G1 key
(carried in a `sealed` envelope, `message_type` in band `0x0900`):

| `type` | id | Purpose |
|--------|-----|---------|
| `mesh_hello` / `mesh_hello_ack` | `0x0900_0001` / `_0002` | Mutual handshake advertising each relay's `RelayDescriptor`. |
| `mesh_peer_exchange` | `0x0900_0003` | Relay-PEX frame (frame only; routing logic is #873). |
| `mesh_forward` | `0x0900_0004` | Forward a node↔node payload between relays — **doubly opaque** (NC-1). |
| `mesh_keepalive` | `0x0900_0005` | Inter-relay liveness. |
| `mesh_handoff` / `mesh_switch` | `0x0900_0006` / `_0007` | Reservation handoff / load-shed signaling. |
| `mesh_error` | `0x0900_00FF` | Inter-relay error notification. |

A mesh frame misdelivered to the wrong relay decaps to the wrong key → discard. `mesh_forward`'s inner
`payload` remains node↔node-sealed, so neither the forwarding relay nor any mesh hop can read it.

---
