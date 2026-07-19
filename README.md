# dig-relay-protocol

The canonical **NODE-TO-RELAY** wire protocol for the DIG Network relay (`relay.dig.net`).

A DIG Node behind NAT cannot accept inbound dials, so it holds a constant registered connection with
a publicly-reachable relay. That connection speaks the **RLY-001 … RLY-007** message set defined
here — registration + reservation, peer discovery, keepalive, relay-coordinated NAT hole punching,
and relayed last-resort transport. Messages are JSON over a WebSocket.

## Single source of truth

This crate is the ONE definition of the node↔relay wire. It is extracted **byte-identical** from the
copies previously vendored across the ecosystem:

- `dig-gossip` — `src/relay/relay_types.rs` (the authoritative shape + the relay client);
- `dig-relay` — `src/wire.rs` (the relay server; a verbatim vendored copy);
- `dig-nat` — `src/relay.rs` (the persistent-reservation relay client).

A consumer that swaps its vendored copy for this crate observes **zero** wire change — proven by the
golden fixtures in [`tests/kat.rs`](tests/kat.rs), which pin the exact serialized bytes.

## Scope

**Node↔relay only.** Relay↔relay (mesh) framing does not exist yet and is tracked separately
(dig_ecosystem #873); it is not part of this crate.

## Usage

```toml
[dependencies]
dig-relay-protocol = "0.1"
```

```rust
use dig_relay_protocol::RelayMessage;

let register = RelayMessage::Register {
    peer_id: "deadbeef".into(),
    network_id: "DIG_MAINNET".into(),
    protocol_version: 1,
};
let json = serde_json::to_string(&register).unwrap();
```

See [`SPEC.md`](SPEC.md) for the normative, byte-level contract.

## Full Protocol Interface (at-a-glance LLM reference)

### RelayMessage Variants (RLY-001 … RLY-007)

JSON-RPC-like wire with `#[serde(tag = "type")]` — each variant's `type` field discriminates the message.

#### RLY-001: Registration Lifecycle

| Variant | Wire Type | Direction | Fields | Summary |
|---|---|---|---|---|
| `Register` | `register` | Client → Relay | `peer_id: String`, `network_id: String`, `protocol_version: u32` | Register after WebSocket connect, hold reservation |
| `RegisterAck` | `register_ack` | Relay → Client | `success: bool`, `message: String`, `connected_peers: usize` | Acknowledgement of Register; success flag |
| `Unregister` | `unregister` | Client → Relay | `peer_id: String` | Graceful disconnect, release reservation |

#### RLY-002: Targeted Message Forwarding

| Variant | Wire Type | Direction | Fields | Summary |
|---|---|---|---|---|
| `RelayGossipMessage` | `relay_message` | Client → Relay → Client | `from: String`, `to: String`, `payload: Vec<u8>`, `seq: u64` | Last-resort relayed transport; payload **end-to-end sealed** to recipient (NC-1) |

#### RLY-003: Broadcast

| Variant | Wire Type | Direction | Fields | Summary |
|---|---|---|---|---|
| `Broadcast` | `broadcast` | Client → Relay → All | `from: String`, `payload: Vec<u8>`, `exclude: Vec<String>` | Fan-out payload to all registered peers except exclude list |

#### Peer Notifications

| Variant | Wire Type | Direction | Fields | Summary |
|---|---|---|---|---|
| `PeerConnected` | `peer_connected` | Relay → Client | `peer: RelayPeerInfo` | A new peer connected to relay |
| `PeerDisconnected` | `peer_disconnected` | Relay → Client | `peer_id: String` | Peer disconnected from relay |

#### RLY-005: Peer Discovery

| Variant | Wire Type | Direction | Fields | Summary |
|---|---|---|---|---|
| `GetPeers` | `get_peers` | Client → Relay | `network_id: Option<String>` | Request connected-peer list, optionally filtered to one network |
| `Peers` | `peers` | Relay → Client | `peers: Vec<RelayPeerInfo>` | Response: peers currently registered with relay |

#### RLY-006: Keepalive

| Variant | Wire Type | Direction | Fields | Summary |
|---|---|---|---|---|
| `Ping` | `ping` | Bidirectional | `timestamp: u64` | Keepalive request; timestamp echoed in Pong |
| `Pong` | `pong` | Bidirectional | `timestamp: u64` | Keepalive response, echoes Ping timestamp |

#### RLY-007: NAT Traversal (Hole Punch Coordination)

| Variant | Wire Type | Direction | Fields | Summary |
|---|---|---|---|---|
| `HolePunchRequest` | `hole_punch_request` | Client → Relay | `peer_id: String`, `target_peer_id: String`, `external_addr: SocketAddr` | Ask relay to coordinate hole punch toward target |
| `HolePunchCoordinate` | `hole_punch_coordinate` | Relay → Client | `peer_id: String`, `external_addr: SocketAddr` | Hole-punch coordination — counterpart's address to dial |
| `HolePunchResult` | `hole_punch_result` | Client → Relay | `peer_id: String`, `success: bool` | Outcome of coordinated hole punch attempt |

#### Error

| Variant | Wire Type | Direction | Fields | Summary |
|---|---|---|---|---|
| `Error` | `error` | Relay → Client | `code: u32`, `message: String` | Error notification from relay |

### RelayPeerInfo

Peer record carried in [`Peers`](message.rs) / [`PeerConnected`](message.rs):

```rust
pub struct RelayPeerInfo {
    pub peer_id: String,              // stable identity, hex-encoded (SHA-256(TLS SPKI DER))
    pub network_id: String,           // network peer registered under (e.g. "DIG_MAINNET")
    pub protocol_version: u32,        // relay protocol version advertised
    pub connected_at: u64,            // unix time (seconds) peer first connected
    pub last_seen: u64,               // unix time (seconds) relay last saw activity
}
```

### Wire Characteristics

- **Transport:** JSON over WebSocket
- **Serialization:** `serde` with `#[serde(tag = "type")]` on `RelayMessage`
- **Peer Identity:** hex-encoded SHA-256 TLS SPKI DER (`peer_id`)
- **Network ID:** freeform string (e.g., `"DIG_MAINNET"`) — node can register under multiple networks
- **Payload Encoding:** `Vec<u8>` (opaque bytes); [`RelayGossipMessage`](message.rs) payloads are **end-to-end encrypted** (SPEC § NC-1)
- **Message Ordering:** `seq` field on [`RelayGossipMessage`](message.rs) for ordering/dedup (monotonic per sender)
- **Timestamps:** UNIX seconds (saturate to `0` before epoch)
- **Socket Addresses:** `std::net::SocketAddr` (IPv4 or IPv6)

### Security Contracts (from SPEC)

- **NC-1 (end-to-end sealed payloads):** Directed [`RelayGossipMessage`](message.rs) payloads are sealed to recipient's identity key; relay forwards ciphertext and cannot read.
- **NC-4 (content-agnostic routing):** Relay routes on envelope (`from`/`to`/`network_id`), never on payload contents.

### Scope

**Node↔relay only.** Relay↔relay (mesh) framing does **not** exist yet and is tracked separately (dig_ecosystem #873).

## License

Apache-2.0 OR MIT.
