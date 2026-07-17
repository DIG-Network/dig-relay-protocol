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

## License

Apache-2.0 OR MIT.
