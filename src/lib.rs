//! # dig-relay-protocol
//!
//! The canonical **NODE-TO-RELAY** wire protocol for the DIG Network relay (`relay.dig.net`).
//!
//! A DIG Node behind NAT cannot accept inbound dials, so it holds a constant registered connection
//! with a publicly-reachable relay. That connection speaks the **RLY-001 … RLY-007** message set
//! defined here: registration + reservation, peer discovery, keepalive, relay-coordinated NAT hole
//! punching, and relayed last-resort transport. Messages are JSON over a WebSocket.
//!
//! ## Single source of truth
//!
//! This crate is the ONE definition of the node↔relay wire. It is extracted **byte-identical** from
//! the copies that were previously vendored across the ecosystem:
//!
//! - `dig-gossip` — `src/relay/relay_types.rs` (the authoritative shape + the relay CLIENT);
//! - `dig-relay` — `src/wire.rs` (the relay SERVER; a verbatim vendored copy);
//! - `dig-nat` — `src/relay.rs` (the persistent-reservation relay client).
//!
//! A consumer that replaces its vendored copy with this crate observes ZERO wire change (proven by
//! the golden fixtures in `tests/kat.rs`, which pin the exact serialized bytes).
//!
//! ## Scope
//!
//! **Node↔relay only.** Relay↔relay (mesh) framing does not exist yet and is tracked separately
//! (dig_ecosystem #873); it is NOT part of this crate.
//!
//! ## Security contracts
//!
//! - **NC-1 (end-to-end sealed payloads).** The relay authenticates the transport with mTLS AND
//!   every directed payload ([`RelayMessage::RelayGossipMessage`]) is sealed to the recipient's
//!   identity key on top of that channel — the relay forwards ciphertext and provably cannot read
//!   it. See `SPEC.md` § NC-1.
//! - **NC-4 (routing).** The relay routes purely on the envelope (`from`/`to`/`network_id`), never
//!   on payload contents. See `SPEC.md` § NC-4.
//!
//! ## Example
//!
//! ```
//! use dig_relay_protocol::RelayMessage;
//!
//! let register = RelayMessage::Register {
//!     peer_id: "deadbeef".into(),
//!     network_id: "DIG_MAINNET".into(),
//!     protocol_version: 1,
//! };
//! let json = serde_json::to_string(&register).unwrap();
//! assert_eq!(
//!     json,
//!     r#"{"type":"register","peer_id":"deadbeef","network_id":"DIG_MAINNET","protocol_version":1}"#
//! );
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod message;

pub use message::{RelayMessage, RelayPeerInfo};
