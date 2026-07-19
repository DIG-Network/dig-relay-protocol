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
//! The crate owns the WHOLE relay boundary contract: **node↔relay** (RLY-001..007 + the v2
//! recipient-sealed control frames) AND **relay↔relay** ([`MeshMessage`], the mesh wire). The larger
//! decentralized-relay NETWORK (on-chain relay discovery, relay-PEX routing, relay-switch policy) is
//! epic dig_ecosystem #873, which CONSUMES this wire.
//!
//! ## v2 — recipient-sealed frames (feature `seal`)
//!
//! v2 adds recipient binding: a relay has a **BLS G1 identity key** (`dig-identity`, slot `0x0010`),
//! advertises a signed [`RelayDescriptor`] in [`RelayMessage::RelayHello`], and every directed
//! control/mesh frame is sealed to the recipient's key via `dig-message` (carried in
//! [`RelayMessage::Sealed`]). A frame for relay A cannot be opened by relay B. The default build is
//! the pure-wire types (serde only); enable `seal` for the [`seal`] helpers + descriptor verification.
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
//!     listen_addrs: vec![], // additive since v1 — empty is omitted from the wire (NC-6 soft-fork)
//! };
//! let json = serde_json::to_string(&register).unwrap();
//! assert_eq!(
//!     json,
//!     r#"{"type":"register","peer_id":"deadbeef","network_id":"DIG_MAINNET","protocol_version":1}"#
//! );
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod descriptor;
pub mod ids;
mod mesh;
mod message;
#[cfg(feature = "seal")]
pub mod seal;

pub use descriptor::RelayDescriptor;
pub use mesh::MeshMessage;
pub use message::{RelayMessage, RelayPeerInfo};

/// The v1 relay protocol version (plaintext RLY-001..007; no recipient sealing).
pub const PROTOCOL_VERSION_V1: u32 = 1;

/// The v2 relay protocol version (adds the BLS relay identity + recipient-sealed control/mesh frames).
/// Advertised in the signed handshake/`register`; a v2↔v1 peer falls back to plaintext control unless
/// the v2 side runs in [`seal::SealMode::Required`] (SPEC §7).
pub const PROTOCOL_VERSION_V2: u32 = 2;
