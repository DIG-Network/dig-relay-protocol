//! The relay↔relay **mesh** frame set ([`MeshMessage`], band `0x0900`).
//!
//! These frames let relays coordinate among themselves — mutual handshake, relay-PEX, forwarding a
//! node↔node payload across the mesh, keepalive, and reservation handoff/switch. Every mesh frame is
//! **recipient-sealed to the peer relay's BLS G1 key** (SPEC §9): a `MeshMessage` is the JSON
//! `payload` of a `dig-message` envelope whose `message_type` is drawn from [`crate::ids::mesh`], sent
//! as a [`crate::RelayMessage::Sealed`]. A frame misdelivered to the wrong relay decaps to the wrong
//! key and is discarded.
//!
//! This crate defines the WIRE only. The decentralized-relay NETWORK that drives these frames
//! (on-chain relay discovery, relay-PEX routing, relay-switch policy) is epic dig_ecosystem #873,
//! which CONSUMES this wire.

use serde::{Deserialize, Serialize};

use crate::descriptor::RelayDescriptor;

/// The complete relay↔relay mesh frame set. Serialized as JSON with a leading `type` discriminator
/// (`#[serde(tag = "type")]`), then sealed inside a `dig-message` band-`0x0900` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MeshMessage {
    /// Mutual-handshake opener: the dialing relay advertises its own descriptor to the peer relay.
    #[serde(rename = "mesh_hello")]
    MeshHello {
        /// The sender relay's signed descriptor (authenticates its BLS G1 key + reachability). Boxed
        /// to keep the enum's other variants cheap to move (serde-transparent, no wire change).
        descriptor: Box<RelayDescriptor>,
    },

    /// Handshake response: the responding relay advertises its descriptor, completing mutual auth.
    #[serde(rename = "mesh_hello_ack")]
    MeshHelloAck {
        /// The responder relay's signed descriptor (boxed; serde-transparent).
        descriptor: Box<RelayDescriptor>,
    },

    /// Relay peer-exchange: share known peer-relay descriptors (frame only; routing is #873).
    #[serde(rename = "mesh_peer_exchange")]
    MeshPeerExchange {
        /// Known peer-relay descriptors the sender is gossiping.
        relays: Vec<RelayDescriptor>,
    },

    /// Forward a node↔node payload between relays on behalf of a reserved node.
    ///
    /// The `payload` is **doubly opaque**: it is already end-to-end sealed node↔node (NC-1), and this
    /// whole frame is then sealed relay↔relay — so no relay on the path can read it.
    #[serde(rename = "mesh_forward")]
    MeshForward {
        /// The originating node's `peer_id` (hex).
        origin_peer_id: String,
        /// The destination node's `peer_id` (hex).
        dest_peer_id: String,
        /// The doubly-opaque node↔node-sealed payload bytes.
        payload: Vec<u8>,
        /// Monotonic per-origin sequence number for ordering/dedup across the mesh.
        seq: u64,
    },

    /// Inter-relay liveness keepalive.
    #[serde(rename = "mesh_keepalive")]
    MeshKeepalive {
        /// Sender unix milliseconds, echoed by the peer's next keepalive.
        timestamp_ms: u64,
    },

    /// Reservation handoff: ask the peer relay to take over a node's reservation (load-shed).
    #[serde(rename = "mesh_handoff")]
    MeshHandoff {
        /// The `peer_id` (hex) of the node whose reservation is being handed off.
        peer_id: String,
        /// The network the node is registered under.
        network_id: String,
    },

    /// Reservation switch: confirm/instruct that a node's reservation now lives on the target relay.
    #[serde(rename = "mesh_switch")]
    MeshSwitch {
        /// The `peer_id` (hex) of the node whose reservation switched.
        peer_id: String,
        /// The `relay_did` (hex) of the relay now holding the reservation.
        target_relay_did: String,
        /// Whether the switch was accepted by the target relay.
        accepted: bool,
    },

    /// Inter-relay error notification.
    #[serde(rename = "mesh_error")]
    MeshError {
        /// Machine-readable error code.
        code: u32,
        /// Human-readable error detail.
        message: String,
    },
}
