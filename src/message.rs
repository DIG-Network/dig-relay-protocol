//! The node↔relay message set (`RelayMessage`) and the peer record it carries (`RelayPeerInfo`).
//!
//! These types are the wire itself. They are byte-identical to the definitions previously vendored
//! in `dig-gossip::relay::relay_types`, `dig-relay::wire`, and consumed by `dig-nat::relay` — same
//! variant set, same `#[serde(rename = ...)]` `type` discriminators, same field names in the same
//! order, same serialization (JSON via serde). See the crate root and `SPEC.md` for the normative
//! contract; the golden fixtures in `tests/kat.rs` pin the exact bytes.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// The complete NODE-TO-RELAY protocol message set (RLY-001 … RLY-007).
///
/// Serialized as JSON over a WebSocket. `#[serde(tag = "type")]` places each variant's
/// `#[serde(rename = "...")]` string in a leading `type` field, e.g. `{"type":"register", ...}`.
///
/// The variants group by requirement:
/// - **RLY-001** registration lifecycle — [`Register`](RelayMessage::Register) /
///   [`RegisterAck`](RelayMessage::RegisterAck) / [`Unregister`](RelayMessage::Unregister);
/// - **RLY-002** targeted forward — [`RelayGossipMessage`](RelayMessage::RelayGossipMessage);
/// - **RLY-003** broadcast fan-out — [`Broadcast`](RelayMessage::Broadcast);
/// - peer notifications — [`PeerConnected`](RelayMessage::PeerConnected) /
///   [`PeerDisconnected`](RelayMessage::PeerDisconnected);
/// - **RLY-005** peer discovery — [`GetPeers`](RelayMessage::GetPeers) /
///   [`Peers`](RelayMessage::Peers);
/// - **RLY-006** keepalive — [`Ping`](RelayMessage::Ping) / [`Pong`](RelayMessage::Pong);
/// - **RLY-007** NAT traversal — [`HolePunchRequest`](RelayMessage::HolePunchRequest) /
///   [`HolePunchCoordinate`](RelayMessage::HolePunchCoordinate) /
///   [`HolePunchResult`](RelayMessage::HolePunchResult);
/// - error — [`Error`](RelayMessage::Error).
///
/// Relay↔relay (mesh) frames are intentionally NOT part of this enum — they do not exist yet and are
/// tracked separately (dig_ecosystem #873).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    // -- RLY-001: Registration --
    /// Client → Relay: register after the WebSocket connects, so the relay holds a reservation for
    /// this node under `network_id` at `protocol_version`.
    #[serde(rename = "register")]
    Register {
        /// The node's stable identity, hex-encoded (`peer_id = SHA-256(TLS SPKI DER)`).
        peer_id: String,
        /// The network the node registers under (e.g. `DIG_MAINNET`).
        network_id: String,
        /// The relay protocol version the node advertises.
        protocol_version: u32,
    },

    /// Relay → Client: acknowledgement of a [`Register`](RelayMessage::Register).
    #[serde(rename = "register_ack")]
    RegisterAck {
        /// Whether the registration was accepted.
        success: bool,
        /// Human-readable status/rejection reason.
        message: String,
        /// How many peers the relay currently has connected.
        connected_peers: usize,
    },

    /// Client → Relay: graceful disconnect, releasing the reservation.
    #[serde(rename = "unregister")]
    Unregister {
        /// The node's `peer_id` (hex) being unregistered.
        peer_id: String,
    },

    // -- RLY-002: Targeted message forwarding --
    /// Client → Relay → Client: relayed (last-resort) transport — forward `payload` to peer `to`.
    #[serde(rename = "relay_message")]
    RelayGossipMessage {
        /// Sender `peer_id` (hex).
        from: String,
        /// Recipient `peer_id` (hex).
        to: String,
        /// Opaque forwarded bytes. Per NC-1 this payload is END-TO-END SEALED to the recipient's
        /// key: the relay forwards ciphertext and cannot read it (see `SPEC.md` § NC-1).
        payload: Vec<u8>,
        /// Monotonic per-sender sequence number for ordering/dedup.
        seq: u64,
    },

    // -- RLY-003: Broadcast --
    /// Client → Relay → All: fan-out `payload` to every registered peer except those in `exclude`.
    #[serde(rename = "broadcast")]
    Broadcast {
        /// Sender `peer_id` (hex).
        from: String,
        /// Opaque broadcast bytes.
        payload: Vec<u8>,
        /// `peer_id`s (hex) to omit from the fan-out.
        exclude: Vec<String>,
    },

    // -- Peer notifications --
    /// Relay → Client: a new peer connected to the relay.
    #[serde(rename = "peer_connected")]
    PeerConnected {
        /// The peer that just connected.
        peer: RelayPeerInfo,
    },

    /// Relay → Client: a peer disconnected from the relay.
    #[serde(rename = "peer_disconnected")]
    PeerDisconnected {
        /// The `peer_id` (hex) that left.
        peer_id: String,
    },

    // -- RLY-005: Peer list --
    /// Client → Relay: request the connected-peer list, optionally filtered to one `network_id`.
    #[serde(rename = "get_peers")]
    GetPeers {
        /// Restrict the response to this network, or `None` for all networks.
        network_id: Option<String>,
    },

    /// Relay → Client: the peer-list response to a [`GetPeers`](RelayMessage::GetPeers).
    #[serde(rename = "peers")]
    Peers {
        /// The peers currently registered with the relay.
        peers: Vec<RelayPeerInfo>,
    },

    // -- RLY-006: Keepalive --
    /// Bidirectional keepalive request.
    #[serde(rename = "ping")]
    Ping {
        /// Sender unix timestamp (seconds), echoed back in the matching [`Pong`](RelayMessage::Pong).
        timestamp: u64,
    },

    /// Keepalive response, echoing the [`Ping`](RelayMessage::Ping) `timestamp`.
    #[serde(rename = "pong")]
    Pong {
        /// The timestamp echoed from the originating ping.
        timestamp: u64,
    },

    // -- RLY-007: NAT traversal --
    /// Client → Relay: ask the relay to coordinate a hole punch toward `target_peer_id`.
    #[serde(rename = "hole_punch_request")]
    HolePunchRequest {
        /// The requesting node's `peer_id` (hex).
        peer_id: String,
        /// The peer to punch toward, `peer_id` (hex).
        target_peer_id: String,
        /// The requester's externally-observed socket address.
        external_addr: SocketAddr,
    },

    /// Relay → Client: hole-punch coordination — the counterpart's external address to dial.
    #[serde(rename = "hole_punch_coordinate")]
    HolePunchCoordinate {
        /// The counterpart peer's `peer_id` (hex).
        peer_id: String,
        /// The counterpart's external socket address to dial simultaneously.
        external_addr: SocketAddr,
    },

    /// Client → Relay: the outcome of a coordinated hole punch.
    #[serde(rename = "hole_punch_result")]
    HolePunchResult {
        /// The counterpart peer's `peer_id` (hex).
        peer_id: String,
        /// Whether a direct connection was established.
        success: bool,
    },

    // -- Error --
    /// Relay → Client: an error notification.
    #[serde(rename = "error")]
    Error {
        /// Machine-readable error code.
        code: u32,
        /// Human-readable error detail.
        message: String,
    },
}

/// A peer as tracked by the relay server, carried in
/// [`Peers`](RelayMessage::Peers)/[`PeerConnected`](RelayMessage::PeerConnected).
///
/// SPEC §2.9 — `RelayPeerInfo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayPeerInfo {
    /// The peer's stable identity, hex-encoded (`peer_id = SHA-256(TLS SPKI DER)`).
    pub peer_id: String,
    /// The network the peer registered under.
    pub network_id: String,
    /// The relay protocol version the peer advertised.
    pub protocol_version: u32,
    /// Unix time (seconds) the peer first connected to the relay.
    pub connected_at: u64,
    /// Unix time (seconds) the relay last saw activity from the peer.
    pub last_seen: u64,
}

impl RelayPeerInfo {
    /// Build a `RelayPeerInfo` stamped with the current unix time for `connected_at`/`last_seen`.
    ///
    /// Matches the vendored constructors in dig-gossip (`RelayPeerInfo::new`) and dig-relay.
    pub fn new(peer_id: String, network_id: String, protocol_version: u32) -> Self {
        let now = now_unix_secs();
        Self {
            peer_id,
            network_id,
            protocol_version,
            connected_at: now,
            last_seen: now,
        }
    }
}

/// Current unix time in seconds, saturating to `0` before the epoch. Mirrors dig-gossip's
/// `types::peer::metric_unix_timestamp_secs` and dig-relay's `unix_secs`.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
