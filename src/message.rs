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

use crate::descriptor::RelayDescriptor;

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
/// ## v2 additions (additive, §5.1 back-compat)
///
/// - **[`RelayHello`](RelayMessage::RelayHello)** — the relay's signed [`RelayDescriptor`], sent
///   FIRST so a node authenticates the relay's BLS G1 key before sealing its `register` (SPEC §8);
/// - **[`Sealed`](RelayMessage::Sealed)** — a single transport envelope carrying a `dig-message`
///   recipient-sealed frame (band `0x0800` control or `0x0900` mesh). Existing v1 variants are
///   byte-identical; a v1 peer simply never emits these two `type`s.
///
/// The relay↔relay mesh frame set ([`crate::MeshMessage`]) travels sealed INSIDE a
/// [`Sealed`](RelayMessage::Sealed) envelope; it is not a top-level `RelayMessage` variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        /// The node's advertised gossip LISTEN candidate address(es), IPv6-first (§5.2).
        ///
        /// The relay uses each candidate's PORT together with the node's observed reflexive IP to
        /// build a dialable [`RelayPeerInfo::addresses`] entry it hands to other peers, enabling the
        /// connect-leg direct-dial path (dig_ecosystem #924, B1). The host is usually the unspecified
        /// dual-stack address (`[::]`); the useful part the relay keeps is the port.
        ///
        /// Additive since protocol v1 (NC-6 soft-fork): pre-#924 peers omit it, so it defaults to
        /// empty and is skipped from serialization when empty — keeping the wire byte-identical for
        /// existing peers, which fall back to today's identity-only relayed reachability.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        listen_addrs: Vec<SocketAddr>,
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

    // -- v2: recipient-sealed handshake + transport (additive since v1) --
    /// Relay → Client: the relay's signed identity record, sent FIRST on a v2 session so the node can
    /// authenticate the relay's BLS G1 key against the live mTLS SPKI, THEN seal its `register` to it
    /// (SPEC §8). Plaintext on the wire but BLS-G2-signed — it carries no secret, it authenticates.
    #[serde(rename = "relay_hello")]
    RelayHello {
        /// The relay's self-describing, signed [`RelayDescriptor`] (boxed — it is the largest field,
        /// so boxing keeps every other `RelayMessage` variant cheap to move; serde-transparent).
        descriptor: Box<RelayDescriptor>,
    },

    /// ↔: a recipient-sealed frame. `envelope` is an encoded `dig-message` `DigMessageEnvelope` whose
    /// `message_type` is a band-`0x0800` (sealed control) or band-`0x0900` (mesh) id. The receiver
    /// opens it with its BLS G1 secret key (see [`crate::seal`]); a frame sealed to a different relay
    /// decaps to the wrong key and is discarded. Envelope metadata (sender/recipient DID) is the only
    /// routable plaintext — the frame body is ciphertext (NC-1).
    #[serde(rename = "sealed")]
    Sealed {
        /// The encoded `dig-message` sealed envelope bytes.
        envelope: Vec<u8>,
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
    /// The relay-resolved dialable candidate address(es) for this peer, IPv6-first (§5.2).
    ///
    /// The relay computes these from the peer's advertised [`RelayMessage::Register`]`::listen_addrs`
    /// by substituting the peer's observed reflexive IP for any unspecified/loopback/private
    /// advertised host (keeping the advertised port), so each entry is a real `reflexive_IP:port`
    /// another node can direct-dial over the existing mTLS path (dig_ecosystem #924, B1).
    ///
    /// Additive since protocol v1 (NC-6 soft-fork): pre-#924 relays omit it, so it defaults to empty
    /// and is skipped from serialization when empty — keeping the wire byte-identical for existing
    /// relays, whose peers fall back to today's identity-only relayed reachability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<SocketAddr>,
}

impl RelayPeerInfo {
    /// Build a `RelayPeerInfo` stamped with the current unix time for `connected_at`/`last_seen` and
    /// no resolved dialable addresses (the relay populates [`addresses`](RelayPeerInfo::addresses)
    /// when it has an observed reflexive IP for the peer).
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
            addresses: Vec::new(),
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
