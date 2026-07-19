//! The `dig-message` **message-type id allocation** for the two relay bands.
//!
//! Every recipient-sealed relay frame travels inside a `dig-message` envelope whose `message_type`
//! selects the frame. The ids are drawn from two bands reserved for the relay boundary in
//! `dig-message` v0.5.0 (`registry::MessageBand`):
//!
//! - **`0x0800` — RelayControl** — the node↔relay sealed-control frames ([`control`]).
//! - **`0x0900` — RelayMesh** — the relay↔relay mesh frames ([`mesh`]).
//!
//! These are plain `u32` constants (no `seal` feature required to name them) so the band map is
//! documentable and testable everywhere; the [`crate::seal`] helpers use them when the feature is on.
//!
//! ## Band 0x0800 sub-allocation (anti-collision with the deferred retainer economy)
//!
//! The retainer economy (dig_ecosystem #1202) will allocate `RTN-001..005` in this SAME band. To let
//! it adopt its ids without a collision, the sealed relay-control frames here occupy only the
//! **`0x0800_00xx`** sub-range, leaving **`0x0800_01xx`** ([`RTN_RESERVED_BASE`]) free for #1202.

/// The `dig-message` band base for node↔relay sealed **control** frames (`RelayControl`, `0x0800`).
pub const BAND_RELAY_CONTROL: u32 = 0x0000_0800;

/// The `dig-message` band base for relay↔relay **mesh** frames (`RelayMesh`, `0x0900`).
pub const BAND_RELAY_MESH: u32 = 0x0000_0900;

/// Reserved sub-base inside band `0x0800` for the deferred retainer economy (dig_ecosystem #1202).
/// The sealed-control ids in [`control`] stay strictly below this so #1202's `RTN-*` ids never clash.
pub const RTN_RESERVED_BASE: u32 = 0x0000_0800 + 0x0100;

/// Node↔relay sealed-control message-type ids (band `0x0800`, sub-range `0x0800_00xx`).
///
/// Each corresponds to a [`crate::RelayMessage`] variant that MUST be recipient-sealed (§ SPEC NC-1):
/// the C→R set seals to the relay's BLS G1 key; the R→C set seals to the node's BLS G1 key.
pub mod control {
    use super::BAND_RELAY_CONTROL;

    /// `register` (C→R, sealed to the relay).
    pub const REGISTER: u32 = BAND_RELAY_CONTROL + 0x01;
    /// `register_ack` (R→C, sealed to the node).
    pub const REGISTER_ACK: u32 = BAND_RELAY_CONTROL + 0x02;
    /// `unregister` (C→R, sealed to the relay).
    pub const UNREGISTER: u32 = BAND_RELAY_CONTROL + 0x03;
    /// `hole_punch_request` (C→R, sealed to the relay).
    pub const HOLE_PUNCH_REQUEST: u32 = BAND_RELAY_CONTROL + 0x04;
    /// `hole_punch_coordinate` (R→C, sealed to the node).
    pub const HOLE_PUNCH_COORDINATE: u32 = BAND_RELAY_CONTROL + 0x05;
    /// `hole_punch_result` (C→R, sealed to the relay).
    pub const HOLE_PUNCH_RESULT: u32 = BAND_RELAY_CONTROL + 0x06;
}

/// Relay↔relay mesh message-type ids (band `0x0900`), all sealed to the peer relay's BLS G1 key.
pub mod mesh {
    use super::BAND_RELAY_MESH;

    /// `mesh_hello` — mutual handshake opener advertising the sender relay's descriptor.
    pub const HELLO: u32 = BAND_RELAY_MESH + 0x01;
    /// `mesh_hello_ack` — handshake response advertising the responder relay's descriptor.
    pub const HELLO_ACK: u32 = BAND_RELAY_MESH + 0x02;
    /// `mesh_peer_exchange` — relay-PEX frame (frame only; routing logic is dig_ecosystem #873).
    pub const PEER_EXCHANGE: u32 = BAND_RELAY_MESH + 0x03;
    /// `mesh_forward` — forward a node↔node payload between relays (payload stays doubly opaque).
    pub const FORWARD: u32 = BAND_RELAY_MESH + 0x04;
    /// `mesh_keepalive` — inter-relay liveness ping.
    pub const KEEPALIVE: u32 = BAND_RELAY_MESH + 0x05;
    /// `mesh_handoff` — reservation handoff (load-shed a node's reservation to a peer relay).
    pub const HANDOFF: u32 = BAND_RELAY_MESH + 0x06;
    /// `mesh_switch` — instruct/confirm a reservation switch to the handoff target.
    pub const SWITCH: u32 = BAND_RELAY_MESH + 0x07;
    /// `mesh_error` — inter-relay error notification.
    pub const ERROR: u32 = BAND_RELAY_MESH + 0xFF;
}
