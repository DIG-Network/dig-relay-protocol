//! Recipient-seal machinery for the v2 relay wire (feature `seal`).
//!
//! This module turns the plaintext frame types into **recipient-sealed** [`RelayMessage::Sealed`]
//! envelopes and back, using `dig-message`'s shipped G1-DHKEM seal over a relay/node **BLS G1
//! identity key** (`dig-identity`, slot `0x0010`, path `m/12381'/8444'/9'/0'`). A relay is a node
//! with a relay role — the SAME identity model.
//!
//! What sealing buys (all provided by `dig-message` `open_message`): a frame sealed to relay A cannot
//! be opened by relay B (wrong key → AEAD-open fails → discard), plus mandatory sender-signature
//! verification, anti-replay, expiry, and G1 subgroup checks — for free.
//!
//! ## What is and is NOT sealed (SPEC §5)
//!
//! Sealed control (band `0x0800`): `register`, `register_ack`, `unregister`, `hole_punch_request`,
//! `hole_punch_coordinate`, `hole_punch_result`. Sealed mesh (band `0x0900`): all [`MeshMessage`]
//! frames. NOT sealed here (the relay must route/read, or the payload is already sealed a layer down):
//! `relay_message` (RLY-002 — inner payload is already node↔node-sealed), `broadcast` (§5.4 public
//! carve-out), `get_peers`/`peers`/`peer_connected`/`peer_disconnected` (semi-public discovery),
//! `ping`/`pong`/`error` (plaintext). `relay_hello` is plaintext-but-signed (SPEC §8).

use dig_identity::bls::{
    derive_identity_sk, master_secret_key_from_seed, public_key_bytes, sign_message, SecretKey,
};
use dig_message::{
    decode_envelope, encode_envelope, open_message, seal_message, InteractionShape, MessageError,
    SealParams,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::descriptor::RelayDescriptor;
use crate::ids::{self, control, mesh};
use crate::mesh::MeshMessage;
use crate::message::RelayMessage;

// Re-export the two upstream types a consumer needs to CALL these helpers, so it can seal/open without
// depending on dig-identity / dig-message directly.
pub use dig_identity::Bytes32;
pub use dig_message::ReplayGuard;

/// Anything that can go wrong sealing or opening a relay frame. Every open-side error is fail-closed:
/// the frame is discarded, never partially trusted.
#[derive(Debug)]
pub enum SealError {
    /// A `dig-message` seal/open failure (wrong key, bad signature, replay, expiry, bad point, …).
    Message(MessageError),
    /// The sealed inner payload failed to (de)serialize as JSON.
    Codec(String),
    /// [`open_control`]/[`open_mesh`] was handed a [`RelayMessage`] that is not a `Sealed` variant.
    NotSealed,
    /// Tried to seal a frame that MUST stay plaintext on the wire (§5) — a caller bug.
    NotSealable,
    /// The opened envelope's `message_type` is not in the band the opener expects (control vs mesh),
    /// or is not an allocated relay id.
    WrongBand {
        /// The offending `message_type`.
        message_type: u32,
    },
    /// A required-seal session negotiated against a peer that cannot seal (downgrade refused, §7).
    DowngradeRefused,
}

impl From<MessageError> for SealError {
    fn from(e: MessageError) -> Self {
        SealError::Message(e)
    }
}

/// The relay/node's sealing identity: its BLS G1 key plus the DID it is addressed by.
///
/// `did` is the on-chain DID (the seal recipient/routing id); `secret_key` is the slot-`0x0010`
/// BLS G1 identity key. The DID↔key binding is anchored on chain (verified via the descriptor +
/// [`RelayDescriptor::verify_did_binding`]); this type just pairs them for local sealing.
pub struct RelayIdentity {
    did: Bytes32,
    secret_key: SecretKey,
    g1_pub: [u8; 48],
}

impl RelayIdentity {
    /// Build an identity from a wallet `seed`, deriving the slot-`0x0010` identity key exactly as
    /// `dig-identity` does (`master → derive_identity_sk`). `did` is the relay/node's on-chain DID.
    #[must_use]
    pub fn from_master_seed(did: Bytes32, seed: &[u8]) -> Self {
        let secret_key = derive_identity_sk(&master_secret_key_from_seed(seed));
        Self::from_secret_key(did, secret_key)
    }

    /// Build an identity from an already-derived slot-`0x0010` BLS G1 secret key.
    #[must_use]
    pub fn from_secret_key(did: Bytes32, secret_key: SecretKey) -> Self {
        let g1_pub = public_key_bytes(&secret_key);
        Self {
            did,
            secret_key,
            g1_pub,
        }
    }

    /// This identity's DID (seal recipient id).
    #[must_use]
    pub fn did(&self) -> Bytes32 {
        self.did
    }

    /// This identity's 48-byte compressed BLS G1 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 48] {
        self.g1_pub
    }

    /// Build and BLS-G2-sign a [`RelayDescriptor`] advertising this identity (SPEC §8). The caller
    /// supplies the transport binding (`peer_id_spki_hash = SHA-256(TLS SPKI DER)`) and reachability.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_descriptor(
        &self,
        peer_id_spki_hash: [u8; 32],
        network_id: String,
        capabilities: Vec<String>,
        addresses: Vec<std::net::SocketAddr>,
        protocol_version: u32,
        timestamp_ms: u64,
        expires_at: u64,
    ) -> RelayDescriptor {
        let mut relay_did = [0u8; 32];
        relay_did.copy_from_slice(self.did.as_ref());
        let mut descriptor = RelayDescriptor {
            relay_did,
            bls_g1_pub: self.g1_pub,
            peer_id_spki_hash,
            network_id,
            capabilities,
            addresses,
            protocol_version,
            timestamp_ms,
            expires_at,
            sig: [0u8; 96],
        };
        descriptor.sig = sign_message(&self.secret_key, &descriptor.signing_bytes());
        descriptor
    }
}

/// Per-message sealing context — the correlation id + monotonic counter + freshness/expiry window
/// threaded into every `dig-message` envelope (SPEC §5.6 anti-replay).
pub struct SealContext {
    /// Correlates a request with its response (or a fresh random id for one-shots).
    pub correlation_id: Bytes32,
    /// Strictly-increasing per-sender counter (the anti-replay sequence).
    pub counter: u64,
    /// Send time, unix milliseconds.
    pub timestamp_ms: u64,
    /// Expiry, unix milliseconds (0 = the receiver's default freshness window applies).
    pub expires_at: u64,
}

/// The `message_type` id for a sealable control [`RelayMessage`], or `None` if the variant MUST stay
/// plaintext on the wire (§5). This is the authoritative "what gets sealed" table.
#[must_use]
pub fn control_message_type(msg: &RelayMessage) -> Option<u32> {
    match msg {
        RelayMessage::Register { .. } => Some(control::REGISTER),
        RelayMessage::RegisterAck { .. } => Some(control::REGISTER_ACK),
        RelayMessage::Unregister { .. } => Some(control::UNREGISTER),
        RelayMessage::HolePunchRequest { .. } => Some(control::HOLE_PUNCH_REQUEST),
        RelayMessage::HolePunchCoordinate { .. } => Some(control::HOLE_PUNCH_COORDINATE),
        RelayMessage::HolePunchResult { .. } => Some(control::HOLE_PUNCH_RESULT),
        _ => None,
    }
}

/// The `message_type` id for a relay↔relay mesh frame (total — every [`MeshMessage`] is sealed).
#[must_use]
pub fn mesh_message_type(frame: &MeshMessage) -> u32 {
    match frame {
        MeshMessage::MeshHello { .. } => mesh::HELLO,
        MeshMessage::MeshHelloAck { .. } => mesh::HELLO_ACK,
        MeshMessage::MeshPeerExchange { .. } => mesh::PEER_EXCHANGE,
        MeshMessage::MeshForward { .. } => mesh::FORWARD,
        MeshMessage::MeshKeepalive { .. } => mesh::KEEPALIVE,
        MeshMessage::MeshHandoff { .. } => mesh::HANDOFF,
        MeshMessage::MeshSwitch { .. } => mesh::SWITCH,
        MeshMessage::MeshError { .. } => mesh::ERROR,
    }
}

/// Seal a control [`RelayMessage`] to a recipient's BLS G1 key, yielding a [`RelayMessage::Sealed`]
/// ready to serialize onto the wire. C→R frames pass the relay's key/DID; R→C frames pass the node's.
///
/// # Errors
/// [`SealError::NotSealable`] if `msg` is a plaintext-only variant; [`SealError::Codec`] on JSON
/// failure; [`SealError::Message`] on a seal failure.
pub fn seal_control(
    sender: &RelayIdentity,
    recipient_did: Bytes32,
    recipient_pub: &[u8; 48],
    msg: &RelayMessage,
    ctx: &SealContext,
) -> Result<RelayMessage, SealError> {
    let message_type = control_message_type(msg).ok_or(SealError::NotSealable)?;
    seal_value(sender, recipient_did, recipient_pub, message_type, msg, ctx)
}

/// Seal a relay↔relay [`MeshMessage`] to the peer relay's BLS G1 key (band `0x0900`).
///
/// # Errors
/// [`SealError::Codec`] on JSON failure; [`SealError::Message`] on a seal failure.
pub fn seal_mesh(
    sender: &RelayIdentity,
    recipient_did: Bytes32,
    recipient_pub: &[u8; 48],
    frame: &MeshMessage,
    ctx: &SealContext,
) -> Result<RelayMessage, SealError> {
    let message_type = mesh_message_type(frame);
    seal_value(
        sender,
        recipient_did,
        recipient_pub,
        message_type,
        frame,
        ctx,
    )
}

/// The shared seal path: JSON-encode `value`, seal it to `recipient_pub` under `message_type`, and
/// wrap the encoded envelope in [`RelayMessage::Sealed`].
fn seal_value<T: Serialize>(
    sender: &RelayIdentity,
    recipient_did: Bytes32,
    recipient_pub: &[u8; 48],
    message_type: u32,
    value: &T,
    ctx: &SealContext,
) -> Result<RelayMessage, SealError> {
    let payload = serde_json::to_vec(value).map_err(|e| SealError::Codec(e.to_string()))?;
    let envelope = seal_message(&SealParams {
        sender_sk: &sender.secret_key,
        sender: sender.did,
        sender_epoch: 0,
        recipient: recipient_did,
        recipient_pub,
        message_type,
        shape: InteractionShape::OneShot,
        correlation_id: ctx.correlation_id,
        stream: None,
        counter: ctx.counter,
        timestamp_ms: ctx.timestamp_ms,
        expires_at: ctx.expires_at,
        payload: &payload,
    })?;
    let bytes = encode_envelope(&envelope).map_err(SealError::Message)?;
    Ok(RelayMessage::Sealed { envelope: bytes })
}

#[derive(Debug)]
/// A control frame recovered from a [`RelayMessage::Sealed`].
pub struct OpenedControl {
    /// The band-`0x0800` `message_type` the frame was sealed under.
    pub message_type: u32,
    /// The recovered control message.
    pub message: RelayMessage,
}

#[derive(Debug)]
/// A mesh frame recovered from a [`RelayMessage::Sealed`].
pub struct OpenedMesh {
    /// The band-`0x0900` `message_type` the frame was sealed under.
    pub message_type: u32,
    /// The recovered mesh frame.
    pub frame: MeshMessage,
}

/// Open + verify a sealed **control** frame (band `0x0800`) addressed to `recipient`.
///
/// `resolve_sender_pub` maps a sender `(DID, epoch)` to its 48-byte BLS G1 key (wire a `dig-identity`
/// chain resolution here). All of sender-signature, anti-replay, expiry, and subgroup checks are
/// enforced by `dig-message`; this adds the band check + JSON decode.
///
/// # Errors
/// [`SealError::NotSealed`] if `sealed` is not a `Sealed` variant; [`SealError::WrongBand`] if the
/// opened `message_type` is not band `0x0800`; [`SealError::Message`]/[`SealError::Codec`] otherwise.
pub fn open_control(
    recipient: &RelayIdentity,
    sealed: &RelayMessage,
    resolve_sender_pub: impl Fn(Bytes32, u32) -> Option<[u8; 48]>,
    guard: &mut ReplayGuard,
    now_ms: u64,
) -> Result<OpenedControl, SealError> {
    let (message_type, message) = open_value(
        recipient,
        sealed,
        ids::BAND_RELAY_CONTROL,
        resolve_sender_pub,
        guard,
        now_ms,
    )?;
    Ok(OpenedControl {
        message_type,
        message,
    })
}

/// Open + verify a sealed **mesh** frame (band `0x0900`) addressed to `recipient`. See
/// [`open_control`] for the checks performed.
///
/// # Errors
/// [`SealError::NotSealed`], [`SealError::WrongBand`] (not band `0x0900`),
/// [`SealError::Message`]/[`SealError::Codec`].
pub fn open_mesh(
    recipient: &RelayIdentity,
    sealed: &RelayMessage,
    resolve_sender_pub: impl Fn(Bytes32, u32) -> Option<[u8; 48]>,
    guard: &mut ReplayGuard,
    now_ms: u64,
) -> Result<OpenedMesh, SealError> {
    let (message_type, frame) = open_value(
        recipient,
        sealed,
        ids::BAND_RELAY_MESH,
        resolve_sender_pub,
        guard,
        now_ms,
    )?;
    Ok(OpenedMesh {
        message_type,
        frame,
    })
}

/// The shared open path: unwrap the `Sealed` envelope, `open_message` it, verify the frame's band is
/// `expected_band` (BEFORE decoding, so a cross-band frame is a clean [`SealError::WrongBand`], never a
/// misleading decode error), then JSON-decode the payload.
fn open_value<T: DeserializeOwned>(
    recipient: &RelayIdentity,
    sealed: &RelayMessage,
    expected_band: u32,
    resolve_sender_pub: impl Fn(Bytes32, u32) -> Option<[u8; 48]>,
    guard: &mut ReplayGuard,
    now_ms: u64,
) -> Result<(u32, T), SealError> {
    let RelayMessage::Sealed { envelope } = sealed else {
        return Err(SealError::NotSealed);
    };
    let envelope = decode_envelope(envelope).map_err(SealError::Message)?;
    let opened = open_message(
        &recipient.secret_key,
        &envelope,
        resolve_sender_pub,
        guard,
        now_ms,
    )?;
    if band_base(opened.message_type) != expected_band {
        return Err(SealError::WrongBand {
            message_type: opened.message_type,
        });
    }
    let value =
        serde_json::from_slice(&opened.payload).map_err(|e| SealError::Codec(e.to_string()))?;
    Ok((opened.message_type, value))
}

/// The band base of a `message_type` (its high 24 bits with the low byte cleared), e.g.
/// `0x0800_0003 → 0x0000_0800`.
fn band_base(message_type: u32) -> u32 {
    message_type & 0xFFFF_FF00
}

/// A node/relay's local policy on whether a session MUST be sealed (SPEC §7 downgrade rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealMode {
    /// Refuse any session that cannot recipient-seal control (fail-closed).
    Required,
    /// Prefer sealing; fall back to v1 plaintext control against a v1 peer.
    Optional,
}

/// The negotiated outcome of a v2 handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    /// Whether control frames will be recipient-sealed on this session.
    pub sealed: bool,
}

/// Negotiate the session's seal policy against a peer's advertised capability (SPEC §7).
///
/// A session seals iff the peer speaks ≥ v2 AND advertises seal support. Under [`SealMode::Required`]
/// a peer that cannot seal is REFUSED (fail-closed) — a downgrade attacker cannot strip sealing.
///
/// # Errors
/// [`SealError::DowngradeRefused`] when `local` is [`SealMode::Required`] but the peer cannot seal.
pub fn negotiate_session(
    local: SealMode,
    peer_protocol_version: u32,
    peer_supports_seal: bool,
) -> Result<Negotiated, SealError> {
    let sealed = peer_protocol_version >= crate::PROTOCOL_VERSION_V2 && peer_supports_seal;
    if local == SealMode::Required && !sealed {
        return Err(SealError::DowngradeRefused);
    }
    Ok(Negotiated { sealed })
}
