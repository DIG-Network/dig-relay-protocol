//! The [`RelayDescriptor`] — a relay's self-describing, BLS-G2-signed identity record.
//!
//! A relay advertises its descriptor FIRST (in [`crate::RelayMessage::RelayHello`], plaintext but
//! signed) so a connecting node can authenticate the relay's BLS G1 identity key BEFORE sealing its
//! own `register` to it — solving the handshake chicken-and-egg (SPEC §8).
//!
//! ## Anti-substitution binding
//!
//! The descriptor binds three identities together under one signature:
//!
//! 1. **`relay_did`** — the relay's on-chain DID (the routing identity / seal recipient id);
//! 2. **`bls_g1_pub`** — the BLS12-381 G1 identity key the descriptor is signed with AND the key a
//!    node seals `register` TO;
//! 3. **`peer_id_spki_hash`** — `SHA-256(TLS SPKI DER)`, i.e. the relay's transport `peer_id`.
//!
//! [`RelayDescriptor::verify`] checks the signature over all fields (so none can be swapped) and that
//! the presented mTLS SPKI hashes to `peer_id_spki_hash` (so a relay cannot present another relay's
//! descriptor over its own TLS session). A consumer with chain access additionally resolves
//! `relay_did → bls_g1_pub` to close the DID↔key binding (see `verify_did_binding`).

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// The domain-separation prefix mixed into the descriptor's signing transcript, so a descriptor
/// signature can never be confused with any other BLS signature the relay's key produces.
pub const DESCRIPTOR_SIG_DOMAIN: &[u8] = b"DIGNET-RELAY-DESCRIPTOR:v2";

/// A relay's signed, self-describing identity + reachability record (SPEC §8).
///
/// Serialized as JSON; the 48/96-byte BLS fields render as JSON `u8` arrays (via `serde-big-array`,
/// which also enforces their exact length on decode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDescriptor {
    /// The relay's on-chain DID identifier (32 bytes) — the routing/seal-recipient identity.
    pub relay_did: [u8; 32],
    /// The relay's compressed BLS12-381 **G1** identity public key (48 bytes) — the descriptor
    /// signing key AND the key nodes seal `register` to (dig-identity slot `0x0010`).
    #[serde(with = "BigArray")]
    pub bls_g1_pub: [u8; 48],
    /// The relay's transport identity: `SHA-256(TLS SPKI DER)` (32 bytes) — bound so the descriptor
    /// cannot be replayed over a different TLS session (anti-substitution).
    pub peer_id_spki_hash: [u8; 32],
    /// The network the relay serves (e.g. `DIG_MAINNET`).
    pub network_id: String,
    /// Advertised relay capabilities (free-form tokens, e.g. `hole-punch`, `mesh`).
    pub capabilities: Vec<String>,
    /// Publicly-dialable relay addresses, IPv6-first (§5.2).
    pub addresses: Vec<SocketAddr>,
    /// The relay protocol version this relay speaks (v2 = recipient-sealed control; SPEC §7).
    pub protocol_version: u32,
    /// Unix milliseconds the descriptor was signed (freshness).
    pub timestamp_ms: u64,
    /// Unix milliseconds after which the descriptor MUST be treated as stale.
    pub expires_at: u64,
    /// The BLS G2 signature (96 bytes) over [`signing_bytes`](RelayDescriptor::signing_bytes),
    /// produced by the secret key matching `bls_g1_pub`.
    #[serde(with = "BigArray")]
    pub sig: [u8; 96],
}

impl RelayDescriptor {
    /// The canonical, deterministic byte transcript that [`sig`](RelayDescriptor::sig) covers.
    ///
    /// Every field EXCEPT the signature is length-prefixed and concatenated after the domain prefix,
    /// so no field can be altered or reordered without invalidating the signature. This is pure (no
    /// `seal` feature) so both signer and verifier — and tests — agree on the exact bytes.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(DESCRIPTOR_SIG_DOMAIN);
        b.extend_from_slice(&self.relay_did);
        b.extend_from_slice(&self.bls_g1_pub);
        b.extend_from_slice(&self.peer_id_spki_hash);
        push_field(&mut b, self.network_id.as_bytes());
        b.extend_from_slice(&(self.capabilities.len() as u32).to_be_bytes());
        for cap in &self.capabilities {
            push_field(&mut b, cap.as_bytes());
        }
        b.extend_from_slice(&(self.addresses.len() as u32).to_be_bytes());
        for addr in &self.addresses {
            push_field(&mut b, addr.to_string().as_bytes());
        }
        b.extend_from_slice(&self.protocol_version.to_be_bytes());
        b.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        b.extend_from_slice(&self.expires_at.to_be_bytes());
        b
    }
}

/// Length-prefix (`u32` big-endian) then append `data` — makes the transcript unambiguous across
/// variable-length fields (no field's bytes can bleed into the next).
fn push_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Why a [`RelayDescriptor`] failed verification. Each is fail-closed — a descriptor that does not
/// verify MUST be discarded, never trusted.
#[cfg(feature = "seal")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    /// The advertised `bls_g1_pub` is not a valid G1 subgroup point.
    BadKey,
    /// The BLS G2 signature over the descriptor transcript did not verify against `bls_g1_pub`.
    BadSignature,
    /// The presented mTLS SPKI does not hash to `peer_id_spki_hash` (anti-substitution).
    PeerIdMismatch,
    /// The descriptor is past `expires_at` (stale).
    Expired,
    /// A chain-resolved `relay_did → G1` key does not equal the advertised `bls_g1_pub`.
    DidBindingMismatch,
}

#[cfg(feature = "seal")]
impl RelayDescriptor {
    /// Verify the descriptor against the relay's live mTLS session (SPEC §8 anti-substitution).
    ///
    /// Checks, fail-closed and in order: the G1 key is a valid subgroup point; the signature verifies
    /// over [`signing_bytes`](RelayDescriptor::signing_bytes) (so no field was altered); the presented
    /// SPKI hashes to `peer_id_spki_hash` (so this descriptor belongs to THIS TLS session); and the
    /// descriptor is not expired. Pass the peer's TLS-presented SPKI DER as `presented_spki_der`.
    ///
    /// This does NOT resolve `relay_did → G1` on chain — a consumer with chain access closes that
    /// last binding via [`verify_did_binding`](RelayDescriptor::verify_did_binding).
    ///
    /// # Errors
    /// A [`DescriptorError`] identifying the first failed check.
    pub fn verify(&self, presented_spki_der: &[u8], now_ms: u64) -> Result<(), DescriptorError> {
        use dig_identity::bls::{g1_subgroup_check, verify_signature};
        use dig_identity::hash::sha256;

        if !g1_subgroup_check(&self.bls_g1_pub) {
            return Err(DescriptorError::BadKey);
        }
        if !verify_signature(&self.bls_g1_pub, &self.signing_bytes(), &self.sig) {
            return Err(DescriptorError::BadSignature);
        }
        if sha256(presented_spki_der) != self.peer_id_spki_hash {
            return Err(DescriptorError::PeerIdMismatch);
        }
        if now_ms > self.expires_at {
            return Err(DescriptorError::Expired);
        }
        Ok(())
    }

    /// Close the `relay_did → bls_g1_pub` binding using a chain-resolved G1 key (e.g. from
    /// `dig_identity::resolve_bls_public_key`). Call after [`verify`](RelayDescriptor::verify) when
    /// chain access is available; misbinding → the descriptor is a substitution attempt → discard.
    ///
    /// # Errors
    /// [`DescriptorError::DidBindingMismatch`] if `resolved_g1` differs from the advertised key.
    pub fn verify_did_binding(&self, resolved_g1: &[u8; 48]) -> Result<(), DescriptorError> {
        if resolved_g1 != &self.bls_g1_pub {
            return Err(DescriptorError::DidBindingMismatch);
        }
        Ok(())
    }
}
