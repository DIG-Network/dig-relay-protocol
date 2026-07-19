//! Recipient-seal + descriptor security tests (feature `seal`).
//!
//! These prove the v2 security contracts: a frame is bound to its intended recipient (opens only with
//! the right key), non-transferable across relays, its body is ciphertext at any intermediary (NC-1),
//! descriptors resist substitution, the non-sealed variants stay plaintext, and a required-seal
//! session refuses a downgrade. The whole file is empty without the `seal` feature.
#![cfg(feature = "seal")]

use dig_relay_protocol::seal::{
    negotiate_session, open_control, open_mesh, seal_control, seal_mesh, Bytes32, RelayIdentity,
    ReplayGuard, SealContext, SealError, SealMode,
};
use dig_relay_protocol::{ids, MeshMessage, RelayMessage};

const NOW_MS: u64 = 1_700_000_000_000;

/// A DID from a single filler byte (distinct per party).
fn did(byte: u8) -> Bytes32 {
    Bytes32::new([byte; 32])
}

/// A deterministic identity keyed by a seed byte, addressed by `did(seed)`.
fn identity(seed: u8) -> RelayIdentity {
    RelayIdentity::from_master_seed(did(seed), &[seed; 32])
}

/// A sender resolver over a set of `(RelayIdentity)` — maps each party's DID to its BLS G1 key, the
/// stand-in for `dig-identity` chain resolution.
fn resolver(parties: &[&RelayIdentity]) -> impl Fn(Bytes32, u32) -> Option<[u8; 48]> {
    let table: Vec<(Bytes32, [u8; 48])> =
        parties.iter().map(|p| (p.did(), p.public_key())).collect();
    move |did, _epoch| table.iter().find(|(d, _)| *d == did).map(|(_, k)| *k)
}

fn ctx(counter: u64) -> SealContext {
    SealContext {
        correlation_id: did(0xC0),
        counter,
        timestamp_ms: NOW_MS,
        expires_at: NOW_MS + 60_000,
    }
}

fn sample_register() -> RelayMessage {
    RelayMessage::Register {
        peer_id: "node-a".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 2,
        listen_addrs: vec![],
    }
}

#[test]
fn sealed_register_opens_only_with_the_relay_key() {
    let node = identity(1);
    let relay_a = identity(2);
    let resolve = resolver(&[&node]);

    let sealed = seal_control(
        &node,
        relay_a.did(),
        &relay_a.public_key(),
        &sample_register(),
        &ctx(0),
    )
    .expect("seal register to relay A");

    // The intended relay opens it.
    let mut guard = ReplayGuard::new();
    let opened =
        open_control(&relay_a, &sealed, &resolve, &mut guard, NOW_MS).expect("relay A opens");
    assert_eq!(opened.message_type, ids::control::REGISTER);
    assert!(matches!(opened.message, RelayMessage::Register { .. }));
}

#[test]
fn frame_sealed_to_relay_a_fails_at_relay_b() {
    // Cross-relay non-transferability: a control frame for A cannot be opened by B.
    let node = identity(1);
    let relay_a = identity(2);
    let relay_b = identity(3);
    let resolve = resolver(&[&node]);

    let sealed = seal_control(
        &node,
        relay_a.did(),
        &relay_a.public_key(),
        &sample_register(),
        &ctx(0),
    )
    .expect("seal to relay A");

    let mut guard = ReplayGuard::new();
    let err = open_control(&relay_b, &sealed, &resolve, &mut guard, NOW_MS);
    assert!(
        matches!(err, Err(SealError::Message(_))),
        "relay B (wrong key) must fail to open a frame sealed to relay A, got {err:?}"
    );
}

#[test]
fn mesh_frame_sealed_to_relay_a_fails_at_relay_b() {
    let relay_a = identity(2);
    let relay_b = identity(3);
    let relay_c = identity(4); // sender
    let resolve = resolver(&[&relay_c]);

    let frame = MeshMessage::MeshKeepalive {
        timestamp_ms: NOW_MS,
    };
    let sealed = seal_mesh(
        &relay_c,
        relay_a.did(),
        &relay_a.public_key(),
        &frame,
        &ctx(0),
    )
    .expect("seal mesh to relay A");

    // Relay A opens.
    let mut ga = ReplayGuard::new();
    assert!(open_mesh(&relay_a, &sealed, &resolve, &mut ga, NOW_MS).is_ok());
    // Relay B cannot.
    let mut gb = ReplayGuard::new();
    assert!(open_mesh(&relay_b, &sealed, &resolve, &mut gb, NOW_MS).is_err());
}

#[test]
fn mesh_forward_payload_is_ciphertext_at_the_relay() {
    // NC-1: a node↔node-sealed payload forwarded across the mesh is ciphertext on the wire — the
    // plaintext marker MUST NOT appear anywhere in the sealed envelope bytes.
    let sender = identity(4);
    let relay_a = identity(2);
    const SECRET: &[u8] = b"TOP-SECRET-INNER-PAYLOAD";

    let frame = MeshMessage::MeshForward {
        origin_peer_id: "o".into(),
        dest_peer_id: "d".into(),
        payload: SECRET.to_vec(),
        seq: 1,
    };
    let sealed = seal_mesh(
        &sender,
        relay_a.did(),
        &relay_a.public_key(),
        &frame,
        &ctx(0),
    )
    .unwrap();

    let RelayMessage::Sealed { envelope } = &sealed else {
        panic!("expected a Sealed transport variant");
    };
    assert!(
        !contains_subslice(envelope, SECRET),
        "the sealed envelope must not contain the plaintext payload (NC-1)"
    );

    // And the intended relay recovers it exactly.
    let resolve = resolver(&[&sender]);
    let mut guard = ReplayGuard::new();
    let opened = open_mesh(&relay_a, &sealed, &resolve, &mut guard, NOW_MS).unwrap();
    assert_eq!(opened.message_type, ids::mesh::FORWARD);
    match opened.frame {
        MeshMessage::MeshForward { payload, .. } => assert_eq!(payload, SECRET),
        other => panic!("expected MeshForward, got {other:?}"),
    }
}

#[test]
fn non_directed_variants_are_not_sealable() {
    // broadcast + get_peers + peers must stay plaintext (relay must read); sealing them is refused.
    let node = identity(1);
    let relay = identity(2);
    for msg in [
        RelayMessage::Broadcast {
            from: "a".into(),
            payload: vec![1],
            exclude: vec![],
        },
        RelayMessage::GetPeers {
            network_id: Some("DIG_MAINNET".into()),
        },
        RelayMessage::Peers { peers: vec![] },
        RelayMessage::Ping { timestamp: 1 },
    ] {
        let err = seal_control(&node, relay.did(), &relay.public_key(), &msg, &ctx(0));
        assert!(
            matches!(err, Err(SealError::NotSealable)),
            "{msg:?} must not be sealable"
        );
    }
}

#[test]
fn descriptor_verifies_then_rejects_tampering_and_substitution() {
    let relay = identity(2);
    let spki = b"the-relays-tls-spki-der-bytes";
    let spki_hash = dig_identity::hash::sha256(spki);

    let descriptor = relay.sign_descriptor(
        spki_hash,
        "DIG_MAINNET".into(),
        vec!["mesh".into()],
        vec!["[2001:db8::1]:9450".parse().unwrap()],
        2,
        NOW_MS,
        NOW_MS + 600_000,
    );

    // Valid against the presented SPKI.
    descriptor
        .verify(spki, NOW_MS)
        .expect("valid descriptor verifies");

    // Tampered field → signature no longer covers it.
    let mut tampered = descriptor.clone();
    tampered.network_id = "EVIL_NET".into();
    assert!(
        tampered.verify(spki, NOW_MS).is_err(),
        "tampered field must fail"
    );

    // Substituted transport identity → SPKI mismatch (a relay presenting another's descriptor).
    assert!(
        descriptor.verify(b"a-different-tls-spki", NOW_MS).is_err(),
        "descriptor presented over the wrong TLS session must fail"
    );

    // Substituted key (attacker swaps in their own G1) → signature fails.
    let attacker = identity(9);
    let mut swapped = descriptor.clone();
    swapped.bls_g1_pub = attacker.public_key();
    assert!(
        swapped.verify(spki, NOW_MS).is_err(),
        "key substitution must fail"
    );

    // Expired descriptor is rejected.
    assert!(
        descriptor.verify(spki, NOW_MS + 600_001).is_err(),
        "expired descriptor must fail"
    );

    // DID→G1 chain binding: matching key passes, mismatched key fails.
    descriptor
        .verify_did_binding(&relay.public_key())
        .expect("matching chain key");
    assert!(descriptor
        .verify_did_binding(&attacker.public_key())
        .is_err());
}

#[test]
fn required_mode_refuses_a_downgraded_session() {
    // A v1 (or seal-incapable) peer cannot strip sealing from a Required-mode node.
    assert!(matches!(
        negotiate_session(SealMode::Required, 1, false),
        Err(SealError::DowngradeRefused)
    ));
    assert!(matches!(
        negotiate_session(SealMode::Required, 2, false),
        Err(SealError::DowngradeRefused)
    ));
    // Required + a v2 seal-capable peer → sealed.
    assert!(
        negotiate_session(SealMode::Required, 2, true)
            .unwrap()
            .sealed
    );
    // Optional falls back to plaintext against a v1 peer, seals against a v2 peer.
    assert!(
        !negotiate_session(SealMode::Optional, 1, false)
            .unwrap()
            .sealed
    );
    assert!(
        negotiate_session(SealMode::Optional, 2, true)
            .unwrap()
            .sealed
    );
}

#[test]
fn replayed_frame_is_rejected() {
    // The dig-message replay guard rejects a re-sent identical envelope (anti-replay comes free).
    let node = identity(1);
    let relay = identity(2);
    let resolve = resolver(&[&node]);
    let sealed = seal_control(
        &node,
        relay.did(),
        &relay.public_key(),
        &sample_register(),
        &ctx(0),
    )
    .unwrap();

    let mut guard = ReplayGuard::new();
    assert!(open_control(&relay, &sealed, &resolve, &mut guard, NOW_MS).is_ok());
    let replay = open_control(&relay, &sealed, &resolve, &mut guard, NOW_MS);
    assert!(
        matches!(replay, Err(SealError::Message(_))),
        "a replayed frame must be rejected, got {replay:?}"
    );
}

#[test]
fn wrong_band_is_rejected() {
    // A mesh frame opened via the control opener (or vice-versa) is refused by the band check.
    let sender = identity(4);
    let relay = identity(2);
    let resolve = resolver(&[&sender]);
    let mesh = seal_mesh(
        &sender,
        relay.did(),
        &relay.public_key(),
        &MeshMessage::MeshKeepalive {
            timestamp_ms: NOW_MS,
        },
        &ctx(0),
    )
    .unwrap();

    let mut guard = ReplayGuard::new();
    let err = open_control(&relay, &mesh, &resolve, &mut guard, NOW_MS);
    assert!(
        matches!(err, Err(SealError::WrongBand { .. })),
        "a mesh frame opened as control must be rejected, got {err:?}"
    );
}

#[test]
fn open_rejects_non_sealed_variant() {
    let relay = identity(2);
    let resolve = resolver(&[&relay]);
    let mut guard = ReplayGuard::new();
    let err = open_control(&relay, &sample_register(), &resolve, &mut guard, NOW_MS);
    assert!(matches!(err, Err(SealError::NotSealed)));
}

/// Whether `haystack` contains `needle` as a contiguous subslice.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
