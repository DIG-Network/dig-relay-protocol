//! Known-Answer Tests (KATs) pinning the node↔relay wire byte-for-byte.
//!
//! Each golden constant is the EXACT JSON a message serializes to. These bytes are what the wire
//! currently vendored in dig-gossip (`src/relay/relay_types.rs`), dig-relay (`src/wire.rs`), and
//! consumed by dig-nat (`src/relay.rs`) produces — same `#[serde(tag = "type")]` discriminators,
//! same field names, same declaration order. If any of these assertions changes, the wire changed
//! and the byte-identical-extraction guarantee (dig_ecosystem #874 WU-1) is broken: consumers that
//! swap their vendored copy for this crate would no longer be wire-compatible.
//!
//! Coverage: every `RelayMessage` variant (RLY-001..RLY-007 + notifications + error) has a golden
//! encode assertion + a decode/round-trip assertion, plus malformed-input rejection.

use dig_relay_protocol::{MeshMessage, RelayDescriptor, RelayMessage, RelayPeerInfo};

/// A `RelayPeerInfo` with fixed timestamps so its golden bytes are deterministic (the `new()`
/// constructor stamps wall-clock time, which cannot appear in a fixture).
fn fixture_peer() -> RelayPeerInfo {
    RelayPeerInfo {
        peer_id: "a".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
        connected_at: 100,
        last_seen: 200,
        addresses: vec![],
    }
}

/// Assert `msg` serializes to EXACTLY `golden`, and that `golden` decodes back to an equal message.
fn assert_kat(msg: &RelayMessage, golden: &str) {
    let encoded = serde_json::to_string(msg).expect("serialize");
    assert_eq!(encoded, golden, "wire bytes drifted for {msg:?}");

    // Round-trip: the golden bytes decode, and re-encoding is stable.
    let decoded: RelayMessage = serde_json::from_str(golden).expect("deserialize golden");
    let re_encoded = serde_json::to_string(&decoded).expect("re-serialize");
    assert_eq!(
        re_encoded, golden,
        "round-trip not byte-stable for {golden}"
    );
}

#[test]
fn kat_register() {
    assert_kat(
        &RelayMessage::Register {
            peer_id: "a".into(),
            network_id: "DIG_MAINNET".into(),
            protocol_version: 1,
            listen_addrs: vec![],
        },
        r#"{"type":"register","peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1}"#,
    );
}

#[test]
fn kat_register_ack() {
    assert_kat(
        &RelayMessage::RegisterAck {
            success: true,
            message: "registered".into(),
            connected_peers: 3,
        },
        r#"{"type":"register_ack","success":true,"message":"registered","connected_peers":3}"#,
    );
}

#[test]
fn kat_unregister() {
    assert_kat(
        &RelayMessage::Unregister {
            peer_id: "a".into(),
        },
        r#"{"type":"unregister","peer_id":"a"}"#,
    );
}

#[test]
fn kat_relay_message() {
    // The variant `RelayGossipMessage` serializes under `type:"relay_message"` (RLY-002).
    assert_kat(
        &RelayMessage::RelayGossipMessage {
            from: "a".into(),
            to: "b".into(),
            payload: vec![1, 2],
            seq: 9,
        },
        r#"{"type":"relay_message","from":"a","to":"b","payload":[1,2],"seq":9}"#,
    );
}

#[test]
fn kat_broadcast() {
    assert_kat(
        &RelayMessage::Broadcast {
            from: "a".into(),
            payload: vec![7],
            exclude: vec!["c".into()],
        },
        r#"{"type":"broadcast","from":"a","payload":[7],"exclude":["c"]}"#,
    );
}

#[test]
fn kat_peer_connected() {
    assert_kat(
        &RelayMessage::PeerConnected {
            peer: fixture_peer(),
        },
        r#"{"type":"peer_connected","peer":{"peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1,"connected_at":100,"last_seen":200}}"#,
    );
}

#[test]
fn kat_peer_disconnected() {
    assert_kat(
        &RelayMessage::PeerDisconnected {
            peer_id: "a".into(),
        },
        r#"{"type":"peer_disconnected","peer_id":"a"}"#,
    );
}

#[test]
fn kat_get_peers_some() {
    assert_kat(
        &RelayMessage::GetPeers {
            network_id: Some("DIG_MAINNET".into()),
        },
        r#"{"type":"get_peers","network_id":"DIG_MAINNET"}"#,
    );
}

#[test]
fn kat_get_peers_none() {
    assert_kat(
        &RelayMessage::GetPeers { network_id: None },
        r#"{"type":"get_peers","network_id":null}"#,
    );
}

#[test]
fn kat_peers() {
    assert_kat(
        &RelayMessage::Peers {
            peers: vec![fixture_peer()],
        },
        r#"{"type":"peers","peers":[{"peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1,"connected_at":100,"last_seen":200}]}"#,
    );
}

#[test]
fn kat_ping_pong() {
    assert_kat(
        &RelayMessage::Ping { timestamp: 5 },
        r#"{"type":"ping","timestamp":5}"#,
    );
    assert_kat(
        &RelayMessage::Pong { timestamp: 5 },
        r#"{"type":"pong","timestamp":5}"#,
    );
}

#[test]
fn kat_hole_punch_request() {
    assert_kat(
        &RelayMessage::HolePunchRequest {
            peer_id: "a".into(),
            target_peer_id: "b".into(),
            external_addr: "203.0.113.1:9444".parse().unwrap(),
        },
        r#"{"type":"hole_punch_request","peer_id":"a","target_peer_id":"b","external_addr":"203.0.113.1:9444"}"#,
    );
}

#[test]
fn kat_hole_punch_coordinate() {
    assert_kat(
        &RelayMessage::HolePunchCoordinate {
            peer_id: "a".into(),
            external_addr: "203.0.113.1:9444".parse().unwrap(),
        },
        r#"{"type":"hole_punch_coordinate","peer_id":"a","external_addr":"203.0.113.1:9444"}"#,
    );
}

#[test]
fn kat_hole_punch_result() {
    assert_kat(
        &RelayMessage::HolePunchResult {
            peer_id: "a".into(),
            success: true,
        },
        r#"{"type":"hole_punch_result","peer_id":"a","success":true}"#,
    );
}

#[test]
fn kat_error() {
    assert_kat(
        &RelayMessage::Error {
            code: 3,
            message: "nope".into(),
        },
        r#"{"type":"error","code":3,"message":"nope"}"#,
    );
}

#[test]
fn ipv6_external_addr_round_trips() {
    // §5.2 IPv6-first: a v6 external address must serialize as the standard bracketed form and
    // round-trip losslessly.
    assert_kat(
        &RelayMessage::HolePunchCoordinate {
            peer_id: "a".into(),
            external_addr: "[2001:db8::1]:9444".parse().unwrap(),
        },
        r#"{"type":"hole_punch_coordinate","peer_id":"a","external_addr":"[2001:db8::1]:9444"}"#,
    );
}

#[test]
fn decode_rejects_unknown_type_tag() {
    let err = serde_json::from_str::<RelayMessage>(r#"{"type":"not_a_real_message"}"#);
    assert!(err.is_err(), "an unknown `type` tag must be rejected");
}

#[test]
fn decode_rejects_missing_type_tag() {
    let err = serde_json::from_str::<RelayMessage>(r#"{"peer_id":"a"}"#);
    assert!(
        err.is_err(),
        "a message with no `type` tag must be rejected"
    );
}

#[test]
fn decode_rejects_missing_required_field() {
    // `register` requires network_id + protocol_version; omitting them is malformed.
    let err = serde_json::from_str::<RelayMessage>(r#"{"type":"register","peer_id":"a"}"#);
    assert!(
        err.is_err(),
        "a message missing a required field must be rejected"
    );
}

#[test]
fn decode_rejects_wrong_field_type() {
    // protocol_version is a u32; a string is malformed.
    let err = serde_json::from_str::<RelayMessage>(
        r#"{"type":"register","peer_id":"a","network_id":"n","protocol_version":"x"}"#,
    );
    assert!(err.is_err(), "a wrongly-typed field must be rejected");
}

// -- #924 WU1: additive connect-leg fields (NC-6 soft-fork) --
//
// `Register.listen_addrs` + `RelayPeerInfo.addresses` are additive optional fields carrying dialable
// candidates for the connect leg (direct-dial B1). Both are `#[serde(default, skip_serializing_if =
// "Vec::is_empty")]`, so: (a) OLD payloads without them still decode (soft-fork); (b) an EMPTY field
// is omitted from the bytes, keeping existing-peer wire byte-identical; (c) a NON-EMPTY field
// round-trips byte-stable, IPv6-first (§5.2).

#[test]
fn register_soft_fork_old_payload_without_listen_addrs_still_decodes() {
    // An OLD peer's `register` (no `listen_addrs`) MUST still decode — the field defaults to empty.
    let old =
        r#"{"type":"register","peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1}"#;
    let decoded: RelayMessage = serde_json::from_str(old).expect("old register must decode");
    match decoded {
        RelayMessage::Register { listen_addrs, .. } => {
            assert!(
                listen_addrs.is_empty(),
                "missing listen_addrs must default to empty"
            );
        }
        other => panic!("expected Register, got {other:?}"),
    }
}

#[test]
fn register_empty_listen_addrs_is_omitted_from_bytes() {
    // skip_serializing_if: an empty `listen_addrs` must NOT appear on the wire, so the bytes are
    // byte-identical to what an old peer emits (`kat_register` shares these exact bytes).
    let encoded = serde_json::to_string(&RelayMessage::Register {
        peer_id: "a".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
        listen_addrs: vec![],
    })
    .expect("serialize");
    assert_eq!(
        encoded,
        r#"{"type":"register","peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1}"#,
        "empty listen_addrs must be omitted from the wire"
    );
}

#[test]
fn register_with_listen_addrs_round_trips_ipv6_first() {
    // A NEW peer advertises its gossip listen candidates, IPv6-first (§5.2); the bytes round-trip.
    assert_kat(
        &RelayMessage::Register {
            peer_id: "a".into(),
            network_id: "DIG_MAINNET".into(),
            protocol_version: 1,
            listen_addrs: vec![
                "[2001:db8::1]:9445".parse().unwrap(),
                "203.0.113.1:9445".parse().unwrap(),
            ],
        },
        r#"{"type":"register","peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1,"listen_addrs":["[2001:db8::1]:9445","203.0.113.1:9445"]}"#,
    );
}

#[test]
fn relay_peer_info_soft_fork_old_payload_without_addresses_still_decodes() {
    // An OLD relay's `RelayPeerInfo` (no `addresses`) MUST still decode — the field defaults empty.
    let old = r#"{"type":"peers","peers":[{"peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1,"connected_at":100,"last_seen":200}]}"#;
    let decoded: RelayMessage = serde_json::from_str(old).expect("old peers must decode");
    match decoded {
        RelayMessage::Peers { peers } => {
            assert_eq!(peers.len(), 1);
            assert!(
                peers[0].addresses.is_empty(),
                "missing addresses must default to empty"
            );
        }
        other => panic!("expected Peers, got {other:?}"),
    }
}

#[test]
fn relay_peer_info_empty_addresses_is_omitted_from_bytes() {
    // skip_serializing_if: an empty `addresses` must NOT appear on the wire (byte-identical to old).
    let encoded = serde_json::to_string(&RelayMessage::PeerConnected {
        peer: fixture_peer(),
    })
    .expect("serialize");
    assert_eq!(
        encoded,
        r#"{"type":"peer_connected","peer":{"peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1,"connected_at":100,"last_seen":200}}"#,
        "empty addresses must be omitted from the wire"
    );
}

#[test]
fn relay_peer_info_with_addresses_round_trips_ipv6_first() {
    // The relay hands a peer its relay-resolved dialable candidates, IPv6-first (§5.2); bytes stable.
    let peer = RelayPeerInfo {
        peer_id: "a".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
        connected_at: 100,
        last_seen: 200,
        addresses: vec![
            "[2001:db8::1]:9445".parse().unwrap(),
            "203.0.113.1:9445".parse().unwrap(),
        ],
    };
    assert_kat(
        &RelayMessage::PeerConnected { peer },
        r#"{"type":"peer_connected","peer":{"peer_id":"a","network_id":"DIG_MAINNET","protocol_version":1,"connected_at":100,"last_seen":200,"addresses":["[2001:db8::1]:9445","203.0.113.1:9445"]}}"#,
    );
}

#[test]
fn relay_peer_info_new_stamps_equal_timestamps() {
    let info = RelayPeerInfo::new("a".into(), "DIG_MAINNET".into(), 1);
    assert_eq!(info.peer_id, "a");
    assert_eq!(info.network_id, "DIG_MAINNET");
    assert_eq!(info.protocol_version, 1);
    // new() stamps connected_at == last_seen (both = now).
    assert_eq!(info.connected_at, info.last_seen);
}

// -- v2: recipient-sealed handshake + transport + mesh (additive since v1, §5.1) --
//
// The v2 additions are new `type` variants; the existing v1 KATs above are UNCHANGED and still pass,
// which IS the §5.1 back-compat proof (adding variants leaves every prior variant byte-identical).
// The sealed CIPHERTEXT is non-deterministic (fresh per-message ephemeral → forward secrecy), so the
// crypto is proven by round-trip in `tests/seal.rs`; here we pin the deterministic PLAINTEXT shapes:
// the `Sealed` transport variant, the `RelayDescriptor`, and the mesh frames.

/// A `RelayDescriptor` with fixed bytes so its JSON round-trips deterministically.
fn fixture_descriptor() -> RelayDescriptor {
    RelayDescriptor {
        relay_did: [0x11; 32],
        bls_g1_pub: [0x22; 48],
        peer_id_spki_hash: [0x33; 32],
        network_id: "DIG_MAINNET".into(),
        capabilities: vec!["hole-punch".into(), "mesh".into()],
        addresses: vec!["[2001:db8::1]:9450".parse().unwrap()],
        protocol_version: 2,
        timestamp_ms: 1_700_000_000_000,
        expires_at: 1_700_000_600_000,
        sig: [0x44; 96],
    }
}

/// Encode→decode a value and assert equality (for structures whose full byte-literal is impractical
/// to inline — the 48/96-byte BLS arrays — but whose stability we still guard).
fn assert_json_round_trip<T>(value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).expect("serialize");
    let decoded: T = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(&decoded, value, "round-trip must be lossless");
}

#[test]
fn kat_sealed_transport_variant() {
    // The `Sealed` variant carries the encoded dig-message envelope bytes as a JSON u8 array.
    assert_kat(
        &RelayMessage::Sealed {
            envelope: vec![1, 2, 3],
        },
        r#"{"type":"sealed","envelope":[1,2,3]}"#,
    );
}

#[test]
fn descriptor_round_trips_and_enforces_bls_lengths() {
    let descriptor = fixture_descriptor();
    assert_json_round_trip(&descriptor);
    // relay_hello carries the descriptor; the whole message round-trips.
    assert_json_round_trip(&RelayMessage::RelayHello {
        descriptor: Box::new(descriptor),
    });

    // serde-big-array enforces the exact BLS field lengths on decode — a short key is rejected.
    let bad = r#"{"relay_did":[0],"bls_g1_pub":[1,2,3],"peer_id_spki_hash":[0],"network_id":"n","capabilities":[],"addresses":[],"protocol_version":2,"timestamp_ms":0,"expires_at":0,"sig":[0]}"#;
    assert!(
        serde_json::from_str::<RelayDescriptor>(bad).is_err(),
        "a wrong-length BLS field must be rejected"
    );
}

#[test]
fn kat_mesh_forward() {
    // mesh_forward's payload is doubly opaque (node↔node-sealed, then relay↔relay-sealed).
    assert_mesh_kat(
        &MeshMessage::MeshForward {
            origin_peer_id: "a".into(),
            dest_peer_id: "b".into(),
            payload: vec![9, 8],
            seq: 4,
        },
        r#"{"type":"mesh_forward","origin_peer_id":"a","dest_peer_id":"b","payload":[9,8],"seq":4}"#,
    );
}

#[test]
fn kat_mesh_keepalive() {
    assert_mesh_kat(
        &MeshMessage::MeshKeepalive {
            timestamp_ms: 1_700_000_000_000,
        },
        r#"{"type":"mesh_keepalive","timestamp_ms":1700000000000}"#,
    );
}

#[test]
fn kat_mesh_handoff_and_switch() {
    assert_mesh_kat(
        &MeshMessage::MeshHandoff {
            peer_id: "a".into(),
            network_id: "DIG_MAINNET".into(),
        },
        r#"{"type":"mesh_handoff","peer_id":"a","network_id":"DIG_MAINNET"}"#,
    );
    assert_mesh_kat(
        &MeshMessage::MeshSwitch {
            peer_id: "a".into(),
            target_relay_did: "ff".into(),
            accepted: true,
        },
        r#"{"type":"mesh_switch","peer_id":"a","target_relay_did":"ff","accepted":true}"#,
    );
}

#[test]
fn kat_mesh_error() {
    assert_mesh_kat(
        &MeshMessage::MeshError {
            code: 7,
            message: "no route".into(),
        },
        r#"{"type":"mesh_error","code":7,"message":"no route"}"#,
    );
}

#[test]
fn mesh_hello_and_peer_exchange_round_trip() {
    // Descriptor-carrying mesh frames round-trip (full byte-literal impractical for BLS arrays).
    assert_json_round_trip(&MeshMessage::MeshHello {
        descriptor: Box::new(fixture_descriptor()),
    });
    assert_json_round_trip(&MeshMessage::MeshHelloAck {
        descriptor: Box::new(fixture_descriptor()),
    });
    assert_json_round_trip(&MeshMessage::MeshPeerExchange {
        relays: vec![fixture_descriptor()],
    });
}

#[test]
fn mesh_decode_rejects_unknown_type() {
    assert!(serde_json::from_str::<MeshMessage>(r#"{"type":"not_mesh"}"#).is_err());
}

/// Assert a `MeshMessage` serializes to EXACTLY `golden` and round-trips byte-stable.
fn assert_mesh_kat(frame: &MeshMessage, golden: &str) {
    let encoded = serde_json::to_string(frame).expect("serialize");
    assert_eq!(encoded, golden, "mesh wire bytes drifted for {frame:?}");
    let decoded: MeshMessage = serde_json::from_str(golden).expect("deserialize golden");
    let re_encoded = serde_json::to_string(&decoded).expect("re-serialize");
    assert_eq!(re_encoded, golden, "mesh round-trip not byte-stable");
}
