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

use dig_relay_protocol::{RelayMessage, RelayPeerInfo};

/// A `RelayPeerInfo` with fixed timestamps so its golden bytes are deterministic (the `new()`
/// constructor stamps wall-clock time, which cannot appear in a fixture).
fn fixture_peer() -> RelayPeerInfo {
    RelayPeerInfo {
        peer_id: "a".into(),
        network_id: "DIG_MAINNET".into(),
        protocol_version: 1,
        connected_at: 100,
        last_seen: 200,
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

#[test]
fn relay_peer_info_new_stamps_equal_timestamps() {
    let info = RelayPeerInfo::new("a".into(), "DIG_MAINNET".into(), 1);
    assert_eq!(info.peer_id, "a");
    assert_eq!(info.network_id, "DIG_MAINNET");
    assert_eq!(info.protocol_version, 1);
    // new() stamps connected_at == last_seen (both = now).
    assert_eq!(info.connected_at, info.last_seen);
}
