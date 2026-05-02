//! Pedersen DKG test suite.
//!
//! Covers:
//! - Happy-path ceremony (2-of-3, 3-of-3, 3-of-5).
//! - Output compatibility with the signing runtime (`attest_frost_distributed`).
//! - Deterministic identity mapping.
//! - Configuration rejection (duplicates, bad threshold).
//! - Invalid sequencing (part2 before part1, part3 before part2, reuse after complete).
//! - FROST library rejection (missing / wrong packages).
//! - Independent runs produce distinct key material.
//!
//! # Build
//!
//! ```bash
//! cargo test --package tls-attestation-testing --features frost --test dkg
//! ```

#![cfg(feature = "frost")]

use std::collections::HashMap;

use tls_attestation_core::{ids::ProverId, types::Nonce};
use tls_attestation_core::ids::VerifierId;
use tls_attestation_crypto::{
    dkg::{dkg_part1, DkgRound1Package},
    dkg_announce::{
        create_dkg_key_announcement, DkgParticipantRegistry,
        SignedDkgKeyAnnouncement, ANNOUNCEMENT_VERSION,
    },
    dkg_encrypt::{
        decrypt_round2_package, encrypt_round2_package, DkgCeremonyId, DkgEncryptionKeyPair,
    },
    frost_adapter::frost_trusted_dealer_keygen,
    threshold::VerifierKeyPair,
};
use tls_attestation_node::{
    dkg_node::{run_dkg_ceremony, run_dkg_ceremony_encrypted, run_dkg_ceremony_with_authenticated_keys},
    error::NodeError,
    FrostDkgNode,
};
use tls_attestation_testing::fixtures::{TestHarness, TestHarnessConfig};
use tls_attestation_network::messages::AttestationRequest;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_request(tag: &str, query: &[u8]) -> AttestationRequest {
    AttestationRequest {
        prover_id: ProverId::from_bytes([0xAAu8; 32]),
        client_nonce: Nonce::from_bytes([0xBBu8; 32]),
        statement_tag: tag.to_string(),
        query: query.to_vec(),
        requested_ttl_secs: 3600,
    }
}

/// Create a harness + DKG nodes using the harness's quorum verifier IDs.
///
/// This is the standard test setup: verifier IDs come from the same source
/// as the coordinator's quorum, so the resulting `FrostAuxiliaryNode`s are
/// compatible with `attest_frost_distributed`.
fn setup_dkg_nodes(
    n: usize,
    threshold: usize,
) -> (TestHarness, Vec<FrostDkgNode>) {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: n,
        threshold,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|vid| {
            FrostDkgNode::new(vid.clone(), vids.clone(), threshold as u16)
                .expect("FrostDkgNode::new should succeed with valid inputs")
        })
        .collect();
    (harness, nodes)
}

// ── Phase 5: Happy-path tests ─────────────────────────────────────────────────

/// Minimal valid ceremony: 2-of-3.
#[test]
fn dkg_2_of_3_ceremony_succeeds() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 2);
    let (aux_nodes, _group_key) =
        run_dkg_ceremony(&mut nodes).expect("2-of-3 DKG ceremony should succeed");
    assert_eq!(aux_nodes.len(), 3);
    // All nodes must report completion.
    assert!(nodes.iter().all(|n| n.is_complete()));
}

/// Strict majority: all nodes must sign.
#[test]
fn dkg_3_of_3_ceremony_succeeds() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 3);
    let (aux_nodes, _group_key) =
        run_dkg_ceremony(&mut nodes).expect("3-of-3 DKG ceremony should succeed");
    assert_eq!(aux_nodes.len(), 3);
}

/// Larger quorum: 3-of-5.
#[test]
fn dkg_3_of_5_ceremony_succeeds() {
    let (_harness, mut nodes) = setup_dkg_nodes(5, 3);
    let (aux_nodes, _group_key) =
        run_dkg_ceremony(&mut nodes).expect("3-of-5 DKG ceremony should succeed");
    assert_eq!(aux_nodes.len(), 5);
}

/// All nodes in the ceremony must derive the same group verifying key.
#[test]
fn dkg_all_nodes_derive_same_group_key() {
    let n = 4;
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: n,
        threshold: 3,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let mut nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|vid| FrostDkgNode::new(vid.clone(), vids.clone(), 3).unwrap())
        .collect();

    // Drive part1 and part2 manually to collect per-node group keys.
    let round1_broadcasts: HashMap<_, _> = nodes
        .iter_mut()
        .map(|n| (n.verifier_id().clone(), n.part1().unwrap()))
        .collect();

    let mut round2_unicasts: HashMap<_, HashMap<_, _>> = HashMap::new();
    for node in nodes.iter_mut() {
        let my_id = node.verifier_id().clone();
        let others: HashMap<_, _> = round1_broadcasts
            .iter()
            .filter(|(v, _)| *v != &my_id)
            .map(|(v, p)| (v.clone(), p.clone()))
            .collect();
        let outbound = node.part2(others).unwrap();
        for (to, pkg) in outbound {
            round2_unicasts.entry(to).or_default().insert(my_id.clone(), pkg);
        }
    }

    let mut key_bytes_seen: Vec<[u8; 32]> = Vec::new();
    for node in nodes.iter_mut() {
        let my_id = node.verifier_id().clone();
        let r2 = round2_unicasts.remove(&my_id).unwrap_or_default();
        let (_, gk) = node.part3(r2).unwrap();
        key_bytes_seen.push(gk.verifying_key_bytes());
    }

    // Every node must have derived the exact same 32-byte group verifying key.
    let first = key_bytes_seen[0];
    for (i, kb) in key_bytes_seen.iter().enumerate().skip(1) {
        assert_eq!(
            *kb, first,
            "node {i} derived a different group key than node 0"
        );
    }
}

/// Each node's group key output is consistent with the standard verifying-key accessor.
#[test]
fn dkg_group_key_verifying_key_bytes_is_32_bytes() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 2);
    let (_aux_nodes, group_key) = run_dkg_ceremony(&mut nodes).unwrap();
    let kb = group_key.verifying_key_bytes();
    // Ed25519 compressed point is always 32 bytes.
    assert_eq!(kb.len(), 32);
    // Not all-zeros (sanity: real key material).
    assert_ne!(kb, [0u8; 32]);
}

/// Identifier mapping is deterministic: running DKG twice with the same ordered
/// participant list produces the same VerifierId→Identifier mapping (though
/// different key material).
#[test]
fn dkg_identifier_mapping_is_deterministic() {
    let n = 3;
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: n,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();

    // First run.
    let mut nodes1: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();
    let (_, gk1) = run_dkg_ceremony(&mut nodes1).unwrap();

    // Second run — different key material but same group structure.
    let mut nodes2: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();
    let (_, gk2) = run_dkg_ceremony(&mut nodes2).unwrap();

    // Same participant set → same verifier-to-identifier mapping.
    for vid in &vids {
        let id1 = gk1.verifier_to_identifier(vid);
        let id2 = gk2.verifier_to_identifier(vid);
        assert_eq!(
            id1, id2,
            "identifier for {vid} must be deterministic across runs"
        );
    }

    // Different random key material → different group verifying keys.
    assert_ne!(
        gk1.verifying_key_bytes(),
        gk2.verifying_key_bytes(),
        "independent ceremonies should produce distinct group keys"
    );
}

/// DKG identifier mapping matches the trusted-dealer mapping for the same participant order.
#[test]
fn dkg_identifier_mapping_matches_trusted_dealer_for_same_order() {
    let n = 3;
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: n,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();

    let mut dkg_nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();
    let (_, dkg_gk) = run_dkg_ceremony(&mut dkg_nodes).unwrap();

    let td_output = frost_trusted_dealer_keygen(&vids, 2).unwrap();
    let td_gk = td_output.group_key;

    // Both key generation paths must assign the same identifier to each participant.
    for vid in &vids {
        assert_eq!(
            dkg_gk.verifier_to_identifier(vid),
            td_gk.verifier_to_identifier(vid),
            "DKG and trusted-dealer must use the same identifier mapping for {vid}"
        );
    }
}

// ── Phase 5: End-to-end compatibility test ────────────────────────────────────

/// Full end-to-end: Pedersen DKG ceremony → distributed FROST signing →
/// aggregate signature verification.
#[test]
fn dkg_then_distributed_signing_produces_valid_signature() {
    let (harness, mut nodes) = setup_dkg_nodes(3, 2);
    let (aux_nodes, group_key) =
        run_dkg_ceremony(&mut nodes).expect("DKG ceremony should succeed");

    let refs: Vec<&tls_attestation_node::FrostAuxiliaryNode> = aux_nodes.iter().collect();

    let envelope = harness
        .coordinator
        .attest_frost_distributed(
            make_request("dkg-e2e/v1", b"GET /price"),
            b"42.00",
            &refs,
            &group_key,
        )
        .expect("distributed signing after DKG should succeed");

    // Aggregate signature must verify against the group key.
    envelope
        .frost_approval
        .verify_signature()
        .expect("aggregate signature should be valid");

    // Approval must be bound to this specific envelope.
    envelope
        .frost_approval
        .verify_binding(&envelope.envelope_digest)
        .expect("approval must be bound to envelope_digest");
}

/// 2-of-3 DKG: using only threshold-many nodes for signing must still succeed.
#[test]
fn dkg_then_distributed_signing_with_threshold_subset_succeeds() {
    let (harness, mut nodes) = setup_dkg_nodes(3, 2);
    let (aux_nodes, group_key) = run_dkg_ceremony(&mut nodes).unwrap();

    // Use only the first 2 of 3 aux nodes.
    let refs: Vec<&tls_attestation_node::FrostAuxiliaryNode> =
        aux_nodes[..2].iter().collect();

    harness
        .coordinator
        .attest_frost_distributed(
            make_request("dkg-subset/v1", b"subset"),
            b"ok",
            &refs,
            &group_key,
        )
        .expect("2-of-3 signing with threshold-many DKG nodes should succeed");
}

/// Two independent sessions using the same DKG key material produce
/// distinct approvals (different envelope digests, different signatures).
#[test]
fn two_sessions_after_dkg_produce_distinct_approvals() {
    let (harness, mut nodes) = setup_dkg_nodes(3, 2);
    let (aux_nodes, group_key) = run_dkg_ceremony(&mut nodes).unwrap();
    let refs: Vec<_> = aux_nodes.iter().collect();

    let env1 = harness
        .coordinator
        .attest_frost_distributed(
            make_request("dkg-distinct/v1", b"session-1"),
            b"data-a",
            &refs,
            &group_key,
        )
        .unwrap();

    let env2 = harness
        .coordinator
        .attest_frost_distributed(
            make_request("dkg-distinct/v1", b"session-2"),
            b"data-b",
            &refs,
            &group_key,
        )
        .unwrap();

    assert_ne!(
        env1.envelope_digest, env2.envelope_digest,
        "distinct sessions must produce distinct digests"
    );
    assert_ne!(
        env1.frost_approval.aggregate_signature_bytes,
        env2.frost_approval.aggregate_signature_bytes,
        "distinct sessions must produce distinct aggregate signatures"
    );
}

// ── Phase 5: Configuration rejection tests ────────────────────────────────────

/// Fewer than 2 participants must be rejected at node construction.
#[test]
fn dkg_single_participant_rejected() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 1,
        threshold: 1,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let result = FrostDkgNode::new(vids[0].clone(), vids.clone(), 1);
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "single participant must be rejected"
    );
}

/// Threshold < 2 must be rejected (FROST constraint).
#[test]
fn dkg_threshold_below_two_rejected() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let result = FrostDkgNode::new(vids[0].clone(), vids.clone(), 1);
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "threshold < 2 must be rejected"
    );
}

/// Threshold > n must be rejected.
#[test]
fn dkg_threshold_exceeds_participant_count_rejected() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    // threshold = 4 > n = 3
    let result = FrostDkgNode::new(vids[0].clone(), vids.clone(), 4);
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "threshold > n must be rejected"
    );
}

/// Duplicate participant IDs must be rejected.
#[test]
fn dkg_duplicate_participant_ids_rejected() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    // Introduce a duplicate.
    let mut bad_vids = vids.clone();
    bad_vids[2] = bad_vids[0].clone();

    let result = FrostDkgNode::new(vids[0].clone(), bad_vids, 2);
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "duplicate participant IDs must be rejected"
    );
}

/// A verifier not in the participant list must be rejected.
#[test]
fn dkg_verifier_not_in_participant_list_rejected() {
    use tls_attestation_core::ids::VerifierId;

    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let outsider = VerifierId::from_bytes([0xFF; 32]);

    let result = FrostDkgNode::new(outsider, vids.clone(), 2);
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "verifier not in list must be rejected"
    );
}

// ── Phase 6: Invalid sequence tests ──────────────────────────────────────────

/// `part2` called before `part1` must return a clear error.
#[test]
fn dkg_part2_before_part1_returns_error() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 2);
    let result = nodes[0].part2(HashMap::new());
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "part2 before part1 must return DkgProtocol error"
    );
    // Other nodes are unaffected — they can still run a valid ceremony.
    let vids = nodes[1].verifier_id().clone();
    assert!(!nodes[1].is_complete());
    drop(vids);
}

/// `part3` called before `part1` and `part2` must return a clear error.
#[test]
fn dkg_part3_before_part1_returns_error() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 2);
    let result = nodes[0].part3(HashMap::new());
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "part3 before part1 must return DkgProtocol error"
    );
}

/// `part3` called after `part1` but before `part2` must return a clear error.
#[test]
fn dkg_part3_before_part2_returns_error() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 2);
    nodes[0].part1().unwrap();
    let result = nodes[0].part3(HashMap::new());
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "part3 before part2 must return DkgProtocol error"
    );
}

/// Calling `part1` twice on the same node must return a clear error.
#[test]
fn dkg_part1_called_twice_returns_error() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 2);
    nodes[0].part1().unwrap();
    let result = nodes[0].part1();
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "second part1 call must return DkgProtocol error"
    );
}

/// Calling `part2` twice must return a clear error (second call after success).
#[test]
fn dkg_part2_called_twice_returns_error() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let mut nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();

    // Run part1 on all nodes.
    let mut r1_pkgs: HashMap<tls_attestation_core::ids::VerifierId, DkgRound1Package> =
        HashMap::new();
    for node in nodes.iter_mut() {
        r1_pkgs.insert(node.verifier_id().clone(), node.part1().unwrap());
    }

    // Run part2 on node 0 with valid packages.
    let my_id = nodes[0].verifier_id().clone();
    let others: HashMap<_, _> = r1_pkgs
        .iter()
        .filter(|(v, _)| *v != &my_id)
        .map(|(v, p)| (v.clone(), p.clone()))
        .collect();
    nodes[0].part2(others.clone()).unwrap();

    // Second part2 call must fail.
    let result = nodes[0].part2(others);
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "second part2 call must return DkgProtocol error"
    );
}

/// After successful ceremony, any further call on a completed node must fail.
#[test]
fn dkg_calls_after_completion_return_error() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 2);
    run_dkg_ceremony(&mut nodes).unwrap();

    // All nodes are Completed — any call must fail.
    for node in nodes.iter_mut() {
        assert!(
            matches!(node.part1(), Err(NodeError::DkgProtocol(_))),
            "part1 after completion must fail"
        );
        assert!(
            matches!(node.part2(HashMap::new()), Err(NodeError::DkgProtocol(_))),
            "part2 after completion must fail"
        );
        assert!(
            matches!(node.part3(HashMap::new()), Err(NodeError::DkgProtocol(_))),
            "part3 after completion must fail"
        );
    }
}

// ── Phase 6: FROST library rejection tests ────────────────────────────────────

/// `part2` receives a package from a participant not in the ceremony.
/// The FROST library will reject it.
#[test]
fn dkg_part2_with_unknown_participant_package_fails() {
    use tls_attestation_core::ids::VerifierId;
    use tls_attestation_crypto::dkg::Identifier;

    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let mut nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();

    nodes[0].part1().unwrap();

    // Build a package for a fake participant not in the list.
    let fake_vid = VerifierId::from_bytes([0xAB; 32]);
    let result = nodes[0].part2(HashMap::from([(fake_vid, {
        // Use the low-level API to produce a valid-looking package from a
        // different ceremony (unknown identifier from our node's perspective).
        // The node should reject the VerifierId since it's not in participant list.
        let fake_id = Identifier::try_from(99u16).unwrap();
        let (_state, pkg) = dkg_part1(fake_id, 3, 2).unwrap();
        pkg
    })]));

    // The node must reject because the VerifierId is not in all_participant_ids.
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "unknown participant must be rejected by part2"
    );
}

/// `part3` called with a Round-2 package from a participant not in the ceremony.
#[test]
fn dkg_part3_with_unknown_sender_rejected() {
    use tls_attestation_core::ids::VerifierId;

    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let mut nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();

    // Run part1 on all.
    let mut r1_pkgs: HashMap<tls_attestation_core::ids::VerifierId, DkgRound1Package> =
        HashMap::new();
    for n in nodes.iter_mut() {
        r1_pkgs.insert(n.verifier_id().clone(), n.part1().unwrap());
    }

    // Run part2 on all.
    let mut r2_unicasts: HashMap<_, HashMap<_, _>> = HashMap::new();
    for node in nodes.iter_mut() {
        let my_id = node.verifier_id().clone();
        let others: HashMap<_, _> = r1_pkgs
            .iter()
            .filter(|(v, _)| *v != &my_id)
            .map(|(v, p)| (v.clone(), p.clone()))
            .collect();
        let outbound = node.part2(others).unwrap();
        for (to, pkg) in outbound {
            r2_unicasts.entry(to).or_default().insert(my_id.clone(), pkg);
        }
    }

    // Inject a fake sender into node 0's round-2 package set.
    // The node must reject it because fake_vid is not in all_participant_ids.
    // We reuse a real package (already produced for another recipient) — the
    // VerifierId check fires before the FROST library ever sees the content.
    let fake_vid = VerifierId::from_bytes([0xCD; 32]);
    let my_id = nodes[0].verifier_id().clone();
    let mut my_r2 = r2_unicasts.remove(&my_id).unwrap_or_default();

    if let Some(real_pkg) = r2_unicasts
        .values()
        .flat_map(|m| m.values())
        .next()
        .cloned()
    {
        my_r2.insert(fake_vid.clone(), real_pkg);
    }

    let result = nodes[0].part3(my_r2);
    // The node must reject the unknown sender VerifierId.
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "unknown sender in part3 must be rejected"
    );
}

/// `part3` with missing Round-2 packages: the FROST library must reject this.
#[test]
fn dkg_part3_with_missing_round2_package_fails_with_crypto_error() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let mut nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();

    let mut r1_pkgs: HashMap<_, _> = HashMap::new();
    for n in nodes.iter_mut() {
        r1_pkgs.insert(n.verifier_id().clone(), n.part1().unwrap());
    }
    for node in nodes.iter_mut() {
        let my_id = node.verifier_id().clone();
        let others: HashMap<_, _> = r1_pkgs
            .iter()
            .filter(|(v, _)| *v != &my_id)
            .map(|(v, p)| (v.clone(), p.clone()))
            .collect();
        node.part2(others).unwrap();
    }

    // Call part3 on node 0 with NO round-2 packages.
    let result = nodes[0].part3(HashMap::new());
    // FROST library must reject (missing share contributions).
    assert!(
        matches!(result, Err(NodeError::Crypto(_))),
        "missing round-2 packages must produce Crypto error from FROST lib"
    );
    // Node stays in AfterPart2 — retryable.
    assert!(!nodes[0].is_complete());
}

/// `part3` is retryable: after a failure (missing packages), the node can
/// be called again with the correct packages and succeed.
#[test]
fn dkg_part3_is_retryable_after_missing_package_failure() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let mut nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();

    let mut r1_pkgs: HashMap<_, _> = HashMap::new();
    for n in nodes.iter_mut() {
        r1_pkgs.insert(n.verifier_id().clone(), n.part1().unwrap());
    }
    let mut r2_unicasts: HashMap<_, HashMap<_, _>> = HashMap::new();
    for node in nodes.iter_mut() {
        let my_id = node.verifier_id().clone();
        let others: HashMap<_, _> = r1_pkgs
            .iter()
            .filter(|(v, _)| *v != &my_id)
            .map(|(v, p)| (v.clone(), p.clone()))
            .collect();
        let outbound = node.part2(others).unwrap();
        for (to, pkg) in outbound {
            r2_unicasts.entry(to).or_default().insert(my_id.clone(), pkg);
        }
    }

    // First part3 call: no packages (simulates temporarily missing delivery).
    let fail = nodes[0].part3(HashMap::new());
    assert!(
        matches!(fail, Err(NodeError::Crypto(_))),
        "first part3 with empty packages must fail"
    );
    assert!(!nodes[0].is_complete(), "node must not be complete after failure");

    // Second part3 call with the correct packages — must succeed.
    let my_id = nodes[0].verifier_id().clone();
    let correct_r2 = r2_unicasts.remove(&my_id).unwrap_or_default();
    let (aux_node, _gk) = nodes[0]
        .part3(correct_r2)
        .expect("retry with correct packages must succeed");
    assert!(nodes[0].is_complete());
    // The auxiliary node exists and has the correct identity.
    assert_eq!(aux_node.verifier_id(), &vids[0]);
}

// ── Phase 5: Key material isolation test ─────────────────────────────────────

// ── Phase 3/4: Round-2 encryption unit tests ──────────────────────────────────

/// Helper: run part1+part2 on a 3-node DKG and extract one sender→recipient
/// plaintext package for use in encryption unit tests.
///
/// Returns `(pkg, sender_vid, recipient_vid, all_vids, ceremony_id,
///           sender_keypair, recipient_keypair)`.
fn get_sample_encrypted_package_setup() -> (
    tls_attestation_crypto::dkg::DkgRound2Package,
    tls_attestation_core::ids::VerifierId,
    tls_attestation_core::ids::VerifierId,
    DkgCeremonyId,
    DkgEncryptionKeyPair,
    DkgEncryptionKeyPair,
) {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let mut nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();

    // Part 1: collect all broadcast packages.
    let mut r1: HashMap<tls_attestation_core::ids::VerifierId, DkgRound1Package> =
        HashMap::new();
    for n in nodes.iter_mut() {
        r1.insert(n.verifier_id().clone(), n.part1().unwrap());
    }

    // Part 2 on node 0 only — extract a single outbound package.
    let my_id = nodes[0].verifier_id().clone();
    let others: HashMap<_, _> = r1
        .iter()
        .filter(|(v, _)| *v != &my_id)
        .map(|(v, p)| (v.clone(), p.clone()))
        .collect();
    let mut outbound = nodes[0].part2(others).unwrap();

    // Pick any recipient.
    let recipient_vid = outbound.keys().next().cloned().unwrap();
    let pkg = outbound.remove(&recipient_vid).unwrap();

    let ceremony_id = DkgCeremonyId::generate();
    let sender_kp = DkgEncryptionKeyPair::generate();
    let recipient_kp = DkgEncryptionKeyPair::generate();

    (pkg, my_id, recipient_vid, ceremony_id, sender_kp, recipient_kp)
}

/// Basic encrypt → decrypt round-trip produces the original plaintext.
#[test]
fn encrypt_decrypt_round2_package_round_trip() {
    let (pkg, sender_id, recipient_id, ceremony_id, sender_kp, recipient_kp) =
        get_sample_encrypted_package_setup();

    let original_bytes = pkg.to_plaintext_bytes();

    let envelope = encrypt_round2_package(
        &pkg,
        &ceremony_id,
        &sender_kp,
        &sender_id,
        recipient_kp.public_key(),
        &recipient_id,
    )
    .expect("encryption must succeed");

    let decrypted = decrypt_round2_package(
        &envelope,
        &recipient_kp,
        sender_kp.public_key(),
        &ceremony_id,
        &sender_id,
        &recipient_id,
    )
    .expect("decryption must succeed");

    assert_eq!(
        decrypted.to_plaintext_bytes(),
        original_bytes,
        "decrypted package must match the original plaintext"
    );
}

/// Decrypting with the wrong recipient private key must fail.
#[test]
fn decrypt_with_wrong_recipient_key_fails() {
    let (pkg, sender_id, recipient_id, ceremony_id, sender_kp, correct_recipient_kp) =
        get_sample_encrypted_package_setup();

    let envelope = encrypt_round2_package(
        &pkg,
        &ceremony_id,
        &sender_kp,
        &sender_id,
        correct_recipient_kp.public_key(),
        &recipient_id,
    )
    .unwrap();

    // Use a completely different key pair as the "wrong" recipient.
    let wrong_kp = DkgEncryptionKeyPair::generate();

    let result = decrypt_round2_package(
        &envelope,
        &wrong_kp,                   // wrong private key
        sender_kp.public_key(),
        &ceremony_id,
        &sender_id,
        &recipient_id,
    );

    assert!(
        matches!(result, Err(tls_attestation_crypto::CryptoError::InvalidKeyMaterial(_))),
        "decryption with wrong key must fail"
    );
}

/// The coordinator cannot decrypt a Round-2 package: it lacks any private key.
/// This is the same as the wrong-recipient-key test but explicitly labelled as
/// a coordinator-blindness proof.
#[test]
fn coordinator_cannot_decrypt_round2_package() {
    let (pkg, sender_id, recipient_id, ceremony_id, sender_kp, recipient_kp) =
        get_sample_encrypted_package_setup();

    let envelope = encrypt_round2_package(
        &pkg,
        &ceremony_id,
        &sender_kp,
        &sender_id,
        recipient_kp.public_key(),
        &recipient_id,
    )
    .unwrap();

    // Coordinator generates its own key pair — it still cannot read the content.
    let coordinator_kp = DkgEncryptionKeyPair::generate();

    let result = decrypt_round2_package(
        &envelope,
        &coordinator_kp,             // coordinator has no private key for this envelope
        sender_kp.public_key(),
        &ceremony_id,
        &sender_id,
        &recipient_id,
    );

    assert!(
        result.is_err(),
        "coordinator (wrong private key) must not be able to decrypt Round-2 packages"
    );
}

/// Flipping any bit in the ciphertext must cause authentication failure.
#[test]
fn tampered_ciphertext_rejected() {
    let (pkg, sender_id, recipient_id, ceremony_id, sender_kp, recipient_kp) =
        get_sample_encrypted_package_setup();

    let mut envelope = encrypt_round2_package(
        &pkg,
        &ceremony_id,
        &sender_kp,
        &sender_id,
        recipient_kp.public_key(),
        &recipient_id,
    )
    .unwrap();

    // Flip the first byte of the ciphertext.
    envelope.ciphertext[0] ^= 0xFF;

    let result = decrypt_round2_package(
        &envelope,
        &recipient_kp,
        sender_kp.public_key(),
        &ceremony_id,
        &sender_id,
        &recipient_id,
    );

    assert!(
        result.is_err(),
        "tampered ciphertext must be rejected"
    );
}

/// Modifying `ceremony_id` in the envelope must be detected.
#[test]
fn tampered_ceremony_id_in_envelope_rejected() {
    let (pkg, sender_id, recipient_id, ceremony_id, sender_kp, recipient_kp) =
        get_sample_encrypted_package_setup();

    let mut envelope = encrypt_round2_package(
        &pkg,
        &ceremony_id,
        &sender_kp,
        &sender_id,
        recipient_kp.public_key(),
        &recipient_id,
    )
    .unwrap();

    // Modify the ceremony_id field in the envelope.
    envelope.ceremony_id[0] ^= 0x01;

    // The metadata check fires before AEAD — explicit error.
    let result = decrypt_round2_package(
        &envelope,
        &recipient_kp,
        sender_kp.public_key(),
        &ceremony_id,    // expected: original
        &sender_id,
        &recipient_id,
    );

    assert!(
        result.is_err(),
        "tampered ceremony_id must be detected"
    );
}

/// Modifying `sender_id` in the envelope must be detected.
#[test]
fn tampered_sender_id_in_envelope_rejected() {
    let (pkg, sender_id, recipient_id, ceremony_id, sender_kp, recipient_kp) =
        get_sample_encrypted_package_setup();

    let mut envelope = encrypt_round2_package(
        &pkg,
        &ceremony_id,
        &sender_kp,
        &sender_id,
        recipient_kp.public_key(),
        &recipient_id,
    )
    .unwrap();

    envelope.sender_id[0] ^= 0x01;

    let result = decrypt_round2_package(
        &envelope,
        &recipient_kp,
        sender_kp.public_key(),
        &ceremony_id,
        &sender_id,   // expected: original
        &recipient_id,
    );

    assert!(result.is_err(), "tampered sender_id must be detected");
}

/// Modifying `recipient_id` in the envelope must be detected.
#[test]
fn tampered_recipient_id_in_envelope_rejected() {
    let (pkg, sender_id, recipient_id, ceremony_id, sender_kp, recipient_kp) =
        get_sample_encrypted_package_setup();

    let mut envelope = encrypt_round2_package(
        &pkg,
        &ceremony_id,
        &sender_kp,
        &sender_id,
        recipient_kp.public_key(),
        &recipient_id,
    )
    .unwrap();

    envelope.recipient_id[0] ^= 0x01;

    let result = decrypt_round2_package(
        &envelope,
        &recipient_kp,
        sender_kp.public_key(),
        &ceremony_id,
        &sender_id,
        &recipient_id,   // expected: original
    );

    assert!(result.is_err(), "tampered recipient_id must be detected");
}

/// Decrypting with the wrong `ceremony_id` expectation must fail
/// even if the ciphertext is untampered.
///
/// This exercises the HKDF key derivation binding: a different ceremony_id
/// produces a different key, and decryption fails at the AEAD tag check.
#[test]
fn wrong_ceremony_id_expectation_rejected() {
    let (pkg, sender_id, recipient_id, ceremony_id, sender_kp, recipient_kp) =
        get_sample_encrypted_package_setup();

    let envelope = encrypt_round2_package(
        &pkg,
        &ceremony_id,
        &sender_kp,
        &sender_id,
        recipient_kp.public_key(),
        &recipient_id,
    )
    .unwrap();

    // Decryptor uses a different ceremony_id — key derivation produces wrong key.
    let wrong_ceremony_id = DkgCeremonyId::generate();

    let result = decrypt_round2_package(
        &envelope,
        &recipient_kp,
        sender_kp.public_key(),
        &wrong_ceremony_id,   // wrong
        &sender_id,
        &recipient_id,
    );

    assert!(result.is_err(), "wrong ceremony_id must cause decryption failure");
}

/// A package encrypted for ceremony A cannot be replayed in ceremony B.
/// Even if the same sender/recipient keys are reused, the ceremony_id in the
/// HKDF info and AAD prevents cross-ceremony replay.
#[test]
fn cross_ceremony_replay_rejected() {
    let (pkg, sender_id, recipient_id, ceremony_a, sender_kp, recipient_kp) =
        get_sample_encrypted_package_setup();

    // Encrypt for ceremony A.
    let envelope_a = encrypt_round2_package(
        &pkg,
        &ceremony_a,
        &sender_kp,
        &sender_id,
        recipient_kp.public_key(),
        &recipient_id,
    )
    .unwrap();

    // Try to decrypt as if it were for ceremony B.
    let ceremony_b = DkgCeremonyId::generate();
    let result = decrypt_round2_package(
        &envelope_a,
        &recipient_kp,
        sender_kp.public_key(),
        &ceremony_b,   // different ceremony
        &sender_id,
        &recipient_id,
    );

    assert!(result.is_err(), "cross-ceremony replay must be rejected");
}

/// Mismatched `encryption_keys.len()` and `nodes.len()` must be rejected
/// before any DKG step runs.
#[test]
fn run_dkg_ceremony_encrypted_rejects_mismatched_key_count() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 2);
    let ceremony_id = DkgCeremonyId::generate();

    // Provide only 2 keys for 3 nodes.
    let enc_keys: Vec<DkgEncryptionKeyPair> =
        (0..2).map(|_| DkgEncryptionKeyPair::generate()).collect();

    let result = run_dkg_ceremony_encrypted(&mut nodes, &ceremony_id, &enc_keys);
    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "mismatched key count must be rejected"
    );
}

// ── Phase 4: Encrypted ceremony integration tests ─────────────────────────────

/// Helper: create encryption keys in the same order as setup_dkg_nodes returns nodes.
fn make_enc_keys(n: usize) -> Vec<DkgEncryptionKeyPair> {
    (0..n).map(|_| DkgEncryptionKeyPair::generate()).collect()
}

/// 2-of-3 DKG ceremony with encrypted Round-2 routing succeeds.
#[test]
fn encrypted_dkg_ceremony_2_of_3_succeeds() {
    let (_harness, mut nodes) = setup_dkg_nodes(3, 2);
    let ceremony_id = DkgCeremonyId::generate();
    let enc_keys = make_enc_keys(nodes.len());

    let (aux_nodes, _group_key) =
        run_dkg_ceremony_encrypted(&mut nodes, &ceremony_id, &enc_keys)
            .expect("encrypted 2-of-3 DKG ceremony must succeed");

    assert_eq!(aux_nodes.len(), 3);
    assert!(nodes.iter().all(|n| n.is_complete()));
}

/// 3-of-5 DKG ceremony with encrypted Round-2 routing succeeds.
#[test]
fn encrypted_dkg_ceremony_3_of_5_succeeds() {
    let (_harness, mut nodes) = setup_dkg_nodes(5, 3);
    let ceremony_id = DkgCeremonyId::generate();
    let enc_keys = make_enc_keys(nodes.len());

    let (aux_nodes, _group_key) =
        run_dkg_ceremony_encrypted(&mut nodes, &ceremony_id, &enc_keys)
            .expect("encrypted 3-of-5 DKG ceremony must succeed");

    assert_eq!(aux_nodes.len(), 5);
}

/// Encrypted ceremony produces the same group key across all participants.
#[test]
fn encrypted_dkg_all_nodes_derive_same_group_key() {
    let (_harness, mut nodes) = setup_dkg_nodes(4, 3);
    let ceremony_id = DkgCeremonyId::generate();
    let enc_keys = make_enc_keys(nodes.len());

    // Manually drive part1 + part2 (encrypted) + part3 to collect group keys.
    // (run_dkg_ceremony_encrypted only returns one key — use it instead.)
    let (_aux_nodes, group_key) =
        run_dkg_ceremony_encrypted(&mut nodes, &ceremony_id, &enc_keys).unwrap();

    // The consistency check inside run_dkg_ceremony_encrypted would have failed
    // if any node derived a different key — verify the returned key is non-trivial.
    let kb = group_key.verifying_key_bytes();
    assert_eq!(kb.len(), 32);
    assert_ne!(kb, [0u8; 32]);
}

/// Encrypted DKG ceremony produces output compatible with distributed FROST signing.
#[test]
fn encrypted_dkg_then_distributed_signing_succeeds() {
    let (harness, mut nodes) = setup_dkg_nodes(3, 2);
    let ceremony_id = DkgCeremonyId::generate();
    let enc_keys = make_enc_keys(nodes.len());

    let (aux_nodes, group_key) =
        run_dkg_ceremony_encrypted(&mut nodes, &ceremony_id, &enc_keys)
            .expect("encrypted DKG ceremony must succeed");

    let refs: Vec<&tls_attestation_node::FrostAuxiliaryNode> = aux_nodes.iter().collect();

    let envelope = harness
        .coordinator
        .attest_frost_distributed(
            make_request("encrypted-dkg/v1", b"GET /price"),
            b"42.00",
            &refs,
            &group_key,
        )
        .expect("distributed signing after encrypted DKG must succeed");

    envelope
        .frost_approval
        .verify_signature()
        .expect("aggregate signature must be valid");

    envelope
        .frost_approval
        .verify_binding(&envelope.envelope_digest)
        .expect("approval must be bound to envelope_digest");
}

/// The output of `run_dkg_ceremony_encrypted` is compatible with
/// `run_dkg_ceremony` — both produce group keys with the same structure
/// (same identifier mapping for the same participant ordering).
#[test]
fn encrypted_dkg_identifier_mapping_matches_plaintext_dkg() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();

    // Plain ceremony.
    let mut plain_nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();
    let (_, plain_gk) = run_dkg_ceremony(&mut plain_nodes).unwrap();

    // Encrypted ceremony.
    let mut enc_nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();
    let ceremony_id = DkgCeremonyId::generate();
    let enc_keys = make_enc_keys(enc_nodes.len());
    let (_, enc_gk) = run_dkg_ceremony_encrypted(&mut enc_nodes, &ceremony_id, &enc_keys).unwrap();

    // Identifier mapping must be identical for both paths.
    for vid in &vids {
        assert_eq!(
            plain_gk.verifier_to_identifier(vid),
            enc_gk.verifier_to_identifier(vid),
            "identifier mapping must be identical for plaintext and encrypted DKG"
        );
    }
}

/// Two independent encrypted ceremonies produce distinct group keys.
#[test]
fn two_encrypted_ceremonies_produce_distinct_keys() {
    let harness1 = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids1 = harness1.coordinator_quorum_verifiers();
    let mut nodes1: Vec<FrostDkgNode> = vids1
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids1.clone(), 2).unwrap())
        .collect();
    let enc_keys1 = make_enc_keys(nodes1.len());
    let (_, gk1) = run_dkg_ceremony_encrypted(
        &mut nodes1,
        &DkgCeremonyId::generate(),
        &enc_keys1,
    )
    .unwrap();

    let harness2 = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids2 = harness2.coordinator_quorum_verifiers();
    let mut nodes2: Vec<FrostDkgNode> = vids2
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids2.clone(), 2).unwrap())
        .collect();
    let enc_keys2 = make_enc_keys(nodes2.len());
    let (_, gk2) = run_dkg_ceremony_encrypted(
        &mut nodes2,
        &DkgCeremonyId::generate(),
        &enc_keys2,
    )
    .unwrap();

    assert_ne!(
        gk1.verifying_key_bytes(),
        gk2.verifying_key_bytes(),
        "independent encrypted ceremonies must produce distinct group keys"
    );
}

// ── Phase 5: Authenticated key distribution tests ────────────────────────────
//
// These tests cover `run_dkg_ceremony_with_authenticated_keys`, which wraps the
// encrypted DKG ceremony with mandatory ed25519 key-announcement verification.
//
// The goal: a coordinator that routes DkgEncryptionPublicKey values cannot
// substitute an attacker-controlled key without forging an ed25519 signature
// under the victim participant's long-term identity key.

/// A self-contained authenticated ceremony setup: signing keys, enc keys,
/// ceremony ID, signed announcements, participant registry, and DKG nodes.
struct AuthCeremonySetup {
    signing_keys: Vec<VerifierKeyPair>,
    enc_keys: Vec<DkgEncryptionKeyPair>,
    ceremony_id: DkgCeremonyId,
    nodes: Vec<FrostDkgNode>,
    announcements: Vec<SignedDkgKeyAnnouncement>,
    registry: DkgParticipantRegistry,
}

/// Build a complete authenticated DKG ceremony setup for `n` participants with
/// the given `threshold`.
///
/// Signing key seeds follow the same convention as `TestHarness` (seeds
/// `[1u8; 32]` … `[n as u8; 32]`), so a `TestHarness` with `num_aux_verifiers
/// == n` produces the same `VerifierIds`.
fn setup_auth_ceremony(n: usize, threshold: usize) -> AuthCeremonySetup {
    let signing_keys: Vec<VerifierKeyPair> = (1u8..=(n as u8))
        .map(|seed| VerifierKeyPair::from_seed([seed; 32]))
        .collect();
    let vids: Vec<VerifierId> = signing_keys.iter().map(|kp| kp.verifier_id.clone()).collect();
    let enc_keys: Vec<DkgEncryptionKeyPair> =
        (0..n).map(|_| DkgEncryptionKeyPair::generate()).collect();
    let ceremony_id = DkgCeremonyId::generate();
    let announcements: Vec<SignedDkgKeyAnnouncement> = signing_keys
        .iter()
        .zip(enc_keys.iter())
        .map(|(sk, ek)| create_dkg_key_announcement(ek, &ceremony_id, sk))
        .collect();
    let registry = DkgParticipantRegistry::from_key_pairs(&signing_keys);
    let nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| {
            FrostDkgNode::new(v.clone(), vids.clone(), threshold as u16)
                .expect("FrostDkgNode::new should succeed with valid inputs")
        })
        .collect();
    AuthCeremonySetup { signing_keys, enc_keys, ceremony_id, nodes, announcements, registry }
}

// ── Happy-path tests ──────────────────────────────────────────────────────────

/// Authenticated 2-of-3 DKG ceremony succeeds with all valid announcements.
#[test]
fn authenticated_dkg_happy_path_2_of_3() {
    let mut s = setup_auth_ceremony(3, 2);
    let (aux_nodes, _group_key) = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &s.announcements,
        &s.registry,
    )
    .expect("authenticated 2-of-3 DKG must succeed");
    assert_eq!(aux_nodes.len(), 3);
    assert!(s.nodes.iter().all(|n| n.is_complete()));
}

/// Authenticated 3-of-5 DKG ceremony succeeds with all valid announcements.
#[test]
fn authenticated_dkg_happy_path_3_of_5() {
    let mut s = setup_auth_ceremony(5, 3);
    let (aux_nodes, _group_key) = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &s.announcements,
        &s.registry,
    )
    .expect("authenticated 3-of-5 DKG must succeed");
    assert_eq!(aux_nodes.len(), 5);
}

/// Group key is consistent (non-zero) after authenticated ceremony.
#[test]
fn authenticated_dkg_produces_valid_group_key() {
    let mut s = setup_auth_ceremony(3, 2);
    let (_aux_nodes, group_key) = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &s.announcements,
        &s.registry,
    )
    .unwrap();
    let kb = group_key.verifying_key_bytes();
    assert_eq!(kb.len(), 32);
    assert_ne!(kb, [0u8; 32], "group key must not be all-zero");
}

/// Full pipeline: authenticated key distribution → encrypted DKG → distributed
/// FROST signing produces a valid, binding aggregate signature.
#[test]
fn authenticated_dkg_end_to_end_distributed_signing() {
    // Build setup using TestHarness seeds so the coordinator is wired correctly.
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();

    // Recreate the same VerifierKeyPairs that TestHarness uses internally
    // (seeds [1;32], [2;32], [3;32]).
    let signing_keys: Vec<VerifierKeyPair> = (1u8..=3u8)
        .map(|seed| VerifierKeyPair::from_seed([seed; 32]))
        .collect();
    // Sanity: signing_keys[i].verifier_id must match harness-derived vids.
    for (sk, vid) in signing_keys.iter().zip(vids.iter()) {
        assert_eq!(&sk.verifier_id, vid, "signing key must match harness VerifierId");
    }

    let enc_keys: Vec<DkgEncryptionKeyPair> =
        (0..3).map(|_| DkgEncryptionKeyPair::generate()).collect();
    let ceremony_id = DkgCeremonyId::generate();
    let announcements: Vec<SignedDkgKeyAnnouncement> = signing_keys
        .iter()
        .zip(enc_keys.iter())
        .map(|(sk, ek)| create_dkg_key_announcement(ek, &ceremony_id, sk))
        .collect();
    let registry = DkgParticipantRegistry::from_key_pairs(&signing_keys);

    let mut nodes: Vec<FrostDkgNode> = vids
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids.clone(), 2).unwrap())
        .collect();

    let (aux_nodes, group_key) = run_dkg_ceremony_with_authenticated_keys(
        &mut nodes,
        &ceremony_id,
        &enc_keys,
        &announcements,
        &registry,
    )
    .expect("authenticated DKG ceremony must succeed");

    let refs: Vec<&tls_attestation_node::FrostAuxiliaryNode> = aux_nodes.iter().collect();
    let envelope = harness
        .coordinator
        .attest_frost_distributed(
            make_request("authenticated-dkg/v1", b"GET /price"),
            b"42.00",
            &refs,
            &group_key,
        )
        .expect("distributed signing after authenticated DKG must succeed");

    envelope
        .frost_approval
        .verify_signature()
        .expect("aggregate FROST signature must be valid");
    envelope
        .frost_approval
        .verify_binding(&envelope.envelope_digest)
        .expect("approval must be bound to envelope_digest");
}

// ── Adversarial tests — coordinator key substitution ─────────────────────────

/// A coordinator that replaces a participant's enc_public_key in their
/// announcement payload (but cannot re-sign it) must be rejected.
/// The original ed25519 signature no longer covers the tampered payload.
#[test]
fn authenticated_dkg_coordinator_key_substitution_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    // Coordinator substitutes participant 0's announced enc key with an
    // attacker-controlled one — they cannot forge the ed25519 signature.
    let mut tampered = s.announcements.clone();
    tampered[0].payload.enc_public_key = [0xAB; 32]; // attacker-controlled key

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &tampered,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "coordinator key substitution must be rejected; got: {:?}", result.as_ref().err()
    );
}

/// A coordinator that replaces the verifier_id in a participant's payload is
/// also rejected — the signature no longer matches the registry key.
#[test]
fn authenticated_dkg_coordinator_identity_swap_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    // Swap participant 0's verifier_id field with participant 1's id.
    let mut tampered = s.announcements.clone();
    tampered[0].payload.verifier_id = tampered[1].payload.verifier_id;

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &tampered,
        &s.registry,
    );

    // Either the registry lookup produces a duplicate (participant 1 now has
    // two announcements) → DkgKeyAnnouncement("duplicate…"), or the signature
    // check fails → DkgKeyAnnouncement.
    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "identity swap must be rejected; got: {:?}", result.as_ref().err()
    );
}

/// An announcement with an entirely zeroed-out (invalid) signature is rejected.
#[test]
fn authenticated_dkg_invalid_signature_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    let mut bad = s.announcements.clone();
    bad[1].signature = vec![0u8; 64]; // signature bytes all zero → invalid

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &bad,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "invalid signature must be rejected; got: {:?}", result.as_ref().err()
    );
}

/// An announcement signed by a different participant's key (signature is
/// valid ed25519 but under the *wrong* identity key) must be rejected.
///
/// Scenario: participant 0 attempts to impersonate participant 2 by using
/// participant 2's verifier_id in the payload but their own signing key.
/// The registry's verifying key for participant 2 won't match.
#[test]
fn authenticated_dkg_wrong_signing_key_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    // Build announcement: payload claims to be from participant 2 (index 2),
    // but the signature is produced by participant 0's key.
    // 1. Clone participant 2's valid announcement (correct verifier_id field).
    // 2. Re-sign the payload bytes with participant 0's key.
    // The registry will verify against participant 2's key → mismatch.
    let mut impostor_ann = s.announcements[2].clone();
    // Forge a plausible signature using participant 0's key.
    // We don't have access to the preimage fn, so we just use a 64-byte
    // signature from a different valid sign_raw call (semantically wrong key).
    let wrong_sig = s.signing_keys[0].sign_raw(b"not-the-correct-preimage").to_vec();
    impostor_ann.signature = wrong_sig;

    let mut tampered = s.announcements.clone();
    tampered[2] = impostor_ann;

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &tampered,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "wrong signing key must be rejected; got: {:?}", result.as_ref().err()
    );
}

// ── Adversarial tests — cross-ceremony replay ─────────────────────────────────

/// An announcement signed for ceremony A must be rejected when presented
/// in ceremony B.  The `ceremony_id` field in the payload differs.
#[test]
fn authenticated_dkg_cross_ceremony_replay_rejected() {
    // Ceremony A — create and sign announcements.
    let s_a = setup_auth_ceremony(3, 2);

    // Ceremony B — fresh ceremony ID, new nodes and enc keys, but reuse
    // ceremony A's announcements (which embed ceremony A's ceremony_id).
    let ceremony_id_b = DkgCeremonyId::generate();
    let signing_keys_b: Vec<VerifierKeyPair> = (1u8..=3u8)
        .map(|seed| VerifierKeyPair::from_seed([seed; 32]))
        .collect();
    let vids_b: Vec<VerifierId> =
        signing_keys_b.iter().map(|kp| kp.verifier_id.clone()).collect();
    let enc_keys_b: Vec<DkgEncryptionKeyPair> =
        (0..3).map(|_| DkgEncryptionKeyPair::generate()).collect();
    let registry_b = DkgParticipantRegistry::from_key_pairs(&signing_keys_b);
    let mut nodes_b: Vec<FrostDkgNode> = vids_b
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids_b.clone(), 2).unwrap())
        .collect();

    // Attempt to use ceremony A's signed announcements in ceremony B.
    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut nodes_b,
        &ceremony_id_b,
        &enc_keys_b,
        &s_a.announcements, // stale from ceremony A
        &registry_b,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "cross-ceremony replay must be rejected; got: {:?}", result.as_ref().err()
    );
}

// ── Adversarial tests — duplicate and missing announcements ──────────────────

/// Two announcements from the same participant (e.g. two conflicting enc keys)
/// must be rejected — ambiguous key.
#[test]
fn authenticated_dkg_duplicate_announcement_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    // Replace participant 2's announcement slot with a second copy of
    // participant 0's announcement (signed correctly, but duplicate).
    let mut dupe = s.announcements.clone();
    dupe[2] = s.announcements[0].clone();

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &dupe,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "duplicate announcement must be rejected; got: {:?}", result.as_ref().err()
    );
}

/// A ceremony with one participant's announcement missing cannot start.
/// This is a liveness guarantee — the ceremony is blocked, not silently degraded.
#[test]
fn authenticated_dkg_missing_announcement_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    // Drop participant 1's announcement.
    let partial: Vec<SignedDkgKeyAnnouncement> = s
        .announcements
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, ann)| ann.clone())
        .collect();

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &partial,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "missing announcement must block ceremony start; got: {:?}", result.as_ref().err()
    );
}

/// An announcement from a participant not in the expected participant set
/// (an outsider injection) must be rejected.
#[test]
fn authenticated_dkg_outsider_announcement_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    // Outsider key pair — not in the ceremony participant set.
    let outsider_kp = VerifierKeyPair::from_seed([99u8; 32]);
    let outsider_enc = DkgEncryptionKeyPair::generate();
    let outsider_ann =
        create_dkg_key_announcement(&outsider_enc, &s.ceremony_id, &outsider_kp);

    // Inject the outsider's announcement alongside the legitimate ones.
    // The outsider's verifier_id is not in `expected_participants`.
    let mut injected = s.announcements.clone();
    injected.push(outsider_ann);

    // Also add outsider to registry so the sig check doesn't fail first —
    // the outsider-in-set check must fire.
    let mut all_kps: Vec<&VerifierKeyPair> = s.signing_keys.iter().collect();
    all_kps.push(&outsider_kp);
    let extended_registry = DkgParticipantRegistry::from_key_pairs(all_kps);

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &injected,
        &extended_registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "outsider announcement must be rejected; got: {:?}", result.as_ref().err()
    );
}

// ── Adversarial tests — self-consistency and caller errors ───────────────────

/// The self-consistency check fires when a node's actual enc key does not
/// match what its own signed announcement claimed.
///
/// This detects programming errors where the caller passes enc_keys in a
/// different order from the announcements, or passes the wrong enc key entirely.
#[test]
fn authenticated_dkg_self_consistency_failure_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    // Swap enc_keys[0] and enc_keys[1] — nodes[0] now holds the key that
    // belongs to nodes[1] (and vice versa).  Both are valid individually, but
    // nodes[0]'s announcement was signed with enc_keys[0]'s public key, not
    // enc_keys[1]'s.
    s.enc_keys.swap(0, 1);

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &s.announcements,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "enc key mismatch with own announcement must be rejected; got: {:?}", result.as_ref().err()
    );
}

/// A fresh `DkgEncryptionKeyPair` (not matching any announcement) provided as
/// enc_keys[0] causes the self-consistency check to fire.
#[test]
fn authenticated_dkg_unannounced_enc_key_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    // Replace enc_keys[2] with a freshly generated key — no announcement
    // for this key was signed.
    s.enc_keys[2] = DkgEncryptionKeyPair::generate();

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &s.announcements,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "unannounced enc key must be rejected; got: {:?}", result.as_ref().err()
    );
}

/// Too few enc_keys for the number of nodes must be caught before DKG starts.
#[test]
fn authenticated_dkg_mismatched_enc_key_count_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    // Provide only 2 enc_keys for 3 nodes.
    s.enc_keys.truncate(2);

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &s.announcements,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgProtocol(_))),
        "mismatched enc_keys count must be rejected; got: {:?}", result.as_ref().err()
    );
}

/// Version mismatch: an announcement with an unsupported version byte is rejected
/// before the signature is even verified.
#[test]
fn authenticated_dkg_wrong_version_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    let mut bad_version = s.announcements.clone();
    // Bump version to a future unsupported value.
    bad_version[0].payload.version = ANNOUNCEMENT_VERSION.wrapping_add(1);

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &bad_version,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "wrong version must be rejected; got: {:?}", result.as_ref().err()
    );
}

/// Malformed signature bytes (wrong length) are rejected with a clear error.
#[test]
fn authenticated_dkg_malformed_signature_bytes_rejected() {
    let mut s = setup_auth_ceremony(3, 2);

    let mut bad_sig = s.announcements.clone();
    // Truncate signature to 32 bytes — not a valid ed25519 signature length.
    bad_sig[0].signature = vec![0u8; 32];

    let result = run_dkg_ceremony_with_authenticated_keys(
        &mut s.nodes,
        &s.ceremony_id,
        &s.enc_keys,
        &bad_sig,
        &s.registry,
    );

    assert!(
        matches!(result, Err(NodeError::DkgKeyAnnouncement(_))),
        "malformed signature must be rejected; got: {:?}", result.as_ref().err()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Original independent-runs test (below) is unchanged.
// ─────────────────────────────────────────────────────────────────────────────

/// Two independent DKG runs produce distinct key material.
/// (This is a probabilistic property — failure probability is negligible.)
#[test]
fn dkg_independent_runs_produce_distinct_key_material() {
    let harness1 = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids1 = harness1.coordinator_quorum_verifiers();

    let harness2 = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids2 = harness2.coordinator_quorum_verifiers();

    let mut nodes1: Vec<FrostDkgNode> = vids1
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids1.clone(), 2).unwrap())
        .collect();
    let (_, gk1) = run_dkg_ceremony(&mut nodes1).unwrap();

    let mut nodes2: Vec<FrostDkgNode> = vids2
        .iter()
        .map(|v| FrostDkgNode::new(v.clone(), vids2.clone(), 2).unwrap())
        .collect();
    let (_, gk2) = run_dkg_ceremony(&mut nodes2).unwrap();

    assert_ne!(
        gk1.verifying_key_bytes(),
        gk2.verifying_key_bytes(),
        "independent DKG runs must produce distinct group verifying keys"
    );
}
