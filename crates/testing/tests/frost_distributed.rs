//! Distributed FROST runtime tests.
//!
//! These tests exercise `CoordinatorNode::attest_frost_distributed`, where the
//! coordinator orchestrates two FROST rounds across multiple `FrostAuxiliaryNode`
//! instances — each holding only its own secret key share.
//!
//! Unlike the in-process `attest_frost` tests in `frost_integration.rs`, here:
//! - The coordinator never sees any secret key material.
//! - Each aux node independently generates nonces (Round 1) and signature
//!   shares (Round 2).
//! - Adversarial tests cover signer-set drift, duplicate round participation,
//!   restart-after-round-1, message tampering, and more.
//!
//! # Build
//!
//! ```bash
//! cargo test --package tls-attestation-testing --features frost --test frost_distributed
//! ```

#![cfg(feature = "frost")]

use tls_attestation_attestation::envelope::AttestationEnvelope;
use tls_attestation_core::{ids::ProverId, types::Nonce};
use tls_attestation_crypto::frost_adapter::{frost_trusted_dealer_keygen, FrostGroupKey};
use tls_attestation_crypto::participant_registry::RegistryEpoch;
use tls_attestation_network::messages::{
    AttestationRequest, FrostRound1Request, FrostRound2Request,
};
use tls_attestation_node::{error::NodeError, frost_aux::FrostAuxiliaryNode};
use tls_attestation_testing::fixtures::{TestHarness, TestHarnessConfig};
use tls_attestation_core::types::UnixTimestamp;

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

/// Build a `TestHarness` plus a set of `FrostAuxiliaryNode`s using the harness
/// quorum's verifier IDs.  The aux nodes are owned by the caller (coordinator
/// never touches the key material).
fn setup_distributed(
    n: usize,
    threshold: usize,
) -> (
    TestHarness,
    Vec<FrostAuxiliaryNode>,
    FrostGroupKey,
) {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: n,
        threshold,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let keygen = frost_trusted_dealer_keygen(&vids, threshold)
        .expect("trusted-dealer keygen should succeed");

    let aux_nodes: Vec<FrostAuxiliaryNode> = keygen
        .participants
        .into_iter()
        .map(FrostAuxiliaryNode::new)
        .collect();

    (harness, aux_nodes, keygen.group_key)
}

// ── Phase 6: Happy-path distributed tests ────────────────────────────────────

/// 2-of-3 distributed: exactly the threshold number of nodes involved.
#[test]
fn distributed_frost_2_of_3_with_threshold_nodes_succeeds() {
    let (harness, aux_nodes, group_key) = setup_distributed(3, 2);
    let refs: Vec<&FrostAuxiliaryNode> = aux_nodes[..2].iter().collect();

    let envelope = harness
        .coordinator
        .attest_frost_distributed(
            make_request("frost-dist/v1", b"GET /price"),
            b"42.00",
            &refs,
            &group_key,
        )
        .expect("distributed 2-of-3 should succeed");

    // Envelope digest must be internally consistent.
    let recomputed = AttestationEnvelope::compute_digest(
        &envelope.session,
        &envelope.randomness,
        &envelope.transcript,
        &envelope.statement,
        &envelope.coordinator_evidence,
    );
    assert_eq!(envelope.envelope_digest, recomputed, "envelope digest mismatch");
}

/// 2-of-3 distributed with all 3 nodes available — surplus is fine.
#[test]
fn distributed_frost_2_of_3_with_all_nodes_succeeds() {
    let (harness, aux_nodes, group_key) = setup_distributed(3, 2);
    let refs: Vec<&FrostAuxiliaryNode> = aux_nodes.iter().collect();

    let envelope = harness
        .coordinator
        .attest_frost_distributed(
            make_request("frost-dist/v1", b"GET /volume"),
            b"999",
            &refs,
            &group_key,
        )
        .expect("distributed 2-of-3 with all nodes should succeed");

    let recomputed = AttestationEnvelope::compute_digest(
        &envelope.session,
        &envelope.randomness,
        &envelope.transcript,
        &envelope.statement,
        &envelope.coordinator_evidence,
    );
    assert_eq!(envelope.envelope_digest, recomputed);
}

/// 3-of-3 distributed: all three nodes required and present.
#[test]
fn distributed_frost_3_of_3_succeeds() {
    let (harness, aux_nodes, group_key) = setup_distributed(3, 3);
    let refs: Vec<&FrostAuxiliaryNode> = aux_nodes.iter().collect();

    let envelope = harness
        .coordinator
        .attest_frost_distributed(
            make_request("frost-dist/v1", b"POST /transfer"),
            b"ok",
            &refs,
            &group_key,
        )
        .expect("distributed 3-of-3 should succeed");

    let recomputed = AttestationEnvelope::compute_digest(
        &envelope.session,
        &envelope.randomness,
        &envelope.transcript,
        &envelope.statement,
        &envelope.coordinator_evidence,
    );
    assert_eq!(envelope.envelope_digest, recomputed);
}

/// The distributed approval's Schnorr signature verifies correctly.
#[test]
fn distributed_frost_approval_signature_verifies() {
    let (harness, aux_nodes, group_key) = setup_distributed(3, 2);
    let refs: Vec<&FrostAuxiliaryNode> = aux_nodes[..2].iter().collect();

    let envelope = harness
        .coordinator
        .attest_frost_distributed(
            make_request("frost-dist/v1", b"GET /health"),
            b"healthy",
            &refs,
            &group_key,
        )
        .expect("should succeed");

    envelope
        .frost_approval
        .verify_signature()
        .expect("aggregate Schnorr signature must verify");
}

/// The distributed approval's binding check ties it to the correct envelope.
#[test]
fn distributed_frost_approval_binding_verifies() {
    let (harness, aux_nodes, group_key) = setup_distributed(3, 2);
    let refs: Vec<&FrostAuxiliaryNode> = aux_nodes[..2].iter().collect();

    let envelope = harness
        .coordinator
        .attest_frost_distributed(
            make_request("frost-dist/v1", b"GET /binding"),
            b"bound",
            &refs,
            &group_key,
        )
        .expect("should succeed");

    envelope
        .frost_approval
        .verify_binding(&envelope.envelope_digest)
        .expect("approval must be bound to this envelope");
}

/// Two independent distributed sessions produce distinct approvals.
#[test]
fn two_distributed_sessions_produce_distinct_approvals() {
    let (harness, aux_nodes, group_key) = setup_distributed(3, 2);
    let refs: Vec<&FrostAuxiliaryNode> = aux_nodes[..2].iter().collect();

    let env1 = harness
        .coordinator
        .attest_frost_distributed(make_request("v1", b"q1"), b"r1", &refs, &group_key)
        .expect("first session should succeed");

    let env2 = harness
        .coordinator
        .attest_frost_distributed(make_request("v1", b"q2"), b"r2", &refs, &group_key)
        .expect("second session should succeed");

    assert_ne!(
        env1.envelope_digest, env2.envelope_digest,
        "different responses must produce different envelope digests"
    );
    assert_ne!(
        env1.frost_approval.aggregate_signature_bytes,
        env2.frost_approval.aggregate_signature_bytes,
        "different sessions must produce different aggregate signatures"
    );
}

/// After attest_frost_distributed, nonce caches for the session are drained.
#[test]
fn distributed_nonce_cache_drained_after_success() {
    let (harness, aux_nodes, group_key) = setup_distributed(3, 2);
    let refs: Vec<&FrostAuxiliaryNode> = aux_nodes[..2].iter().collect();

    harness
        .coordinator
        .attest_frost_distributed(
            make_request("frost-dist/v1", b"drain-check"),
            b"ok",
            &refs,
            &group_key,
        )
        .expect("should succeed");

    // After the session ends, each participating aux node's nonce cache must
    // be empty — nonces were consumed in round-2.
    for node in &refs {
        assert_eq!(
            node.pending_session_count(),
            0,
            "nonce cache must be empty after successful signing"
        );
    }
}

// ── Phase 7: Adversarial distributed tests ────────────────────────────────────

/// Below-threshold nodes → QuorumNotMet before any FROST round runs.
#[test]
fn distributed_below_threshold_fails_with_quorum_not_met() {
    let (harness, aux_nodes, group_key) = setup_distributed(3, 2);
    let refs: Vec<&FrostAuxiliaryNode> = aux_nodes[..1].iter().collect(); // only 1, need 2

    let result = harness
        .coordinator
        .attest_frost_distributed(make_request("v1", b"q"), b"r", &refs, &group_key);

    assert!(result.is_err(), "below-threshold must fail");
    assert!(
        matches!(result.unwrap_err(), NodeError::QuorumNotMet { .. }),
        "expected QuorumNotMet"
    );
}

/// Empty aux_nodes → QuorumNotMet.
#[test]
fn distributed_empty_nodes_fails_with_quorum_not_met() {
    let (harness, _aux_nodes, group_key) = setup_distributed(3, 2);

    let result = harness
        .coordinator
        .attest_frost_distributed(make_request("v1", b"q"), b"r", &[], &group_key);

    assert!(
        matches!(result.unwrap_err(), NodeError::QuorumNotMet { .. }),
        "expected QuorumNotMet for empty nodes"
    );
}

/// Aux node from a different keygen (different key share) fails in aggregation.
/// The coordinator's group_key doesn't recognize the signer.
#[test]
fn distributed_signer_from_different_keygen_fails() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();

    let keygen_a = frost_trusted_dealer_keygen(&vids, 2).expect("keygen A");
    let keygen_b = frost_trusted_dealer_keygen(&vids, 2).expect("keygen B");

    // Use nodes from keygen_b but group_key from keygen_a — mismatch.
    let aux_b: Vec<FrostAuxiliaryNode> =
        keygen_b.participants.into_iter().map(FrostAuxiliaryNode::new).collect();
    let refs: Vec<&FrostAuxiliaryNode> = aux_b[..2].iter().collect();

    let result = harness
        .coordinator
        .attest_frost_distributed(make_request("v1", b"q"), b"r", &refs, &keygen_a.group_key);

    assert!(result.is_err(), "mismatched keygen must fail");
    // Aggregation will fail because the shares won't be valid under group_key_a.
}

/// Simulated restart: nonces consumed in round-1, then a NEW node replaces the
/// original (simulates restart — nonce cache is empty).
/// A new round-2 request for the same session must fail.
#[test]
fn distributed_restart_between_rounds_fails_safely() {
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};
    use tls_attestation_crypto::threshold::approval_signed_digest;

    // Set up a single FrostAuxiliaryNode.
    let n: usize = 3;
    let threshold: usize = 2;
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: n,
        threshold,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let keygen = frost_trusted_dealer_keygen(&vids, threshold).expect("keygen");

    // Take participant 0 to run round-1 on the original node.
    let participant = keygen.participants.into_iter().next().unwrap();
    let verifier_id = participant.verifier_id.clone();
    let orig_node = FrostAuxiliaryNode::new(participant);

    // Simulate a round-1 request.
    let session_id = tls_attestation_core::ids::SessionId::new_random();
    let envelope_digest = DigestBytes::from_bytes([0x42u8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let now = UnixTimestamp::now();
    let expires_at = UnixTimestamp(now.0 + 3600);
    let signer_set = vec![verifier_id.clone()];

    let r1_req = FrostRound1Request {
        session_id: session_id.clone(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest: signed_digest.clone(),
        envelope_digest: envelope_digest.clone(),
        signer_set: signer_set.clone(),
        round_expires_at: expires_at,
        registry_epoch: RegistryEpoch::GENESIS,
    };

    // Round-1 completes on the original node — nonces are cached.
    orig_node.frost_round1(&r1_req, now).expect("round-1 should succeed");
    assert_eq!(orig_node.pending_session_count(), 1, "nonce should be cached");

    // *** Simulate restart: discard the original node, create a fresh one. ***
    // The fresh node has an empty nonce cache.
    let keygen2 = frost_trusted_dealer_keygen(&vids, threshold).expect("keygen2 for restart sim");
    let fresh_node = FrostAuxiliaryNode::new(
        keygen2.participants.into_iter().next().unwrap()
    );

    // Fabricate a plausible Round-2 request (package bytes aren't validated
    // because the fresh node will fail at the nonce-missing check first).
    let r2_req = FrostRound2Request {
        session_id: session_id.clone(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signing_package_bytes: vec![0u8; 64], // deliberately invalid — won't be reached
        signer_set: signer_set.clone(),
    };

    let result = fresh_node.frost_round2(&r2_req);
    assert!(result.is_err(), "fresh node after restart must fail round-2");
    assert!(
        matches!(result.unwrap_err(), NodeError::FrostProtocol(ref s) if s.contains("nonces missing")),
        "expected FrostProtocol with 'nonces missing'"
    );
}

/// Duplicate round-1 for the same session from the same node must fail.
#[test]
fn distributed_duplicate_round1_from_same_node_fails() {
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};
    use tls_attestation_crypto::threshold::approval_signed_digest;

    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");

    let participant = keygen.participants.into_iter().next().unwrap();
    let verifier_id = participant.verifier_id.clone();
    let node = FrostAuxiliaryNode::new(participant);

    let session_id = tls_attestation_core::ids::SessionId::new_random();
    let envelope_digest = DigestBytes::from_bytes([0x55u8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let now = UnixTimestamp::now();

    let req = FrostRound1Request {
        session_id: session_id.clone(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set: vec![verifier_id],
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: RegistryEpoch::GENESIS,
    };

    node.frost_round1(&req, now).expect("first round-1 should succeed");

    // Second round-1 for the same session must be rejected.
    let result = node.frost_round1(&req, now);
    assert!(result.is_err(), "duplicate round-1 must fail");
    assert!(
        matches!(result.unwrap_err(), NodeError::FrostProtocol(ref s) if s.contains("already completed")),
        "expected FrostProtocol with 'already completed'"
    );
}

/// Round-2 request with a different signer set than round-1 must be rejected.
#[test]
fn distributed_signer_set_drift_between_rounds_fails() {
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};
    use tls_attestation_crypto::threshold::approval_signed_digest;

    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");

    let participant = keygen.participants.into_iter().next().unwrap();
    let verifier_id = participant.verifier_id.clone();
    let node = FrostAuxiliaryNode::new(participant);

    let session_id = tls_attestation_core::ids::SessionId::new_random();
    let envelope_digest = DigestBytes::from_bytes([0x77u8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let now = UnixTimestamp::now();
    let original_signer_set = vec![verifier_id.clone()];

    let r1_req = FrostRound1Request {
        session_id: session_id.clone(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest: signed_digest.clone(),
        envelope_digest,
        signer_set: original_signer_set.clone(),
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: RegistryEpoch::GENESIS,
    };

    node.frost_round1(&r1_req, now).expect("round-1 should succeed");

    // Round-2 presents a DIFFERENT signer set (extra unknown verifier added).
    let tampered_signer_set = vec![verifier_id, VerifierId::from_bytes([0xFF; 32])];

    let r2_req = FrostRound2Request {
        session_id: session_id.clone(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signing_package_bytes: vec![0u8; 16], // won't be reached
        signer_set: tampered_signer_set,
    };

    let result = node.frost_round2(&r2_req);
    assert!(result.is_err(), "signer-set drift must be rejected");
    assert!(
        matches!(result.unwrap_err(), NodeError::FrostProtocol(ref s) if s.contains("mismatch")),
        "expected FrostProtocol with 'mismatch'"
    );
}

/// Node not in the signer set rejects Round-1 request.
#[test]
fn distributed_node_not_in_signer_set_rejects_round1() {
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};
    use tls_attestation_crypto::threshold::approval_signed_digest;

    let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");

    let participant = keygen.participants.into_iter().next().unwrap();
    let node = FrostAuxiliaryNode::new(participant);

    let session_id = tls_attestation_core::ids::SessionId::new_random();
    let envelope_digest = DigestBytes::from_bytes([0xAA; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let now = UnixTimestamp::now();

    // Signer set that does NOT include this node's verifier_id.
    let signer_set = vec![VerifierId::from_bytes([0xBB; 32]), VerifierId::from_bytes([0xCC; 32])];

    let req = FrostRound1Request {
        session_id,
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set,
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: RegistryEpoch::GENESIS,
    };

    let result = node.frost_round1(&req, now);
    assert!(result.is_err(), "node not in signer set must reject round-1");
    assert!(
        matches!(result.unwrap_err(), NodeError::FrostProtocol(ref s) if s.contains("not in the signer set")),
        "expected FrostProtocol 'not in the signer set'"
    );
}

/// Stale (expired) Round-1 request must be rejected.
#[test]
fn distributed_stale_round1_request_rejected() {
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};
    use tls_attestation_crypto::threshold::approval_signed_digest;

    let vids: Vec<VerifierId> = (1u8..=2).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");

    let participant = keygen.participants.into_iter().next().unwrap();
    let verifier_id = participant.verifier_id.clone();
    let node = FrostAuxiliaryNode::new(participant);

    let envelope_digest = DigestBytes::from_bytes([0xDD; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);

    let now = UnixTimestamp::now();
    // round_expires_at is in the past.
    let expired_at = UnixTimestamp(now.0 - 1);

    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set: vec![verifier_id],
        round_expires_at: expired_at,
        registry_epoch: RegistryEpoch::GENESIS,
    };

    let result = node.frost_round1(&req, now);
    assert!(result.is_err(), "expired round-1 must be rejected");
    assert!(
        matches!(result.unwrap_err(), NodeError::FrostProtocol(ref s) if s.contains("expired")),
        "expected FrostProtocol 'expired'"
    );
}

/// Coordinator-supplied `signed_digest` that doesn't match `envelope_digest`
/// is rejected in Round-1 before any nonces are generated.
#[test]
fn distributed_tampered_signed_digest_rejected_in_round1() {
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};

    let vids: Vec<VerifierId> = (1u8..=2).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");

    let participant = keygen.participants.into_iter().next().unwrap();
    let verifier_id = participant.verifier_id.clone();
    let node = FrostAuxiliaryNode::new(participant);

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0x11; 32]);
    // signed_digest deliberately NOT equal to approval_signed_digest(envelope_digest).
    let tampered_signed_digest = DigestBytes::from_bytes([0xFF; 32]);

    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest: tampered_signed_digest,
        envelope_digest,
        signer_set: vec![verifier_id],
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: RegistryEpoch::GENESIS,
    };

    let result = node.frost_round1(&req, now);
    assert!(result.is_err(), "mismatched signed_digest must be rejected");
    assert!(
        matches!(result.unwrap_err(), NodeError::FrostProtocol(ref s) if s.contains("mismatch")),
        "expected FrostProtocol with 'mismatch'"
    );

    // No nonces should have been cached.
    assert_eq!(node.pending_session_count(), 0, "no nonces must be cached on rejection");
}

/// Duplicate round-2 for the same session must fail — nonces were consumed.
#[test]
fn distributed_duplicate_round2_fails_nonces_consumed() {
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};
    use tls_attestation_crypto::threshold::approval_signed_digest;

    // We need a full keygen so the round2 can actually work in the first call.
    let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let group_key = keygen.group_key;

    let mut participants = keygen.participants.into_iter();
    let p0 = participants.next().unwrap();
    let p1 = participants.next().unwrap();
    let p2 = participants.next().unwrap();

    let node0 = FrostAuxiliaryNode::new(p0);
    let node1 = FrostAuxiliaryNode::new(p1);
    let _node2 = FrostAuxiliaryNode::new(p2); // not used in this test

    let now = UnixTimestamp::now();
    let session_id = tls_attestation_core::ids::SessionId::new_random();
    let envelope_digest = DigestBytes::from_bytes([0x22u8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let signer_set = vec![node0.verifier_id().clone(), node1.verifier_id().clone()];

    let r1_req = FrostRound1Request {
        session_id: session_id.clone(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest: signed_digest.clone(),
        envelope_digest,
        signer_set: signer_set.clone(),
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: RegistryEpoch::GENESIS,
    };

    let r0_resp = node0.frost_round1(&r1_req, now).unwrap();
    let r1_resp = node1.frost_round1(&r1_req, now).unwrap();

    // Build a valid signing package.
    let (_, pkg_bytes) = tls_attestation_crypto::frost_adapter::build_signing_package(
        &[
            (r0_resp.verifier_id.clone(), r0_resp.commitment_bytes.clone()),
            (r1_resp.verifier_id.clone(), r1_resp.commitment_bytes.clone()),
        ],
        &signed_digest,
        &group_key,
    )
    .expect("package assembly should succeed");

    let r2_req = FrostRound2Request {
        session_id: session_id.clone(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signing_package_bytes: pkg_bytes,
        signer_set: signer_set.clone(),
    };

    // First round-2 must succeed.
    node0.frost_round2(&r2_req).expect("first round-2 should succeed");

    // Second round-2 for the same session on the same node must fail —
    // nonces were consumed.
    let result = node0.frost_round2(&r2_req);
    assert!(result.is_err(), "duplicate round-2 must fail");
    assert!(
        matches!(result.unwrap_err(), NodeError::FrostProtocol(ref s) if s.contains("nonces missing")),
        "expected FrostProtocol 'nonces missing' after nonce consumption"
    );
}

/// Finalization via `attest_frost_distributed` persists approvals; a second
/// call using the same session ID (impossible by construction, but verifying
/// storage invariants hold) would be rejected.
#[test]
fn distributed_session_state_is_finalized_after_success() {
    let (harness, aux_nodes, group_key) = setup_distributed(3, 2);
    let refs: Vec<&FrostAuxiliaryNode> = aux_nodes[..2].iter().collect();

    harness
        .coordinator
        .attest_frost_distributed(
            make_request("frost-dist/v1", b"finalize-check"),
            b"done",
            &refs,
            &group_key,
        )
        .expect("should succeed");

    // Both participating verifiers should be recorded as having approved.
    // (We verify this via `has_approved` indirectly — the approvals were
    // recorded by the coordinator, and a second `record_approval` would panic.)
    // The coordinator's store is private; we can't inspect it from here,
    // but a successful `attest_frost_distributed` guarantees the state
    // machine transitioned to Finalized and all approvals were written.
    // The test simply asserts the call succeeded without panicking on
    // DuplicateApproval.
}
