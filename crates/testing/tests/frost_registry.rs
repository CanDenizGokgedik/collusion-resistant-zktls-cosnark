//! Registry-gated FROST signing tests.
//!
//! These tests exercise the `ParticipantRegistry`-based admission checks
//! layered into both `FrostAuxiliaryNode` (per-node) and
//! `CoordinatorNode::attest_frost_distributed_with_registry` (coordinator gate).
//!
//! Coverage:
//!
//! - Happy path: registry-gated aux node accepts Active participants at correct epoch.
//! - Per-node rejection: revoked, retired, and unknown signers are blocked at Round 1.
//! - Per-node rejection: stale epoch in `FrostRound1Request` is rejected.
//! - GENESIS epoch sentinel: bypasses per-node registry checks unconditionally.
//! - Coordinator-level gate: `attest_frost_distributed_with_registry` rejects revoked
//!   and retired signers before sending any round message.
//! - Coordinator-level gate: epoch mismatch is caught before round messages are sent.
//! - Backward compat: `attest_frost_distributed` (no registry) still works end-to-end.
//! - Key consistency: `ParticipantRegistry::new_validated` rejects mismatched entries.
//! - End-to-end: registry-gated distributed FROST signing produces a valid aggregate
//!   Schnorr signature verifiable against the group key.
//!
//! # Build
//!
//! ```bash
//! cargo test --package tls-attestation-testing --features frost --test frost_registry
//! ```

#![cfg(feature = "frost")]

use tls_attestation_core::{
    hash::DigestBytes,
    ids::{ProverId, VerifierId},
    types::{Nonce, UnixTimestamp},
};
use tls_attestation_crypto::{
    frost_adapter::{frost_trusted_dealer_keygen, FrostGroupKey},
    participant_registry::{
        ParticipantRegistry, RegisteredParticipant, RegistryEpoch, RegistryError,
    },
    threshold::{approval_signed_digest, VerifierKeyPair},
};
use tls_attestation_network::messages::{AttestationRequest, FrostRound1Request};
use tls_attestation_node::{error::NodeError, frost_aux::FrostAuxiliaryNode};
use tls_attestation_testing::fixtures::{TestHarness, TestHarnessConfig};

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

/// A FROST-signing setup bound to a `ParticipantRegistry`.
///
/// All participants are `Active` at `epoch` on construction. Tests that need
/// a revoked or retired participant must call `registry.with_revocation` /
/// `registry.with_retirement` and re-derive a fresh registry after construction.
struct FrostRegistrySetup {
    signing_kps: Vec<VerifierKeyPair>,
    registry: ParticipantRegistry,
    frost_nodes: Vec<FrostAuxiliaryNode>,
    group_key: FrostGroupKey,
    harness: TestHarness,
    _epoch: RegistryEpoch,
}

/// Build a complete registry-gated FROST setup with `n` participants at `epoch`.
///
/// Each `FrostAuxiliaryNode` is constructed via `with_registry` and holds the
/// same registry snapshot, so per-node admission checks fire on Round 1.
fn setup_frost_with_registry(
    n: usize,
    threshold: usize,
    epoch: RegistryEpoch,
) -> FrostRegistrySetup {
    let signing_kps: Vec<VerifierKeyPair> =
        (1u8..=(n as u8)).map(|b| VerifierKeyPair::from_seed([b; 32])).collect();
    let vids: Vec<VerifierId> = signing_kps.iter().map(|kp| kp.verifier_id.clone()).collect();
    let registry = ParticipantRegistry::from_key_pairs(epoch, &signing_kps).unwrap();

    let keygen = frost_trusted_dealer_keygen(&vids, threshold).expect("frost keygen");
    let group_key = keygen.group_key;

    // Each node gets its own clone of the registry snapshot.
    let frost_nodes: Vec<FrostAuxiliaryNode> = keygen
        .participants
        .into_iter()
        .map(|p| FrostAuxiliaryNode::with_registry(p, registry.clone()))
        .collect();

    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: n,
        threshold,
        ttl_secs: 3600,
    });

    FrostRegistrySetup { signing_kps, registry, frost_nodes, group_key, harness, _epoch: epoch }
}

// ── Per-node Round-1 admission tests ─────────────────────────────────────────

/// A node with a registry accepts a well-formed Round-1 request for Active
/// participants at the correct epoch.
#[test]
fn registry_gated_round1_accepts_active_participant() {
    let epoch = RegistryEpoch(1);
    let setup = setup_frost_with_registry(3, 2, epoch);

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0xAAu8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let node0 = &setup.frost_nodes[0];

    let signer_set: Vec<VerifierId> =
        setup.frost_nodes.iter().map(|n| n.verifier_id().clone()).collect();

    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set,
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: epoch,
    };

    let result = node0.frost_round1(&req, now);
    assert!(result.is_ok(), "Active participant at correct epoch should be admitted");
    assert_eq!(node0.pending_session_count(), 1);
}

/// Revoked signer in `signer_set` must be rejected at Round 1.
#[test]
fn registry_gated_round1_rejects_revoked_signer() {
    let epoch = RegistryEpoch(1);
    let setup = setup_frost_with_registry(3, 2, epoch);

    // Revoke participant 1 at a new epoch.
    let revoked_vid = setup.frost_nodes[1].verifier_id().clone();
    let new_epoch = epoch.next();
    let revoked_registry = setup
        .registry
        .with_revocation(&revoked_vid, new_epoch)
        .expect("revocation should succeed");

    // Rebuild node 0 with the revoked registry snapshot.
    let signing_kps: Vec<VerifierKeyPair> =
        (1u8..=3u8).map(|b| VerifierKeyPair::from_seed([b; 32])).collect();
    let vids: Vec<VerifierId> = signing_kps.iter().map(|kp| kp.verifier_id.clone()).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let node0 = FrostAuxiliaryNode::with_registry(
        keygen.participants.into_iter().next().unwrap(),
        revoked_registry,
    );

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0xBBu8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);

    // Include the revoked participant in the signer set.
    let signer_set = vec![vids[0].clone(), revoked_vid.clone()];

    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set,
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: new_epoch,
    };

    let result = node0.frost_round1(&req, now);
    assert!(result.is_err(), "revoked signer in set must be rejected");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(ref s) if s.contains("denied")),
        "expected SigningAdmission error"
    );
    assert_eq!(node0.pending_session_count(), 0, "no nonces must be cached on rejection");
}

/// Retired signer in `signer_set` must be rejected at Round 1.
#[test]
fn registry_gated_round1_rejects_retired_signer() {
    let epoch = RegistryEpoch(1);
    let setup = setup_frost_with_registry(3, 2, epoch);

    let retired_vid = setup.frost_nodes[2].verifier_id().clone();
    let new_epoch = epoch.next();
    let retired_registry = setup
        .registry
        .with_retirement(&retired_vid, new_epoch)
        .expect("retirement should succeed");

    let signing_kps: Vec<VerifierKeyPair> =
        (1u8..=3u8).map(|b| VerifierKeyPair::from_seed([b; 32])).collect();
    let vids: Vec<VerifierId> = signing_kps.iter().map(|kp| kp.verifier_id.clone()).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let node0 = FrostAuxiliaryNode::with_registry(
        keygen.participants.into_iter().next().unwrap(),
        retired_registry,
    );

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0xCCu8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);

    let signer_set = vec![vids[0].clone(), retired_vid.clone()];

    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set,
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: new_epoch,
    };

    let result = node0.frost_round1(&req, now);
    assert!(result.is_err(), "retired signer must be rejected");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(_)),
        "expected SigningAdmission error"
    );
}

/// Unknown signer (not in registry at all) must be rejected at Round 1.
#[test]
fn registry_gated_round1_rejects_unknown_signer() {
    let epoch = RegistryEpoch(1);
    let setup = setup_frost_with_registry(2, 2, epoch);

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0xDDu8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let node0 = &setup.frost_nodes[0];

    // Include an unknown outsider in the signer set.
    let outsider = VerifierId::from_bytes([0xFF; 32]);
    let signer_set = vec![node0.verifier_id().clone(), outsider];

    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set,
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: epoch,
    };

    let result = node0.frost_round1(&req, now);
    assert!(result.is_err(), "unknown signer must be rejected");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(_)),
        "expected SigningAdmission error for unknown signer"
    );
}

/// Stale (wrong) epoch in the Round-1 request is rejected by a registry-holding node.
#[test]
fn registry_gated_round1_rejects_stale_epoch() {
    let current_epoch = RegistryEpoch(5);
    let setup = setup_frost_with_registry(2, 2, current_epoch);

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0xEEu8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let node0 = &setup.frost_nodes[0];

    let signer_set: Vec<VerifierId> =
        setup.frost_nodes.iter().map(|n| n.verifier_id().clone()).collect();

    // Use a stale epoch (lower than the registry epoch).
    let stale_epoch = RegistryEpoch(3);

    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set,
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: stale_epoch,
    };

    let result = node0.frost_round1(&req, now);
    assert!(result.is_err(), "stale epoch must be rejected");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(ref s) if s.contains("epoch mismatch")),
        "expected SigningAdmission with epoch mismatch message"
    );
}

/// Future (wrong) epoch in the Round-1 request is also rejected.
#[test]
fn registry_gated_round1_rejects_future_epoch() {
    let current_epoch = RegistryEpoch(3);
    let setup = setup_frost_with_registry(2, 2, current_epoch);

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0xF0u8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let node0 = &setup.frost_nodes[0];

    let signer_set: Vec<VerifierId> =
        setup.frost_nodes.iter().map(|n| n.verifier_id().clone()).collect();

    let future_epoch = RegistryEpoch(99);

    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set,
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: future_epoch,
    };

    let result = node0.frost_round1(&req, now);
    assert!(result.is_err(), "future epoch must be rejected");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(_)),
        "expected SigningAdmission for future epoch"
    );
}

/// `RegistryEpoch::GENESIS` in the request bypasses per-node registry checks
/// even when the node holds a registry at a non-GENESIS epoch.
///
/// This maintains backward compatibility: legacy coordinators that don't know
/// about registries send `GENESIS`, and nodes that hold a registry skip the
/// admission check to stay interoperable.
#[test]
fn registry_gated_round1_genesis_epoch_bypasses_checks() {
    // Build a registry at epoch 5 — not GENESIS.
    let epoch = RegistryEpoch(5);
    let setup = setup_frost_with_registry(3, 2, epoch);

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0x11u8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let node0 = &setup.frost_nodes[0];

    let signer_set: Vec<VerifierId> =
        setup.frost_nodes.iter().map(|n| n.verifier_id().clone()).collect();

    // GENESIS epoch — bypass all registry admission checks.
    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set,
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: RegistryEpoch::GENESIS,
    };

    // Even though the node holds a registry at epoch 5, GENESIS bypasses checks.
    let result = node0.frost_round1(&req, now);
    assert!(result.is_ok(), "GENESIS epoch must bypass registry checks; got: {:?}", result.err());
}

/// `FrostAuxiliaryNode::new` (no registry) accepts any well-formed request
/// regardless of `registry_epoch`.
#[test]
fn no_registry_node_accepts_any_epoch() {
    let vids: Vec<VerifierId> = (1u8..=2).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let participant = keygen.participants.into_iter().next().unwrap();
    let vid = participant.verifier_id.clone();
    let node = FrostAuxiliaryNode::new(participant);

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0x22u8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);

    // Use an arbitrary non-GENESIS epoch — should be accepted without a registry.
    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set: vec![vid],
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: RegistryEpoch(42),
    };

    let result = node.frost_round1(&req, now);
    assert!(result.is_ok(), "no-registry node must accept any epoch; got: {:?}", result.err());
}

// ── Key consistency enforcement ───────────────────────────────────────────────

/// `ParticipantRegistry::new_validated` rejects an entry where `verifier_id`
/// does not match `SHA-256(signing_key.to_bytes())`.
#[test]
fn new_validated_rejects_mismatched_verifier_id() {
    let kp = VerifierKeyPair::from_seed([0xABu8; 32]);
    // Construct an entry with a plausible but WRONG VerifierId.
    let wrong_id = VerifierId::from_bytes([0x00u8; 32]);
    let bad_entry = RegisteredParticipant::active(
        wrong_id.clone(),
        kp.verifying_key(),
        RegistryEpoch::GENESIS,
    );

    let result = ParticipantRegistry::new_validated(RegistryEpoch::GENESIS, vec![bad_entry]);
    assert!(result.is_err(), "new_validated must reject mismatched entry");
    assert!(
        matches!(
            result.unwrap_err(),
            RegistryError::VerifierIdMismatch { ref claimed, .. } if *claimed == wrong_id
        ),
        "expected VerifierIdMismatch"
    );
}

/// `ParticipantRegistry::new_validated` accepts entries constructed via
/// `RegisteredParticipant::from_signing_key` (always consistent).
#[test]
fn new_validated_accepts_consistent_entries() {
    let kp = VerifierKeyPair::from_seed([0xCDu8; 32]);
    let entry = RegisteredParticipant::from_signing_key(kp.verifying_key(), RegistryEpoch::GENESIS);

    let result = ParticipantRegistry::new_validated(RegistryEpoch::GENESIS, vec![entry]);
    assert!(result.is_ok(), "from_signing_key entry must pass new_validated");
}

/// `RegisteredParticipant::validate_key_consistency` returns `Ok` for a
/// self-consistent entry and `Err(VerifierIdMismatch)` for an inconsistent one.
#[test]
fn registered_participant_validate_key_consistency() {
    let kp = VerifierKeyPair::from_seed([0x01u8; 32]);

    // Consistent: from_signing_key derives the correct verifier_id.
    let good = RegisteredParticipant::from_signing_key(kp.verifying_key(), RegistryEpoch::GENESIS);
    assert!(good.validate_key_consistency().is_ok());

    // Inconsistent: verifier_id is arbitrarily chosen, not derived from the key.
    let bad = RegisteredParticipant::active(
        VerifierId::from_bytes([0xFF; 32]),
        kp.verifying_key(),
        RegistryEpoch::GENESIS,
    );
    let err = bad.validate_key_consistency();
    assert!(err.is_err(), "inconsistent entry must fail validation");
    assert!(matches!(err.unwrap_err(), RegistryError::VerifierIdMismatch { .. }));
}

// ── Coordinator-level admission gate ─────────────────────────────────────────

/// End-to-end happy path: `attest_frost_distributed_with_registry` produces a
/// valid `FrostAttestationEnvelope` when all signers are Active at the correct epoch.
#[test]
fn distributed_with_registry_happy_path_2_of_3() {
    let epoch = RegistryEpoch(1);
    let setup = setup_frost_with_registry(3, 2, epoch);

    let node_refs: Vec<&FrostAuxiliaryNode> = setup.frost_nodes.iter().collect();

    let result = setup.harness.coordinator.attest_frost_distributed_with_registry(
        make_request("v1.tls", b"registry happy path"),
        b"ok",
        &node_refs,
        &setup.group_key,
        &setup.registry,
        epoch,
    );
    assert!(result.is_ok(), "registry-gated happy path must succeed; got: {:?}", result.err());

    let envelope = result.unwrap();
    let bind_ok = envelope.frost_approval.verify_binding(&envelope.envelope_digest);
    assert!(bind_ok.is_ok(), "approval must bind to envelope digest");
    let sig_ok = envelope.frost_approval.verify_signature();
    assert!(sig_ok.is_ok(), "aggregate FROST signature must verify");
}

/// End-to-end happy path with 3-of-5.
#[test]
fn distributed_with_registry_happy_path_3_of_5() {
    let epoch = RegistryEpoch(2);
    let setup = setup_frost_with_registry(5, 3, epoch);

    let node_refs: Vec<&FrostAuxiliaryNode> = setup.frost_nodes.iter().collect();

    let result = setup.harness.coordinator.attest_frost_distributed_with_registry(
        make_request("v1.tls", b"3of5 registry"),
        b"response",
        &node_refs,
        &setup.group_key,
        &setup.registry,
        epoch,
    );
    assert!(result.is_ok(), "3-of-5 registry-gated must succeed; got: {:?}", result.err());
}

/// `attest_frost_distributed_with_registry` rejects the request when a signer
/// in `aux_nodes` is revoked in the provided registry.
#[test]
fn distributed_with_registry_rejects_revoked_signer() {
    let epoch = RegistryEpoch(1);
    let setup = setup_frost_with_registry(3, 2, epoch);

    let revoked_vid = setup.frost_nodes[1].verifier_id().clone();
    let new_epoch = epoch.next();
    let revoked_registry = setup
        .registry
        .with_revocation(&revoked_vid, new_epoch)
        .expect("revocation");

    let node_refs: Vec<&FrostAuxiliaryNode> = setup.frost_nodes.iter().collect();

    let result = setup.harness.coordinator.attest_frost_distributed_with_registry(
        make_request("v1.tls", b"revoked"),
        b"fail",
        &node_refs,
        &setup.group_key,
        &revoked_registry,
        new_epoch,
    );
    assert!(result.is_err(), "revoked signer must be rejected at coordinator gate");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(_)),
        "expected SigningAdmission error from coordinator gate"
    );
}

/// `attest_frost_distributed_with_registry` rejects the request when a signer
/// is retired.
#[test]
fn distributed_with_registry_rejects_retired_signer() {
    let epoch = RegistryEpoch(1);
    let setup = setup_frost_with_registry(3, 2, epoch);

    let retired_vid = setup.frost_nodes[0].verifier_id().clone();
    let new_epoch = epoch.next();
    let retired_registry = setup
        .registry
        .with_retirement(&retired_vid, new_epoch)
        .expect("retirement");

    let node_refs: Vec<&FrostAuxiliaryNode> = setup.frost_nodes.iter().collect();

    let result = setup.harness.coordinator.attest_frost_distributed_with_registry(
        make_request("v1.tls", b"retired"),
        b"fail",
        &node_refs,
        &setup.group_key,
        &retired_registry,
        new_epoch,
    );
    assert!(result.is_err(), "retired signer must be rejected at coordinator gate");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(_)),
        "expected SigningAdmission for retired signer"
    );
}

/// `attest_frost_distributed_with_registry` rejects when `expected_epoch` does
/// not match the registry's epoch.
#[test]
fn distributed_with_registry_rejects_epoch_mismatch() {
    let epoch = RegistryEpoch(3);
    let setup = setup_frost_with_registry(2, 2, epoch);

    let wrong_epoch = RegistryEpoch(99);
    let node_refs: Vec<&FrostAuxiliaryNode> = setup.frost_nodes.iter().collect();

    let result = setup.harness.coordinator.attest_frost_distributed_with_registry(
        make_request("v1.tls", b"epoch mismatch"),
        b"fail",
        &node_refs,
        &setup.group_key,
        &setup.registry,
        wrong_epoch, // does not match registry.epoch() == 3
    );
    assert!(result.is_err(), "epoch mismatch must be rejected at coordinator");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(ref s) if s.contains("epoch mismatch")),
        "expected SigningAdmission with 'epoch mismatch'"
    );
}

/// `attest_frost_distributed` (no registry) continues to work end-to-end
/// after the registry gating infrastructure is added.
#[test]
fn distributed_without_registry_still_works() {
    let epoch = RegistryEpoch(1);
    let setup = setup_frost_with_registry(3, 2, epoch);

    // Build plain (no-registry) nodes from the same key material.
    let signing_kps: Vec<VerifierKeyPair> =
        (1u8..=3u8).map(|b| VerifierKeyPair::from_seed([b; 32])).collect();
    let vids: Vec<VerifierId> = signing_kps.iter().map(|kp| kp.verifier_id.clone()).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let group_key = keygen.group_key;
    let plain_nodes: Vec<FrostAuxiliaryNode> = keygen
        .participants
        .into_iter()
        .map(FrostAuxiliaryNode::new)
        .collect();
    let node_refs: Vec<&FrostAuxiliaryNode> = plain_nodes.iter().collect();

    let result = setup.harness.coordinator.attest_frost_distributed(
        make_request("v1.tls", b"no registry backward compat"),
        b"ok",
        &node_refs,
        &group_key,
    );
    assert!(result.is_ok(), "no-registry path must still work; got: {:?}", result.err());
}

/// After key rotation in the registry, the new epoch is required and the old epoch
/// is rejected.
#[test]
fn distributed_with_registry_rejects_old_epoch_after_rotation() {
    let old_epoch = RegistryEpoch(1);
    let setup = setup_frost_with_registry(2, 2, old_epoch);

    // Rotate key for participant 0 at a new epoch.
    let new_kp = VerifierKeyPair::from_seed([0xFEu8; 32]);
    let new_epoch = old_epoch.next();
    let rotated_registry = setup
        .registry
        .with_key_rotation(&setup.signing_kps[0].verifier_id, new_kp.verifying_key(), new_epoch)
        .expect("key rotation");

    let node_refs: Vec<&FrostAuxiliaryNode> = setup.frost_nodes.iter().collect();

    // Using the OLD epoch with the new registry must be rejected.
    let result = setup.harness.coordinator.attest_frost_distributed_with_registry(
        make_request("v1.tls", b"old epoch after rotation"),
        b"fail",
        &node_refs,
        &setup.group_key,
        &rotated_registry,
        old_epoch, // stale — new registry is at new_epoch
    );
    assert!(result.is_err(), "old epoch must be rejected after rotation");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(_)),
        "expected SigningAdmission for old epoch"
    );
}

/// Two-layer defence: per-node registry check fires even when the coordinator
/// sends a request that bypassed the coordinator-level check (simulated by
/// calling `frost_round1` directly with a bad epoch).
///
/// This validates defence-in-depth: aux nodes reject stale-epoch requests even
/// if the coordinator tries to use a different epoch.
#[test]
fn per_node_check_fires_independently_of_coordinator() {
    let epoch = RegistryEpoch(7);
    let setup = setup_frost_with_registry(2, 2, epoch);

    let now = UnixTimestamp::now();
    let envelope_digest = DigestBytes::from_bytes([0x44u8; 32]);
    let signed_digest = approval_signed_digest(&envelope_digest);
    let node0 = &setup.frost_nodes[0];

    let signer_set: Vec<VerifierId> =
        setup.frost_nodes.iter().map(|n| n.verifier_id().clone()).collect();

    // Coordinator-like bypass: crafts a request with the wrong epoch.
    let wrong_epoch = RegistryEpoch(1);
    let req = FrostRound1Request {
        session_id: tls_attestation_core::ids::SessionId::new_random(),
        coordinator_id: VerifierId::from_bytes([0u8; 32]),
        signed_digest,
        envelope_digest,
        signer_set,
        round_expires_at: UnixTimestamp(now.0 + 3600),
        registry_epoch: wrong_epoch,
    };

    // The aux node should reject this regardless of what the coordinator claims.
    let result = node0.frost_round1(&req, now);
    assert!(result.is_err(), "aux node must reject bad epoch independently");
    assert!(
        matches!(result.unwrap_err(), NodeError::SigningAdmission(_)),
        "expected SigningAdmission from per-node check"
    );
    assert_eq!(node0.pending_session_count(), 0);
}
