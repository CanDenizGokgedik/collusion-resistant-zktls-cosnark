//! FROST runtime integration tests.
//!
//! These tests exercise the full `CoordinatorNode::attest_frost` path —
//! the same session lifecycle as the prototype `attest`, but with the real
//! two-round FROST (RFC 9591) signing replacing the per-verifier ed25519 calls.
//!
//! # Build
//!
//! ```bash
//! cargo test --package tls-attestation-testing --features frost
//! ```
//!
//! Without `--features frost` this entire file is compiled away.

// Gate the entire file on the frost feature so that the default workspace
// build (`cargo test --workspace`) continues to work without changes.
#![cfg(feature = "frost")]

use tls_attestation_attestation::envelope::AttestationEnvelope;
use tls_attestation_core::{ids::ProverId, types::Nonce};
use tls_attestation_crypto::frost_adapter::{frost_trusted_dealer_keygen, FrostGroupKey};
use tls_attestation_network::messages::AttestationRequest;
use tls_attestation_testing::fixtures::{TestHarness, TestHarnessConfig};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_request(tag: &str, query: &[u8]) -> AttestationRequest {
    AttestationRequest {
        prover_id: ProverId::from_bytes([0xAAu8; 32]),
        client_nonce: Nonce::from_bytes([0xBBu8; 32]),
        statement_tag: tag.to_string(),
        query: query.to_vec(),
        requested_ttl_secs: 3600,
    }
}

/// Build a harness and run trusted-dealer keygen for `n` verifiers with the
/// given `threshold`, using the harness's quorum verifier IDs.
///
/// Returns the harness, the FROST participants (in quorum order), and the group key.
fn setup_frost(
    n: usize,
    threshold: usize,
) -> (
    TestHarness,
    Vec<tls_attestation_crypto::frost_adapter::FrostParticipant>,
    FrostGroupKey,
) {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: n,
        threshold,
        ttl_secs: 3600,
    });

    // Run keygen using the exact verifier IDs from the harness quorum so that
    // the coordinator's config.quorum and the FROST group key are in sync.
    let verifier_ids = harness.coordinator_quorum_verifiers();
    let keygen_out = frost_trusted_dealer_keygen(&verifier_ids, threshold)
        .expect("trusted-dealer keygen should succeed");

    (harness, keygen_out.participants, keygen_out.group_key)
}

// ── Phase 5: Happy-path tests ─────────────────────────────────────────────────

/// 2-of-3: basic happy path — threshold of 2 satisfied with exactly 2 signers.
#[test]
fn frost_attest_2_of_3_with_threshold_signers_succeeds() {
    let (harness, participants, group_key) = setup_frost(3, 2);

    let request = make_request("frost/v1", b"GET /api/price");
    let response = b"99.50";

    // Pass exactly the minimum threshold (2 of 3) participants.
    let envelope = harness
        .coordinator
        .attest_frost(request, response, &participants[..2], &group_key)
        .expect("FROST 2-of-3 attestation should succeed");

    // The envelope digest must be internally consistent.
    let recomputed = AttestationEnvelope::compute_digest(
        &envelope.session,
        &envelope.randomness,
        &envelope.transcript,
        &envelope.statement,
        &envelope.coordinator_evidence,
    );
    assert_eq!(
        envelope.envelope_digest, recomputed,
        "envelope_digest must match the recomputed value"
    );
}

/// 2-of-3: all three participants provided — surplus signers are fine.
#[test]
fn frost_attest_2_of_3_with_all_signers_succeeds() {
    let (harness, participants, group_key) = setup_frost(3, 2);

    let request = make_request("frost/v1", b"GET /api/volume");
    let response = b"1234567";

    let envelope = harness
        .coordinator
        .attest_frost(request, response, &participants, &group_key)
        .expect("FROST 2-of-3 with all signers should succeed");

    let recomputed = AttestationEnvelope::compute_digest(
        &envelope.session,
        &envelope.randomness,
        &envelope.transcript,
        &envelope.statement,
        &envelope.coordinator_evidence,
    );
    assert_eq!(envelope.envelope_digest, recomputed);
}

/// 3-of-3: all three participants required and provided.
#[test]
fn frost_attest_3_of_3_succeeds() {
    let (harness, participants, group_key) = setup_frost(3, 3);

    let request = make_request("frost/v1", b"POST /transfer");
    let response = b"ok";

    let envelope = harness
        .coordinator
        .attest_frost(request, response, &participants, &group_key)
        .expect("FROST 3-of-3 attestation should succeed");

    let recomputed = AttestationEnvelope::compute_digest(
        &envelope.session,
        &envelope.randomness,
        &envelope.transcript,
        &envelope.statement,
        &envelope.coordinator_evidence,
    );
    assert_eq!(envelope.envelope_digest, recomputed);
}

/// The FROST aggregate signature verifies against the embedded group key.
#[test]
fn frost_approval_signature_verifies() {
    let (harness, participants, group_key) = setup_frost(3, 2);

    let request = make_request("frost/v1", b"GET /status");
    let response = b"healthy";

    let envelope = harness
        .coordinator
        .attest_frost(request, response, &participants[..2], &group_key)
        .expect("attestation should succeed");

    envelope
        .frost_approval
        .verify_signature()
        .expect("aggregate Schnorr signature must verify");
}

/// The FROST approval's `signed_digest` must be bound to the envelope digest.
/// `verify_binding` checks that the preimage is `approval_signed_digest(envelope_digest)`.
#[test]
fn frost_approval_binding_verifies() {
    let (harness, participants, group_key) = setup_frost(3, 2);

    let request = make_request("frost/v1", b"GET /binding-check");
    let response = b"bound";

    let envelope = harness
        .coordinator
        .attest_frost(request, response, &participants[..2], &group_key)
        .expect("attestation should succeed");

    envelope
        .frost_approval
        .verify_binding(&envelope.envelope_digest)
        .expect("approval must be bound to this envelope's digest");
}

/// Two independent `attest_frost` calls produce different envelopes and
/// different FROST approvals (fresh nonces each time).
#[test]
fn two_frost_attestations_produce_distinct_approvals() {
    let (harness, participants, group_key) = setup_frost(3, 2);

    let req1 = make_request("frost/v1", b"GET /price");
    let req2 = make_request("frost/v1", b"GET /price");

    let env1 = harness
        .coordinator
        .attest_frost(req1, b"100", &participants[..2], &group_key)
        .expect("first attestation should succeed");

    let env2 = harness
        .coordinator
        .attest_frost(req2, b"101", &participants[..2], &group_key)
        .expect("second attestation should succeed");

    // Different responses → different envelope digests.
    assert_ne!(
        env1.envelope_digest, env2.envelope_digest,
        "different responses must produce different envelope digests"
    );

    // Different envelope digests → different FROST approvals.
    assert_ne!(
        env1.frost_approval.aggregate_signature_bytes,
        env2.frost_approval.aggregate_signature_bytes,
        "different envelopes must produce different aggregate signatures"
    );
}

// ── Phase 6: Adversarial / negative tests ─────────────────────────────────────

/// Providing fewer signers than the quorum threshold must fail before FROST runs.
///
/// Expects `NodeError::QuorumNotMet` — not a cryptographic error.
#[test]
fn frost_attest_below_threshold_fails() {
    let (harness, participants, group_key) = setup_frost(3, 2);

    let request = make_request("frost/v1", b"GET /price");

    // Pass only 1 signer — threshold is 2.
    let result = harness
        .coordinator
        .attest_frost(request, b"fail", &participants[..1], &group_key);

    assert!(
        result.is_err(),
        "below-threshold must be rejected"
    );
    let err = result.unwrap_err();
    // Should be QuorumNotMet, not a crypto error.
    assert!(
        matches!(err, tls_attestation_node::error::NodeError::QuorumNotMet { .. }),
        "expected QuorumNotMet, got: {err}"
    );
}

/// Passing zero signers must fail with QuorumNotMet.
#[test]
fn frost_attest_empty_signers_fails() {
    let (harness, _participants, group_key) = setup_frost(3, 2);

    let result = harness
        .coordinator
        .attest_frost(make_request("frost/v1", b"q"), b"r", &[], &group_key);

    assert!(result.is_err(), "empty signers must be rejected");
    assert!(
        matches!(
            result.unwrap_err(),
            tls_attestation_node::error::NodeError::QuorumNotMet { .. }
        ),
        "expected QuorumNotMet for empty signers"
    );
}

/// Signers from a *different* keygen that are unknown to the group key must fail.
///
/// The FROST library will not find the signer's FROST identifier in the
/// signing package and must return an `UnknownVerifier` error.
#[test]
fn frost_attest_signers_not_in_group_key_fails() {
    // Harness A — the coordinator and quorum we'll actually use.
    let (harness_a, _participants_a, group_key_a) = setup_frost(3, 2);

    // Harness B — a different quorum with its own keygen.
    let harness_b = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids_b = harness_b.coordinator_quorum_verifiers();
    let keygen_b = frost_trusted_dealer_keygen(&vids_b, 2)
        .expect("keygen B should succeed");

    // Use participants from group B but the group key from group A — mismatch.
    let result = harness_a.coordinator.attest_frost(
        make_request("frost/v1", b"mismatch"),
        b"fail",
        &keygen_b.participants[..2],
        &group_key_a,
    );

    assert!(
        result.is_err(),
        "signers unknown to the group key must be rejected"
    );
    // The error should be a Crypto error (UnknownVerifier), not QuorumNotMet.
    assert!(
        matches!(result.unwrap_err(), tls_attestation_node::error::NodeError::Crypto(_)),
        "expected a Crypto error for unknown signers"
    );
}

/// The group key from a different keygen must be rejected.
///
/// Participants match a real quorum, but the group key is from a different
/// keygen — FROST signature verification will fail.
#[test]
fn frost_attest_wrong_group_key_fails() {
    // Both groups use the same verifier IDs (from the same harness quorum)
    // but were key-generated independently — their group secrets differ.
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();

    let keygen1 = frost_trusted_dealer_keygen(&vids, 2).expect("keygen 1");
    let keygen2 = frost_trusted_dealer_keygen(&vids, 2).expect("keygen 2");

    // Use signers from keygen1 but supply the group key from keygen2.
    // The FROST aggregate will be over keygen1's group secret but checked
    // against keygen2's verifying key — they don't match.
    let result = harness.coordinator.attest_frost(
        make_request("frost/v1", b"wrong-key"),
        b"fail",
        &keygen1.participants[..2],
        &keygen2.group_key,
    );

    assert!(
        result.is_err(),
        "wrong group key must cause an error"
    );
}

/// Verify that `verify_binding` rejects a tampered envelope digest.
///
/// If someone swaps the envelope fields after signing, the binding check
/// catches it.
#[test]
fn frost_approval_binding_rejects_tampered_digest() {
    use tls_attestation_core::hash::DigestBytes;

    let (harness, participants, group_key) = setup_frost(3, 2);

    let envelope = harness
        .coordinator
        .attest_frost(
            make_request("frost/v1", b"tamper-test"),
            b"original",
            &participants[..2],
            &group_key,
        )
        .expect("attestation should succeed");

    let tampered_digest = DigestBytes::from_bytes([0xFF; 32]);
    assert_ne!(tampered_digest, envelope.envelope_digest);

    let result = envelope.frost_approval.verify_binding(&tampered_digest);
    assert!(
        result.is_err(),
        "verify_binding must reject a tampered envelope digest"
    );
}

/// The approval signature must not verify with a different group key's
/// verifying bytes.
///
/// Guards against a scenario where an attacker provides a `FrostGroupKey`
/// they control to produce a valid-looking approval.
#[test]
fn frost_approval_signature_rejects_wrong_verifying_key() {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 3,
        threshold: 2,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();

    let keygen1 = frost_trusted_dealer_keygen(&vids, 2).expect("keygen 1");
    let keygen2 = frost_trusted_dealer_keygen(&vids, 2).expect("keygen 2");

    let envelope = harness
        .coordinator
        .attest_frost(
            make_request("frost/v1", b"key-swap"),
            b"data",
            &keygen1.participants[..2],
            &keygen1.group_key,
        )
        .expect("attestation with keygen1 should succeed");

    // Manually construct a tampered approval that embeds keygen2's verifying
    // key while keeping keygen1's aggregate signature.
    let tampered = tls_attestation_crypto::frost_adapter::FrostThresholdApproval {
        signed_digest: envelope.frost_approval.signed_digest.clone(),
        aggregate_signature_bytes: envelope.frost_approval.aggregate_signature_bytes,
        group_verifying_key_bytes: keygen2.group_key.verifying_key_bytes(),
    };

    assert!(
        tampered.verify_signature().is_err(),
        "approval with mismatched verifying key must be rejected"
    );
}
