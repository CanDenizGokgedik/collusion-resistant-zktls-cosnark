//! Replay-protection integration tests.
//!
//! These tests verify that the protocol correctly rejects all replay scenarios
//! documented in `docs/THREAT_MODEL.md` and `crates/storage/src/traits.rs`.
//!
//! # Scenarios covered
//!
//! 1. Duplicate `SessionId` is rejected at the storage layer.
//! 2. A finalized session cannot be re-opened by a state update.
//! 3. A finalized session's ID cannot be reused for a new session.
//! 4. A verifier cannot approve the same session twice.
//! 5. Approvals are rejected for expired sessions.
//! 6. A duplicate aux-signer entry in the `aux_signers` slice is de-duplicated.
//! 7. A session that has been expired externally is not re-activatable.
//! 8. Approval count does not exceed quorum even if the same verifier signs twice.

use tls_attestation_attestation::session::SessionState;
use tls_attestation_core::{
    ids::{ProverId, SessionId, VerifierId},
    types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
};
use tls_attestation_network::messages::{AttestationRequest, AttestationResponse};
use tls_attestation_storage::{error::StorageError, memory::InMemorySessionStore, traits::SessionStore};
use tls_attestation_attestation::session::{Session, SessionContext};
use tls_attestation_testing::fixtures::{TestHarness, TestHarnessConfig};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_request() -> AttestationRequest {
    AttestationRequest {
        prover_id: ProverId::from_bytes([0xAAu8; 32]),
        client_nonce: Nonce::from_bytes([0xBBu8; 32]),
        statement_tag: "replay-test/v1".to_string(),
        query: b"GET /price".to_vec(),
        requested_ttl_secs: 3600,
    }
}

fn make_session_in_store(store: &InMemorySessionStore, id_byte: u8, state: SessionState) -> SessionId {
    let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
    let id = SessionId::from_bytes([id_byte; 16]);
    let ctx = SessionContext::new(
        id.clone(),
        ProverId::from_bytes([0u8; 32]),
        VerifierId::from_bytes([1u8; 32]),
        quorum,
        Epoch::GENESIS,
        UnixTimestamp(1000),
        UnixTimestamp(2000),
        Nonce::from_bytes([id_byte; 32]),
    );
    let session = Session::new(ctx);
    store.insert(session).unwrap();
    if state != SessionState::Pending {
        store.update_state(&id, state).unwrap();
    }
    id
}

// ── Test 1: Duplicate SessionId rejected at storage layer ─────────────────────

#[test]
fn duplicate_session_id_rejected_by_store() {
    // Invariant: inserting a session with an already-used ID must fail,
    // regardless of whether the prior session is still active.
    let store = InMemorySessionStore::new();

    let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
    let id = SessionId::from_bytes([0x01u8; 16]);

    let make = || {
        let ctx = SessionContext::new(
            id.clone(),
            ProverId::from_bytes([0u8; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum.clone(),
            Epoch::GENESIS,
            UnixTimestamp(100),
            UnixTimestamp(200),
            Nonce::from_bytes([0u8; 32]),
        );
        Session::new(ctx)
    };

    store.insert(make()).expect("first insert should succeed");

    let err = store.insert(make()).expect_err("second insert with same ID must fail");
    assert!(
        matches!(err, StorageError::AlreadyExists),
        "expected AlreadyExists, got {err:?}"
    );
}

// ── Test 2: Terminal session cannot be re-opened ──────────────────────────────

#[test]
fn finalized_session_state_is_immutable() {
    let store = InMemorySessionStore::new();
    let id = make_session_in_store(&store, 0x02, SessionState::Active);
    store.update_state(&id, SessionState::Attesting).unwrap();
    store.update_state(&id, SessionState::Collecting).unwrap();
    store.update_state(&id, SessionState::Finalized).unwrap();

    // Any attempt to change state after Finalized must fail.
    for bad_state in [
        SessionState::Active,
        SessionState::Attesting,
        SessionState::Collecting,
        SessionState::Expired,
    ] {
        let result = store.update_state(&id, bad_state);
        assert!(
            matches!(result, Err(StorageError::SessionTerminated)),
            "expected SessionTerminated when writing to finalized session, got {result:?}"
        );
    }
}

#[test]
fn expired_session_state_is_immutable() {
    let store = InMemorySessionStore::new();
    let id = make_session_in_store(&store, 0x03, SessionState::Active);
    store.update_state(&id, SessionState::Expired).unwrap();

    let result = store.update_state(&id, SessionState::Active);
    assert!(
        matches!(result, Err(StorageError::SessionTerminated)),
        "expected SessionTerminated, got {result:?}"
    );
}

// ── Test 3: Finalized SessionId cannot be reused ──────────────────────────────

#[test]
fn session_id_not_reusable_after_finalization() {
    let store = InMemorySessionStore::new();
    let id = make_session_in_store(&store, 0x04, SessionState::Active);
    store.update_state(&id, SessionState::Attesting).unwrap();
    store.update_state(&id, SessionState::Collecting).unwrap();
    store.update_state(&id, SessionState::Finalized).unwrap();

    // Build a new session with the same ID and attempt to insert it.
    let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
    let ctx = SessionContext::new(
        id.clone(),
        ProverId::from_bytes([0xBBu8; 32]),  // different prover
        VerifierId::from_bytes([1u8; 32]),
        quorum,
        Epoch::GENESIS,
        UnixTimestamp(9000),
        UnixTimestamp(9999),
        Nonce::random(),  // different nonce
    );
    let new_session = Session::new(ctx);

    let result = store.insert(new_session);
    assert!(
        matches!(result, Err(StorageError::AlreadyExists)),
        "expected AlreadyExists when reusing a finalized session ID, got {result:?}"
    );
}

// ── Test 4: Per-verifier approval deduplication ───────────────────────────────

#[test]
fn verifier_cannot_approve_twice() {
    let store = InMemorySessionStore::new();
    let id = make_session_in_store(&store, 0x05, SessionState::Collecting);
    let v = VerifierId::from_bytes([0xCCu8; 32]);

    store.record_approval(&id, &v).unwrap();

    let result = store.record_approval(&id, &v);
    assert!(
        matches!(result, Err(StorageError::DuplicateApproval { .. })),
        "expected DuplicateApproval, got {result:?}"
    );
}

#[test]
fn two_different_verifiers_can_approve() {
    let store = InMemorySessionStore::new();
    let id = make_session_in_store(&store, 0x06, SessionState::Collecting);

    let v1 = VerifierId::from_bytes([0x01u8; 32]);
    let v2 = VerifierId::from_bytes([0x02u8; 32]);

    store.record_approval(&id, &v1).unwrap();
    store.record_approval(&id, &v2).unwrap();

    assert!(store.has_approved(&id, &v1));
    assert!(store.has_approved(&id, &v2));
}

// ── Test 5: Approval rejected for terminal sessions ───────────────────────────

#[test]
fn approvals_rejected_after_finalization() {
    let store = InMemorySessionStore::new();
    let id = make_session_in_store(&store, 0x07, SessionState::Active);
    store.update_state(&id, SessionState::Attesting).unwrap();
    store.update_state(&id, SessionState::Collecting).unwrap();
    store.update_state(&id, SessionState::Finalized).unwrap();

    let v = VerifierId::from_bytes([0xDDu8; 32]);
    let result = store.record_approval(&id, &v);
    assert!(
        matches!(result, Err(StorageError::SessionTerminated)),
        "expected SessionTerminated for post-finalization approval, got {result:?}"
    );
}

#[test]
fn approvals_rejected_after_expiry() {
    let store = InMemorySessionStore::new();
    let id = make_session_in_store(&store, 0x08, SessionState::Active);
    store.update_state(&id, SessionState::Expired).unwrap();

    let v = VerifierId::from_bytes([0xEEu8; 32]);
    let result = store.record_approval(&id, &v);
    assert!(
        matches!(result, Err(StorageError::SessionTerminated)),
        "expected SessionTerminated, got {result:?}"
    );
}

// ── Test 6: Coordinator deduplicates repeated aux_signers entries ─────────────

#[test]
fn coordinator_rejects_duplicate_aux_signer_entries() {
    // If the same aux signer object appears twice in aux_signers, the coordinator
    // must count it only once. Below threshold ⟹ failure.
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 2,
        threshold: 2,
        ttl_secs: 3600,
    });

    let all_signers = harness.aux_signers();
    // Pass signer[0] twice — should be deduplicated to one approval.
    let repeated = vec![all_signers[0], all_signers[0]];

    let result = harness.coordinator.attest(make_request(), b"response", &repeated);
    // Threshold is 2; only 1 unique verifier → must fail.
    assert!(
        result.is_err(),
        "expected failure when same verifier appears twice, threshold unmet"
    );
}

// ── Test 7: Expired sessions can be read but not advanced ─────────────────────

#[test]
fn expired_session_cannot_be_advanced() {
    let store = InMemorySessionStore::new();
    let id = make_session_in_store(&store, 0x09, SessionState::Active);
    // Simulate expiry.
    store.update_state(&id, SessionState::Expired).unwrap();

    // The session is readable.
    let s = store.get(&id).unwrap();
    assert_eq!(s.state, SessionState::Expired);

    // But cannot be advanced to Attesting.
    let result = store.update_state(&id, SessionState::Attesting);
    assert!(matches!(result, Err(StorageError::SessionTerminated)));
}

// ── Test 8: Full protocol replay — identical request yields distinct envelope ──

#[test]
fn identical_requests_yield_distinct_envelopes() {
    // The coordinator always generates a fresh SessionId and Nonce, so two
    // identical requests must produce different envelopes (different session
    // binding, different randomness, different digests).
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: 2,
        threshold: 2,
        ttl_secs: 3600,
    });

    let signers = harness.aux_signers();
    let req = make_request();

    let r1 = harness.coordinator.attest(
        AttestationRequest {
            prover_id: req.prover_id.clone(),
            client_nonce: req.client_nonce.clone(),
            statement_tag: req.statement_tag.clone(),
            query: req.query.clone(),
            requested_ttl_secs: req.requested_ttl_secs,
        },
        b"response",
        &signers,
    ).expect("first attestation should succeed");

    let r2 = harness.coordinator.attest(
        AttestationRequest {
            prover_id: req.prover_id.clone(),
            client_nonce: req.client_nonce.clone(),
            statement_tag: req.statement_tag.clone(),
            query: req.query.clone(),
            requested_ttl_secs: req.requested_ttl_secs,
        },
        b"response",
        &signers,
    ).expect("second attestation should succeed");

    let d1 = match r1 {
        AttestationResponse::Success(e) => e.envelope_digest,
        _ => panic!("expected success"),
    };
    let d2 = match r2 {
        AttestationResponse::Success(e) => e.envelope_digest,
        _ => panic!("expected success"),
    };

    assert_ne!(
        d1, d2,
        "two sessions for the same request must produce different envelopes"
    );
}
