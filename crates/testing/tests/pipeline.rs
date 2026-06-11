//! Full Π_coll-min end-to-end pipeline integration tests.
//!
//! These tests exercise the complete protocol chain:
//!
//! ```text
//! DVRF(α) → rand  →  HSP(rand)  →  QP  →  PGP  →  TSS  →  OnChainAttestation
//! ```
//!
//! Each test verifies that:
//! 1. The DVRF produces a unique, verifiable random value for the session.
//! 2. The DCTLS proofs (HSP/QP/PGP) are correctly generated and verifiable.
//! 3. The threshold signature covers the full attestation envelope.
//! 4. The on-chain format correctly encodes and decodes.
//! 5. The AuxiliaryVerifier's `check_full` approves only valid full-chain attestations.
//!
//! # Build
//!
//! ```bash
//! cargo test --package tls-attestation-testing --features frost --test pipeline
//! ```

#![cfg(feature = "frost")]

use tls_attestation_attestation::{
    dctls::{
        DctlsEvidence, HSPProof, PGPProof, QueryRecord, SessionParamsPublic,
        SessionParamsSecret, Statement, verify_hsp_proof, verify_pgp_proof, verify_query_record,
    },
    engine::{
        AttestationEngine, AttestationPackage, DxDctlsAttestationEngine,
        PrototypeDctlsEngine,
    },
    envelope::{AttestationEnvelope, RandomnessBinding},
    onchain::{derive_onchain_statement_digest, extract_on_chain_attestation, OnChainAttestation},
    session::SessionContext,
    statement::StatementPayload,
    verify::{AuxiliaryVerifier, VerificationPolicy},
};
use tls_attestation_core::{
    hash::{CanonicalHasher, DigestBytes},
    ids::{ProverId, RandomnessId, SessionId, VerifierId},
    types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
};
use tls_attestation_crypto::{
    dvrf::{DvRFInput, DvRFOutput, FrostDvRF},
    frost_adapter::{
        aggregate_signature_shares, build_signing_package, frost_collect_approval,
        frost_trusted_dealer_keygen, FrostGroupKey, FrostParticipant,
    },
    threshold::approval_signed_digest,
};

// ── Test fixtures ──────────────────────────────────────────────────────────────

fn make_session(n: usize, threshold: usize) -> (SessionContext, Vec<VerifierId>) {
    let vids: Vec<VerifierId> = (1u8..=(n as u8))
        .map(|b| VerifierId::from_bytes([b; 32]))
        .collect();
    let quorum = QuorumSpec::new(vids.clone(), threshold).unwrap();
    let session = SessionContext::new(
        SessionId::from_bytes([0xAA; 16]),
        ProverId::from_bytes([0xBB; 32]),
        vids[0].clone(),
        quorum,
        Epoch::GENESIS,
        UnixTimestamp(1_000_000),
        UnixTimestamp(1_002_000),
        Nonce::from_bytes([0xCC; 32]),
    );
    (session, vids)
}

fn quorum_hash(vids: &[VerifierId]) -> DigestBytes {
    let mut h = CanonicalHasher::new("tls-attestation/quorum-hash/v1");
    h.update_u64(vids.len() as u64);
    for v in vids {
        h.update_fixed(v.as_bytes());
    }
    h.finalize()
}

// ── Phase 1: DVRF → rand ───────────────────────────────────────────────────────

#[test]
fn phase1_dvrf_produces_unique_verifiable_randomness() {
    let (session, vids) = make_session(3, 2);
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key);

    let qhash = quorum_hash(&vids);
    let alpha = DvRFInput::for_session(
        &session.session_id,
        &session.prover_id,
        &session.nonce,
        session.epoch,
        &qhash,
    );

    let participants: Vec<_> = keygen.participants.iter().collect();
    let dvrf_output = dvrf.evaluate(&alpha, &participants[..2]).expect("DVRF evaluate");

    // Verify: anyone with group key can verify the DVRF output.
    FrostDvRF::verify(&alpha, &dvrf_output).expect("DVRF verify");
    assert_ne!(dvrf_output.value, DigestBytes::ZERO, "DVRF output must be non-zero");
}

// ── Phase 2: HSP/QP/PGP → DCTLS proofs ───────────────────────────────────────

#[test]
fn phase2_dctls_engine_produces_verifiable_proofs() {
    let (session, vids) = make_session(3, 2);
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key);

    let qhash = quorum_hash(&vids);
    let alpha = DvRFInput::for_session(
        &session.session_id, &session.prover_id, &session.nonce, session.epoch, &qhash,
    );
    let participants: Vec<_> = keygen.participants.iter().collect();
    let dvrf_output = dvrf.evaluate(&alpha, &participants[..2]).expect("DVRF");
    let rand = dvrf_output.value.clone();

    let server_cert_hash = DigestBytes::from_bytes([0x55; 32]);
    let query = b"GET /api/balance";
    let response = b"200 OK: balance=1000";

    let engine = PrototypeDctlsEngine;
    let (transcript, evidence, dctls_evidence) = engine
        .execute_dctls(&session, &rand, query, response, &server_cert_hash)
        .expect("execute_dctls");

    // Independently verify all three DCTLS proofs.
    dctls_evidence
        .verify_all(&rand, &server_cert_hash, query, response)
        .expect("DCTLS verify_all");

    // Verify individual phases.
    verify_hsp_proof(&dctls_evidence.hsp_proof, &rand, &server_cert_hash)
        .expect("HSP verify");
    verify_query_record(&dctls_evidence.query_record, query, response)
        .expect("QP verify");
    verify_pgp_proof(&dctls_evidence.pgp_proof, &rand, &dctls_evidence.hsp_proof)
        .expect("PGP verify");
}

// ── Phase 3: Full pipeline DVRF → DCTLS → TSS ────────────────────────────────

#[test]
fn phase3_full_pipeline_2_of_3_complete_attestation() {
    let (session, vids) = make_session(3, 2);
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key.clone());

    // ── Step 1: DVRF → rand ──────────────────────────────────────────────
    let qhash = quorum_hash(&vids);
    let alpha = DvRFInput::for_session(
        &session.session_id, &session.prover_id, &session.nonce, session.epoch, &qhash,
    );
    let participants: Vec<_> = keygen.participants.iter().collect();
    let dvrf_output = dvrf.evaluate(&alpha, &participants[..2]).expect("DVRF");
    let rand = dvrf_output.value.clone();

    // ── Step 2: HSP → QP → PGP ──────────────────────────────────────────
    let server_cert_hash = DigestBytes::from_bytes([0x42; 32]);
    let query = b"GET /attestation";
    let response = b"200 OK: attested=true";

    let engine = PrototypeDctlsEngine;
    let (transcript, evidence, dctls_evidence) = engine
        .execute_dctls(&session, &rand, query, response, &server_cert_hash)
        .expect("execute_dctls");

    // ── Step 3: Build attestation package ───────────────────────────────
    let statement = StatementPayload::new(
        b"attested=true".to_vec(),
        "result/v1".into(),
        &transcript.session_transcript_digest,
    );

    let package = AttestationPackage::build(
        session.clone(),
        rand.clone(),
        transcript.clone(),
        evidence.clone(),
    );

    // ── Step 4: Aux verifier check_full (all 14 checks) ─────────────────
    let policy = VerificationPolicy {
        allowed_engine_tags: vec!["dx-dctls/commitment-v1".into()],
        allowed_statement_tags: vec![],
        max_session_duration_secs: 3600,
    };
    let aux_verifier = AuxiliaryVerifier::new(vids[0].clone(), policy);
    let result = aux_verifier.check_full(
        &package,
        &statement,
        &dctls_evidence,
        &dvrf_output,
        &alpha,
        &server_cert_hash,
        query,
        response,
        UnixTimestamp(1_001_000),
    );
    assert!(
        result.approved,
        "check_full must approve valid full-chain attestation: {:?}",
        result.failure_reason
    );

    // ── Step 5: TSS → aggregate signature ───────────────────────────────
    let envelope_digest = AttestationEnvelope::compute_digest(
        &session,
        &RandomnessBinding {
            id: RandomnessId::from_bytes([0u8; 16]),
            value: rand.clone(),
            epoch: session.epoch,
            session_binding: {
                let mut h = CanonicalHasher::new("tls-attestation/session-binding/v1");
                h.update_fixed(session.session_id.as_bytes());
                h.update_fixed(session.nonce.as_bytes());
                h.finalize()
            },
        },
        &transcript,
        &statement,
        &tls_attestation_attestation::engine::CoordinatorEvidence {
            engine_tag: evidence.engine_tag.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            package_digest: package.package_digest.clone(),
        },
    );

    // frost_collect_approval expects approval_signed_digest(envelope_digest),
    // not the raw envelope_digest. approval_signed_digest adds domain separation.
    let signed_digest = approval_signed_digest(&envelope_digest);
    let frost_approval = frost_collect_approval(
        &keygen.participants[..2],
        &signed_digest,
        &keygen.group_key,
        &session.quorum,
    )
    .expect("TSS approval");

    // Verify the threshold signature.
    frost_approval.verify_signature().expect("TSS signature verify");
    frost_approval.verify_binding(&envelope_digest).expect("TSS binding verify");
}

// ── Phase 4: On-chain format ───────────────────────────────────────────────────

#[test]
fn phase4_on_chain_attestation_abi_encode_decode_roundtrip() {
    let (session, vids) = make_session(3, 2);
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key.clone());

    // Run DVRF.
    let qhash = quorum_hash(&vids);
    let alpha = DvRFInput::for_session(
        &session.session_id, &session.prover_id, &session.nonce, session.epoch, &qhash,
    );
    let participants: Vec<_> = keygen.participants.iter().collect();
    let dvrf_output = dvrf.evaluate(&alpha, &participants[..2]).expect("DVRF");
    let rand = dvrf_output.value.clone();

    // Run DCTLS.
    let server_cert_hash = DigestBytes::from_bytes([0x33; 32]);
    let query = b"GET /";
    let response = b"200 OK";
    let engine = PrototypeDctlsEngine;
    let (transcript, evidence, _dctls_evidence) = engine
        .execute_dctls(&session, &rand, query, response, &server_cert_hash)
        .expect("execute_dctls");

    // Build statement + package.
    let statement = StatementPayload::new(
        b"result".to_vec(),
        "result/v1".into(),
        &transcript.session_transcript_digest,
    );
    let package = AttestationPackage::build(
        session.clone(), rand.clone(), transcript.clone(), evidence.clone(),
    );

    // TSS.
    let envelope_digest = AttestationEnvelope::compute_digest(
        &session,
        &RandomnessBinding {
            id: RandomnessId::from_bytes([0u8; 16]),
            value: rand.clone(),
            epoch: session.epoch,
            session_binding: DigestBytes::from_bytes([0u8; 32]),
        },
        &transcript,
        &statement,
        &tls_attestation_attestation::engine::CoordinatorEvidence {
            engine_tag: evidence.engine_tag.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            package_digest: package.package_digest.clone(),
        },
    );

    let frost_approval = frost_collect_approval(
        &keygen.participants[..2],
        &envelope_digest,
        &keygen.group_key,
        &session.quorum,
    ).expect("TSS");

    // Build on-chain attestation.
    let stmt_digest = derive_onchain_statement_digest("result/v1", b"result");
    let onchain = extract_on_chain_attestation(
        stmt_digest,
        *dvrf_output.value.as_bytes(),
        *envelope_digest.as_bytes(),
        &frost_approval,
        2,
        3,
    );

    // Verify on-chain (Rust implementation of smart contract logic).
    onchain.verify().expect("on-chain verify");

    // ABI encode → decode roundtrip.
    let encoded = onchain.abi_encode();
    assert_eq!(encoded.len(), 256, "ABI encoding must be 256 bytes");
    let decoded = OnChainAttestation::abi_decode(&encoded).expect("abi_decode");
    assert_eq!(decoded.statement_digest, onchain.statement_digest);
    assert_eq!(decoded.dvrf_value, onchain.dvrf_value);
    assert_eq!(decoded.envelope_digest, onchain.envelope_digest);
    assert_eq!(decoded.group_verifying_key, onchain.group_verifying_key);
    assert_eq!(decoded.aggregate_signature, onchain.aggregate_signature);
    assert_eq!(decoded.threshold, 2);
    assert_eq!(decoded.verifier_count, 3);
}

// ── Phase 5: Adversarial full-pipeline rejections ────────────────────────────

#[test]
fn phase5_check_full_rejects_wrong_dvrf_value_in_package() {
    // Coordinator presents a package with a different randomness_value than the
    // DVRF output. check_full's Check 14 catches this.
    let (session, vids) = make_session(3, 2);
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key.clone());

    let qhash = quorum_hash(&vids);
    let alpha = DvRFInput::for_session(
        &session.session_id, &session.prover_id, &session.nonce, session.epoch, &qhash,
    );
    let participants: Vec<_> = keygen.participants.iter().collect();
    let dvrf_output = dvrf.evaluate(&alpha, &participants[..2]).expect("DVRF");
    let rand = dvrf_output.value.clone();

    let server_cert_hash = DigestBytes::from_bytes([0x44; 32]);
    let engine = PrototypeDctlsEngine;
    let (transcript, evidence, dctls_evidence) = engine
        .execute_dctls(&session, &rand, b"GET /", b"OK", &server_cert_hash)
        .expect("execute_dctls");

    let statement = StatementPayload::new(
        b"result".to_vec(), "result/v1".into(), &transcript.session_transcript_digest,
    );

    // Package uses a DIFFERENT randomness value (coordinator equivocation).
    let attacker_rand = DigestBytes::from_bytes([0xFF; 32]);
    let package = AttestationPackage::build(
        session.clone(), attacker_rand, transcript, evidence,
    );

    let policy = VerificationPolicy {
        allowed_engine_tags: vec!["dx-dctls/commitment-v1".into()],
        allowed_statement_tags: vec![],
        max_session_duration_secs: 3600,
    };
    let aux_verifier = AuxiliaryVerifier::new(vids[0].clone(), policy);
    let result = aux_verifier.check_full(
        &package, &statement, &dctls_evidence, &dvrf_output, &alpha,
        &server_cert_hash, b"GET /", b"OK", UnixTimestamp(1_001_000),
    );

    // Package digest mismatch (randomness_value changed → package_digest invalid)
    // or Check 14 (randomness_value ≠ dvrf_output.value).
    assert!(
        !result.approved,
        "Coordinator equivocation on randomness must be rejected"
    );
}

#[test]
fn phase5_check_full_rejects_tampered_hsp_proof() {
    let (session, vids) = make_session(3, 2);
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key.clone());

    let qhash = quorum_hash(&vids);
    let alpha = DvRFInput::for_session(
        &session.session_id, &session.prover_id, &session.nonce, session.epoch, &qhash,
    );
    let participants: Vec<_> = keygen.participants.iter().collect();
    let dvrf_output = dvrf.evaluate(&alpha, &participants[..2]).expect("DVRF");
    let rand = dvrf_output.value.clone();

    let server_cert_hash = DigestBytes::from_bytes([0x66; 32]);
    let engine = PrototypeDctlsEngine;
    let (transcript, evidence, mut dctls_evidence) = engine
        .execute_dctls(&session, &rand, b"GET /", b"OK", &server_cert_hash)
        .expect("execute_dctls");

    let statement = StatementPayload::new(
        b"result".to_vec(), "result/v1".into(), &transcript.session_transcript_digest,
    );
    let package = AttestationPackage::build(
        session.clone(), rand.clone(), transcript, evidence,
    );

    // Tamper with the HSP commitment.
    dctls_evidence.hsp_proof.commitment = DigestBytes::from_bytes([0xAB; 32]);

    let policy = VerificationPolicy {
        allowed_engine_tags: vec!["dx-dctls/commitment-v1".into()],
        allowed_statement_tags: vec![],
        max_session_duration_secs: 3600,
    };
    let aux_verifier = AuxiliaryVerifier::new(vids[0].clone(), policy);
    let result = aux_verifier.check_full(
        &package, &statement, &dctls_evidence, &dvrf_output, &alpha,
        &server_cert_hash, b"GET /", b"OK", UnixTimestamp(1_001_000),
    );
    assert!(!result.approved, "Tampered HSP proof must be rejected by check_full");
    let reason = result.failure_reason.unwrap();
    assert!(reason.contains("HSP"), "Rejection reason must mention HSP: {reason}");
}

#[test]
fn phase5_check_full_rejects_wrong_response_in_qp() {
    let (session, vids) = make_session(3, 2);
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key.clone());

    let qhash = quorum_hash(&vids);
    let alpha = DvRFInput::for_session(
        &session.session_id, &session.prover_id, &session.nonce, session.epoch, &qhash,
    );
    let participants: Vec<_> = keygen.participants.iter().collect();
    let dvrf_output = dvrf.evaluate(&alpha, &participants[..2]).expect("DVRF");
    let rand = dvrf_output.value.clone();

    let server_cert_hash = DigestBytes::from_bytes([0x77; 32]);
    let engine = PrototypeDctlsEngine;
    let (transcript, evidence, dctls_evidence) = engine
        .execute_dctls(&session, &rand, b"GET /", b"200 OK", &server_cert_hash)
        .expect("execute_dctls");

    let statement = StatementPayload::new(
        b"result".to_vec(), "result/v1".into(), &transcript.session_transcript_digest,
    );
    let package = AttestationPackage::build(
        session.clone(), rand.clone(), transcript, evidence,
    );

    let policy = VerificationPolicy {
        allowed_engine_tags: vec!["dx-dctls/commitment-v1".into()],
        allowed_statement_tags: vec![],
        max_session_duration_secs: 3600,
    };
    let aux_verifier = AuxiliaryVerifier::new(vids[0].clone(), policy);

    // Present wrong response to check_full.
    let result = aux_verifier.check_full(
        &package, &statement, &dctls_evidence, &dvrf_output, &alpha,
        &server_cert_hash, b"GET /", b"500 Error", // Wrong response
        UnixTimestamp(1_001_000),
    );
    assert!(!result.approved, "Wrong response in QP must be rejected");
    let reason = result.failure_reason.unwrap();
    assert!(reason.contains("QP"), "Rejection reason must mention QP: {reason}");
}

// ── Phase 6: Multiple aux verifiers / quorum simulation ──────────────────────

#[test]
fn phase6_multiple_aux_verifiers_all_approve_valid_pipeline() {
    let (session, vids) = make_session(3, 2);
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key.clone());

    let qhash = quorum_hash(&vids);
    let alpha = DvRFInput::for_session(
        &session.session_id, &session.prover_id, &session.nonce, session.epoch, &qhash,
    );
    let participants: Vec<_> = keygen.participants.iter().collect();
    let dvrf_output = dvrf.evaluate(&alpha, &participants[..2]).expect("DVRF");
    let rand = dvrf_output.value.clone();

    let server_cert_hash = DigestBytes::from_bytes([0x88; 32]);
    let engine = PrototypeDctlsEngine;
    let (transcript, evidence, dctls_evidence) = engine
        .execute_dctls(&session, &rand, b"GET /balance", b"1000", &server_cert_hash)
        .expect("execute_dctls");

    let statement = StatementPayload::new(
        b"balance=1000".to_vec(), "balance/v1".into(), &transcript.session_transcript_digest,
    );
    let package = AttestationPackage::build(
        session.clone(), rand.clone(), transcript, evidence,
    );

    let policy = VerificationPolicy {
        allowed_engine_tags: vec!["dx-dctls/commitment-v1".into()],
        allowed_statement_tags: vec![],
        max_session_duration_secs: 3600,
    };

    // All 3 aux verifiers independently check the full proof chain.
    let approved_count = vids.iter().filter(|vid| {
        let aux = AuxiliaryVerifier::new((*vid).clone(), policy.clone());
        let result = aux.check_full(
            &package, &statement, &dctls_evidence, &dvrf_output, &alpha,
            &server_cert_hash, b"GET /balance", b"1000",
            UnixTimestamp(1_001_000),
        );
        result.approved
    }).count();

    assert_eq!(approved_count, 3, "All 3 aux verifiers must approve the valid attestation");
}
