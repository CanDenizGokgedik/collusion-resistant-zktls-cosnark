//! Adversarial security tests for the Π_coll-min protocol.
//!
//! Tests that the system correctly rejects attacks under:
//! - Malicious coordinator (equivocation, substitution)
//! - Corrupted verifier (tampered proofs)
//! - Replay attacks
//! - Cross-session attacks
//!
//! These tests validate the TAU security property:
//! forgery requires breaking DVRF OR dx-DCTLS unforgeability.

use tls_attestation_attestation::{
    dctls::{
        verify_hsp_proof, verify_pgp_proof, verify_query_record,
        DctlsEvidence, HSPProof, PGPProof, QueryRecord, SessionParamsPublic,
        SessionParamsSecret, Statement,
    },
    engine::{AttestationEngine, AttestationPackage, PrototypeAttestationEngine},
    statement::StatementPayload,
    verify::{AuxiliaryVerifier, VerificationPolicy},
};
use tls_attestation_core::{
    hash::{CanonicalHasher, DigestBytes},
    ids::{ProverId, SessionId, VerifierId},
    types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_session(seed: u8) -> tls_attestation_attestation::session::SessionContext {
    let quorum = QuorumSpec::new(
        vec![VerifierId::from_bytes([seed; 32]), VerifierId::from_bytes([seed + 1; 32])],
        2,
    )
    .unwrap();
    // Session duration: 2000s (within permissive policy max of 3600s).
    tls_attestation_attestation::session::SessionContext::new(
        SessionId::from_bytes([seed; 16]),
        ProverId::from_bytes([seed + 1; 32]),
        VerifierId::from_bytes([seed; 32]),
        quorum,
        Epoch::GENESIS,
        UnixTimestamp(1_000_000),
        UnixTimestamp(1_002_000), // 2000s duration
        Nonce::from_bytes([seed + 2; 32]),
    )
}

fn make_rand(seed: u8) -> DigestBytes {
    DigestBytes::from_bytes([seed; 32])
}

fn make_cert_hash(seed: u8) -> DigestBytes {
    DigestBytes::from_bytes([seed; 32])
}

fn make_sps(session_id: &SessionId, rand: &DigestBytes) -> SessionParamsSecret {
    let mut h = CanonicalHasher::new("test/exporter");
    h.update_fixed(session_id.as_bytes());
    h.update_digest(rand);
    let dvrf_exporter = h.finalize();
    SessionParamsSecret {
        dvrf_exporter,
        session_nonce: DigestBytes::from_bytes([99u8; 32]),
    }
}

fn make_spp(cert: DigestBytes) -> SessionParamsPublic {
    let established_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    SessionParamsPublic {
        server_cert_hash: cert,
        tls_version: 0x0304,
        server_name: "example.com".into(),
        established_at,
    }
}

fn make_dctls_evidence(
    session_id: &SessionId,
    rand: &DigestBytes,
    cert: &DigestBytes,
    query: &[u8],
    response: &[u8],
) -> DctlsEvidence {
    let sps = make_sps(session_id, rand);
    let spp = make_spp(cert.clone());
    let hsp = HSPProof::generate(session_id, rand, &sps, &spp);
    let qp = QueryRecord::build(session_id, rand, query, response);
    let stmt = Statement::derive(
        b"test-statement".to_vec(),
        "test/v1".into(),
        &qp.transcript_commitment,
    );
    let pgp = PGPProof::generate(session_id, rand, &qp, stmt, &hsp);
    DctlsEvidence { hsp_proof: hsp, query_record: qp, pgp_proof: pgp }
}

fn verifier() -> AuxiliaryVerifier {
    AuxiliaryVerifier::new(
        VerifierId::from_bytes([99u8; 32]),
        VerificationPolicy::permissive(),
    )
}

fn make_package_and_statement(
    session: &tls_attestation_attestation::session::SessionContext,
    rand: &DigestBytes,
) -> (AttestationPackage, StatementPayload) {
    let engine = PrototypeAttestationEngine;
    let (transcript, evidence) = engine
        .execute(session, rand, b"GET /api", b"200 OK")
        .unwrap();
    let statement = StatementPayload::new(
        b"result".to_vec(),
        "test/v1".into(),
        &transcript.session_transcript_digest,
    );
    let package = AttestationPackage::build(
        session.clone(),
        rand.clone(),
        transcript,
        evidence,
    );
    (package, statement)
}

// ── Coordinator adversary tests ───────────────────────────────────────────────

#[test]
fn malicious_coordinator_tampered_randomness_rejected_by_package_digest() {
    // A malicious coordinator substitutes a different randomness value in the
    // package after the DVRF has run. The package_digest check (Check 4) catches this.
    let session = make_session(1);
    let real_rand = make_rand(10);
    let (mut package, statement) = make_package_and_statement(&session, &real_rand);

    // Coordinator substitutes a different randomness value.
    package.randomness_value = make_rand(99);

    let result = verifier().check(&package, &statement, UnixTimestamp(1_001_000));
    assert!(
        !result.approved,
        "Substituted randomness must be rejected by package digest check"
    );
    assert!(result.failure_reason.unwrap().contains("package digest"));
}

#[test]
fn malicious_coordinator_tampered_transcript_rejected() {
    // Coordinator substitutes a tampered session_transcript_digest.
    let session = make_session(2);
    let rand = make_rand(20);
    let (mut package, statement) = make_package_and_statement(&session, &rand);

    // Tamper with the transcript digest.
    package.transcript_commitments.session_transcript_digest =
        DigestBytes::from_bytes([0xFF; 32]);

    let result = verifier().check(&package, &statement, UnixTimestamp(1_001_000));
    assert!(!result.approved, "Tampered transcript must be rejected");
}

#[test]
fn malicious_coordinator_tampered_evidence_rejected() {
    // Coordinator modifies evidence bytes after the evidence digest was computed.
    let session = make_session(3);
    let rand = make_rand(30);
    let (mut package, statement) = make_package_and_statement(&session, &rand);

    // Tamper with raw evidence bytes (without updating the evidence_digest).
    // This will be caught by Check 4 (package_digest) because the package_digest
    // commits to evidence_digest, which no longer matches the tampered bytes.
    // Alternatively, if package_digest matches somehow, Check 9 catches it.
    package.evidence.bytes = b"tampered-evidence".to_vec();

    let result = verifier().check(&package, &statement, UnixTimestamp(1_001_000));
    assert!(!result.approved, "Tampered evidence bytes must be rejected");
    // The rejection may come from package digest (Check 4) or evidence digest (Check 9).
    let reason = result.failure_reason.unwrap();
    assert!(
        reason.contains("package digest") || reason.contains("evidence digest"),
        "Unexpected rejection reason: {reason}"
    );
}

#[test]
fn malicious_coordinator_wrong_session_digest_rejected() {
    // Coordinator substitutes a session with a different nonce but claims the
    // same session_digest.
    let session = make_session(4);
    let rand = make_rand(40);
    let (mut package, statement) = make_package_and_statement(&session, &rand);

    // Substitute a different nonce while keeping the old session_digest.
    package.session_context.nonce = Nonce::from_bytes([0xAA; 32]);

    let result = verifier().check(&package, &statement, UnixTimestamp(1_001_000));
    assert!(!result.approved, "Modified nonce must be rejected by session digest check");
    assert!(result.failure_reason.unwrap().contains("session digest"));
}

// ── Replay attack tests ────────────────────────────────────────────────────────

#[test]
fn replay_of_expired_session_rejected() {
    // An attacker replays a valid package after session expiry.
    let session = make_session(5);
    let rand = make_rand(50);
    let (package, statement) = make_package_and_statement(&session, &rand);

    // Session expires at UnixTimestamp(1_002_000); present it after expiry.
    let result = verifier().check(&package, &statement, UnixTimestamp(1_003_000));
    assert!(!result.approved, "Expired session replay must be rejected");
    assert!(result.failure_reason.unwrap().contains("expired"));
}

#[test]
fn cross_session_statement_not_transferable() {
    // A statement derived from session A cannot be reused for session B.
    // The statement binds to session_transcript_digest, which includes session_id.
    let session_a = make_session(6);
    let session_b = make_session(7); // Different session_id, different nonce
    let rand = make_rand(60);

    let engine = PrototypeAttestationEngine;
    let (transcript_a, _evidence_a) = engine.execute(&session_a, &rand, b"GET /", b"OK").unwrap();
    let (transcript_b, evidence_b) = engine.execute(&session_b, &rand, b"GET /", b"OK").unwrap();

    // Statement derived from session A's transcript.
    let statement_a = StatementPayload::new(
        b"result".to_vec(),
        "test/v1".into(),
        &transcript_a.session_transcript_digest,
    );

    // Package from session B.
    let package_b = AttestationPackage::build(
        session_b,
        rand,
        transcript_b,
        evidence_b,
    );

    // Presenting session A's statement with session B's package must fail.
    let result = verifier().check(&package_b, &statement_a, UnixTimestamp(1_001_000));
    assert!(
        !result.approved,
        "Cross-session statement substitution must be rejected"
    );
    assert!(result.failure_reason.unwrap().contains("statement digest"));
}

// ── DCTLS adversary tests ─────────────────────────────────────────────────────

#[test]
fn hsp_proof_with_wrong_rand_rejected() {
    let session_id = SessionId::from_bytes([10u8; 16]);
    let real_rand = make_rand(10);
    let wrong_rand = make_rand(11);
    let cert = make_cert_hash(10);

    let evidence = make_dctls_evidence(&session_id, &real_rand, &cert, b"GET /", b"OK");

    // Verify with wrong rand fails.
    let result = verify_hsp_proof(&evidence.hsp_proof, &wrong_rand, &cert);
    assert!(result.is_err(), "HSP with wrong rand must be rejected");
}

#[test]
fn hsp_proof_tampered_commitment_rejected() {
    let session_id = SessionId::from_bytes([11u8; 16]);
    let rand = make_rand(11);
    let cert = make_cert_hash(11);

    let mut evidence = make_dctls_evidence(&session_id, &rand, &cert, b"GET /", b"OK");

    // Tamper with the HSP commitment.
    evidence.hsp_proof.commitment = DigestBytes::from_bytes([0xAB; 32]);

    let result = verify_hsp_proof(&evidence.hsp_proof, &rand, &cert);
    assert!(result.is_err(), "Tampered HSP commitment must be rejected");
}

#[test]
fn qp_proof_with_different_query_rejected() {
    let session_id = SessionId::from_bytes([12u8; 16]);
    let rand = make_rand(12);
    let cert = make_cert_hash(12);

    let evidence = make_dctls_evidence(&session_id, &rand, &cert, b"GET /api", b"200 OK");

    // Try to verify with a different query.
    let result = verify_query_record(&evidence.query_record, b"POST /api", b"200 OK");
    assert!(result.is_err(), "Wrong query must be rejected");
}

#[test]
fn qp_proof_from_different_session_rejected() {
    // A QP record from session A cannot be presented for session B.
    let session_a = SessionId::from_bytes([13u8; 16]);
    let session_b = SessionId::from_bytes([14u8; 16]);
    let rand = make_rand(13);
    let cert = make_cert_hash(13);

    let evidence_a = make_dctls_evidence(&session_a, &rand, &cert, b"GET /", b"OK");

    // Present session A's QP record with session B's rand context.
    // The commitment includes session_id, so it won't match.
    // Verify against session_b would require recomputing with session_b,
    // but the record.session_id is session_a — detect via commitment.
    // Verify query record normally (it embeds session_id in commitment).
    // Change the session_id in the record to see if verification catches it.
    let mut tampered_record = evidence_a.query_record.clone();
    tampered_record.session_id = session_b;

    let result = verify_query_record(&tampered_record, b"GET /", b"OK");
    assert!(result.is_err(),
        "QP record with substituted session_id must fail (commitment won't match)");
}

#[test]
fn pgp_proof_tampered_statement_content_rejected() {
    let session_id = SessionId::from_bytes([15u8; 16]);
    let rand = make_rand(15);
    let cert = make_cert_hash(15);

    let mut evidence = make_dctls_evidence(&session_id, &rand, &cert, b"GET /", b"OK");

    // Tamper with statement content.
    evidence.pgp_proof.statement.content = b"forged statement".to_vec();

    let result = verify_pgp_proof(
        &evidence.pgp_proof,
        &rand,
        &evidence.hsp_proof,
    );
    assert!(result.is_err(), "Tampered statement content must be rejected");
}

#[test]
fn pgp_proof_substituted_hsp_digest_rejected() {
    // Coordinator presents a PGP proof that references a different HSP session.
    let session_id = SessionId::from_bytes([16u8; 16]);
    let rand = make_rand(16);
    let cert = make_cert_hash(16);

    let mut evidence = make_dctls_evidence(&session_id, &rand, &cert, b"GET /", b"OK");

    // Replace the HSP proof digest with a random value.
    evidence.pgp_proof.hsp_proof_digest = DigestBytes::from_bytes([0xCC; 32]);

    let result = verify_pgp_proof(
        &evidence.pgp_proof,
        &rand,
        &evidence.hsp_proof,
    );
    assert!(result.is_err(), "Substituted HSP proof digest must be rejected");
}

#[test]
fn full_dctls_verify_all_succeeds_for_valid_evidence() {
    let session_id = SessionId::from_bytes([17u8; 16]);
    let rand = make_rand(17);
    let cert = make_cert_hash(17);

    let evidence = make_dctls_evidence(&session_id, &rand, &cert, b"GET /", b"200 OK");

    evidence.verify_all(&rand, &cert, b"GET /", b"200 OK")
        .expect("Valid evidence must verify successfully");
}

#[test]
fn full_dctls_verify_all_fails_for_wrong_response() {
    let session_id = SessionId::from_bytes([18u8; 16]);
    let rand = make_rand(18);
    let cert = make_cert_hash(18);

    let evidence = make_dctls_evidence(&session_id, &rand, &cert, b"GET /", b"200 OK");

    let result = evidence.verify_all(&rand, &cert, b"GET /", b"500 Error");
    assert!(result.is_err(), "Wrong response must fail verify_all");
}

// ── Statement forgery tests ────────────────────────────────────────────────────

#[test]
fn statement_digest_change_invalidates_package() {
    // A forger attempts to substitute a different statement while keeping the
    // same package digest. This requires recomputing the package_digest, which
    // they cannot do without access to the session transcript.
    let session = make_session(20);
    let rand = make_rand(80);
    let (package, _real_statement) = make_package_and_statement(&session, &rand);

    // Create a different statement (not bound to this session's transcript).
    let forged_statement = StatementPayload::new(
        b"forged claim".to_vec(),
        "test/v1".into(),
        &DigestBytes::from_bytes([0xDE; 32]), // Wrong transcript digest
    );

    let result = verifier().check(&package, &forged_statement, UnixTimestamp(1_001_000));
    assert!(!result.approved, "Forged statement must be rejected");
}

#[test]
fn statement_with_correct_tag_but_wrong_content_rejected() {
    let session = make_session(21);
    let rand = make_rand(90);
    let (package, mut statement) = make_package_and_statement(&session, &rand);

    // Modify statement content without updating digest.
    statement.content = b"malicious content".to_vec();

    let result = verifier().check(&package, &statement, UnixTimestamp(1_001_000));
    assert!(!result.approved, "Modified statement content must be rejected");
}
