//! Auxiliary verifier logic.
//!
//! The `AuxiliaryVerifier` performs all checks that an honest aux verifier
//! must perform before issuing a partial approval. These checks are:
//!
//! ## Basic checks (`check()` — checks 1–9)
//!
//! 1. Session not expired.
//! 2. Session digest matches recomputed value (binds nonce, quorum, expiry, etc.).
//! 3. Statement digest is consistent with transcript and content.
//! 4. Package digest matches recomputed value (binds randomness, transcript, evidence).
//! 5. Evidence engine tag is in the accepted set (policy check).
//! 6. Statement tag is in the accepted set (policy check, if configured).
//! 7. Session duration is within policy limits.
//! 8. Session transcript digest is internally consistent with query/response digests.
//! 9. Evidence digest is internally consistent with engine tag and bytes.
//!
//! ## Full checks (`check_full()` — checks 1–15)
//!
//! All of the above, plus:
//!
//! 10. DVRF proof verification — the randomness is the unique, bias-resistant DVRF
//!     output for this session's α, AND the proof's embedded `alpha_bytes` matches
//!     the recomputed α (prevents α-substitution attacks).
//! 11. HSP proof verification — the TLS session was established with DVRF `rand`,
//!     the `handshake_transcript_hash` is consistent with stored TLS parameters.
//! 12. QP proof verification — query/response are correctly committed.
//! 13. PGP proof verification — the statement is bound to the transcript.
//! 14. DVRF randomness consistency — `package.randomness_value == dvrf_output.value`.
//! 15. Transcript binding consistency — HSP, QP, and PGP all reference the same
//!     `session_id` and `rand_value`, and PGP is correctly linked to both.
//!     Prevents a coordinator from mixing proofs from different sessions.
//!
//! An aux verifier MUST NOT sign if any check fails. The checks are
//! independent — a failure in one does not skip the others.
//!
//! # Why checks 8 and 9 matter
//!
//! Check 8 prevents a coordinator from substituting a `session_transcript_digest`
//! that does not derive from the actual `query.digest` and `response.digest` in
//! the package. Without this check, a coordinator could present inconsistent
//! individual transcript entries while the aggregate digest looks valid.
//!
//! Check 9 prevents a coordinator from tampering with `evidence.bytes` while
//! presenting a stale `evidence_digest`. Since `package_digest` only commits
//! to `evidence_digest` (not to the raw bytes), an attacker who can predict
//! the stored digest value could substitute different bytes. This check closes
//! that gap by recomputing the evidence digest from first principles.

use crate::{
    engine::AttestationPackage,
    statement::StatementPayload,
};
use tls_attestation_core::{
    hash::CanonicalHasher,
    ids::VerifierId,
    types::UnixTimestamp,
};
#[allow(unused_imports)]
use tls_attestation_crypto;

/// Policy governing which engine tags and statement types the verifier accepts.
///
/// An empty `allowed_engine_tags` means all engines are rejected.
/// An empty `allowed_statement_tags` means all statement types are rejected.
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    pub allowed_engine_tags: Vec<String>,
    pub allowed_statement_tags: Vec<String>,
    pub max_session_duration_secs: u64,
}

impl VerificationPolicy {
    pub fn permissive() -> Self {
        Self {
            allowed_engine_tags: vec![
                "prototype-attestation/v1".into(),
                "dx-dctls/commitment-v1".into(),
            ],
            allowed_statement_tags: vec![],  // empty = accept all
            max_session_duration_secs: 3600,
        }
    }
}

/// The result of an auxiliary verifier's check.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub verifier_id: VerifierId,
    /// The package digest from the checked package.
    pub package_digest: tls_attestation_core::hash::DigestBytes,
    /// All checks passed; the verifier may issue a partial signature.
    pub approved: bool,
    /// If not approved, describes the first failing check.
    pub failure_reason: Option<String>,
}

/// Performs independent validation of an attestation package.
///
/// # Trust model
///
/// The `AuxiliaryVerifier` trusts nothing from the coordinator. It recomputes
/// all digests from first principles and rejects any package where the claimed
/// values do not match.
pub struct AuxiliaryVerifier {
    pub verifier_id: VerifierId,
    pub policy: VerificationPolicy,
}

impl AuxiliaryVerifier {
    pub fn new(verifier_id: VerifierId, policy: VerificationPolicy) -> Self {
        Self { verifier_id, policy }
    }

    /// Validate an `AttestationPackage`.
    ///
    /// Returns a `VerificationResult` indicating whether approval can be granted.
    /// Never panics; all errors are returned as `VerificationResult { approved: false }`.
    pub fn check(
        &self,
        package: &AttestationPackage,
        statement: &StatementPayload,
        now: UnixTimestamp,
    ) -> VerificationResult {
        let fail = |reason: String| VerificationResult {
            verifier_id: self.verifier_id.clone(),
            package_digest: package.package_digest.clone(),
            approved: false,
            failure_reason: Some(reason),
        };

        // ── Check 1: Session expiry ──────────────────────────────────────────
        if package.session_context.is_expired(now) {
            return fail("session has expired".into());
        }

        // ── Check 2: Session digest consistency ──────────────────────────────
        // Recompute the session digest and verify it matches the claimed value.
        let expected_session_digest = {
            let sc = &package.session_context;
            let mut h = CanonicalHasher::new("tls-attestation/session-context/v1");
            h.update_fixed(sc.session_id.as_bytes());
            h.update_fixed(sc.prover_id.as_bytes());
            h.update_fixed(sc.coordinator_id.as_bytes());
            h.update_u64(sc.epoch.0);
            h.update_u64(sc.created_at.0);
            h.update_u64(sc.expires_at.0);
            h.update_fixed(sc.nonce.as_bytes());
            h.update_u64(sc.quorum.threshold as u64);
            h.update_u64(sc.quorum.verifiers.len() as u64);
            for v in &sc.quorum.verifiers {
                h.update_fixed(v.as_bytes());
            }
            h.finalize()
        };
        if package.session_context.session_digest != expected_session_digest {
            return fail("session digest mismatch".into());
        }

        // ── Check 3: Statement digest consistency ────────────────────────────
        if !statement.verify_digest(&package.transcript_commitments.session_transcript_digest) {
            return fail("statement digest does not match transcript".into());
        }

        // ── Check 4: Package digest consistency ──────────────────────────────
        let expected_package_digest = AttestationPackage::compute_digest(
            &package.session_context.session_digest,
            &package.randomness_value,
            &package.transcript_commitments.session_transcript_digest,
            &package.evidence.evidence_digest,
        );
        if package.package_digest != expected_package_digest {
            return fail("package digest mismatch".into());
        }

        // ── Check 5: Engine tag policy ───────────────────────────────────────
        if !self
            .policy
            .allowed_engine_tags
            .contains(&package.evidence.engine_tag)
        {
            return fail(format!(
                "engine tag '{}' is not in policy",
                package.evidence.engine_tag
            ));
        }

        // ── Check 6: Statement tag policy (if non-empty) ─────────────────────
        if !self.policy.allowed_statement_tags.is_empty()
            && !self
                .policy
                .allowed_statement_tags
                .contains(&statement.derivation_tag)
        {
            return fail(format!(
                "statement tag '{}' is not in policy",
                statement.derivation_tag
            ));
        }

        // ── Check 7: Session duration policy ─────────────────────────────────
        let duration = package
            .session_context
            .expires_at
            .0
            .saturating_sub(package.session_context.created_at.0);
        if duration > self.policy.max_session_duration_secs {
            return fail(format!(
                "session duration {duration}s exceeds policy maximum {}s",
                self.policy.max_session_duration_secs
            ));
        }

        // ── Check 8: Session transcript digest internal consistency ──────────
        // Recompute session_transcript_digest from the individual query and
        // response digests and verify it matches the stored value.
        //
        // Security rationale: `package_digest` commits to `session_transcript_digest`
        // but not to the individual query/response digests. Without this check, a
        // coordinator could substitute a `session_transcript_digest` that does not
        // derive from the presented query/response commitments. An inconsistency
        // here indicates tampering with transcript structure.
        let expected_session_transcript_digest = {
            let tc = &package.transcript_commitments;
            let mut h = CanonicalHasher::new("tls-attestation/session-transcript/v1");
            h.update_fixed(package.session_context.session_id.as_bytes());
            h.update_digest(&tc.query.digest);
            h.update_digest(&tc.response.digest);
            h.finalize()
        };
        if package.transcript_commitments.session_transcript_digest
            != expected_session_transcript_digest
        {
            return fail(
                "session transcript digest is inconsistent with query/response commitments".into(),
            );
        }

        // ── Check 9: Evidence digest internal consistency ─────────────────────
        // Recompute evidence_digest from engine_tag and bytes, and verify it
        // matches the stored value.
        //
        // Security rationale: `package_digest` commits to `evidence_digest` but
        // not to the raw evidence bytes. Without this check, a coordinator could
        // present tampered `evidence.bytes` paired with a stale `evidence_digest`.
        let expected_evidence_digest = {
            let mut h = CanonicalHasher::new("tls-attestation/evidence/v1");
            h.update_bytes(package.evidence.engine_tag.as_bytes());
            h.update_bytes(&package.evidence.bytes);
            h.finalize()
        };
        if package.evidence.evidence_digest != expected_evidence_digest {
            return fail("evidence digest is inconsistent with engine tag and bytes".into());
        }

        VerificationResult {
            verifier_id: self.verifier_id.clone(),
            package_digest: package.package_digest.clone(),
            approved: true,
            failure_reason: None,
        }
    }

    /// Full verification including DVRF proof and dx-DCTLS proof chain.
    ///
    /// Only available when the `frost` feature is enabled.
    ///
    /// This is the method aux verifiers MUST call in production. It extends
    /// `check()` with:
    ///
    /// - **Check 10**: DVRF proof verification (FrostDvRF::verify).
    ///   Ensures the randomness `rand` is the unique, bias-resistant output
    ///   of the DVRF evaluation for this session's α.
    ///
    /// - **Check 11**: HSP proof verification.
    ///   Ensures the TLS session was established using `rand` as randomness.
    ///
    /// - **Check 12**: QP proof verification.
    ///   Ensures Q̂ and R̂ are correctly committed from actual query/response.
    ///
    /// - **Check 13**: PGP proof verification.
    ///   Ensures the statement is correctly derived from the transcript.
    ///
    /// - **Check 14**: DVRF randomness consistency.
    ///   Ensures the `randomness_value` in the package equals the DVRF output.
    ///
    /// # Trust model
    ///
    /// An aux verifier calling `check_full` trusts NOTHING from the coordinator.
    /// Even if the coordinator is fully malicious, passing all 14 checks guarantees:
    /// 1. The randomness is the unique DVRF output for this session's α.
    /// 2. The TLS session used that randomness.
    /// 3. The query/response are bound to the session and randomness.
    /// 4. The statement is correctly derived from the transcript.
    ///
    /// # When to use
    ///
    /// Use `check_full` when `DctlsEvidence` is available in the package.
    /// Use `check` when only the basic package is available (legacy support).
    #[cfg(feature = "frost")]
    pub fn check_full(
        &self,
        package: &AttestationPackage,
        statement: &StatementPayload,
        dctls_evidence: &crate::dctls::DctlsEvidence,
        dvrf_output: &tls_attestation_crypto::dvrf::DvRFOutput,
        dvrf_input: &tls_attestation_crypto::dvrf::DvRFInput,
        server_cert_hash: &tls_attestation_core::hash::DigestBytes,
        query: &[u8],
        response: &[u8],
        now: tls_attestation_core::types::UnixTimestamp,
    ) -> VerificationResult {
        // First run all basic checks (1-9).
        let basic = self.check(package, statement, now);
        if !basic.approved {
            return basic;
        }

        let fail = |reason: String| VerificationResult {
            verifier_id: self.verifier_id.clone(),
            package_digest: package.package_digest.clone(),
            approved: false,
            failure_reason: Some(reason),
        };

        // ── Check 10: DVRF proof verification ────────────────────────────────
        // Verifies the aggregate Schnorr signature over α AND checks that the
        // proof's embedded alpha_bytes matches the provided DVRF input (prevents
        // α-substitution attacks where a coordinator presents a proof for α' while
        // claiming the session used α).
        if let Err(e) = tls_attestation_crypto::dvrf::FrostDvRF::verify(dvrf_input, dvrf_output) {
            return fail(format!("DVRF proof verification failed: {e}"));
        }

        // ── Check 11: HSP proof verification ─────────────────────────────────
        if let Err(e) = crate::dctls::verify_hsp_proof(
            &dctls_evidence.hsp_proof,
            &dvrf_output.value,
            server_cert_hash,
        ) {
            return fail(format!("HSP proof verification failed: {e}"));
        }

        // ── Check 12: QP proof verification ──────────────────────────────────
        if let Err(e) = crate::dctls::verify_query_record(
            &dctls_evidence.query_record,
            query,
            response,
        ) {
            return fail(format!("QP proof verification failed: {e}"));
        }

        // ── Check 13: PGP proof verification ─────────────────────────────────
        if let Err(e) = crate::dctls::verify_pgp_proof(
            &dctls_evidence.pgp_proof,
            &dvrf_output.value,
            &dctls_evidence.hsp_proof,
        ) {
            return fail(format!("PGP proof verification failed: {e}"));
        }

        // ── Check 14: DVRF randomness consistency ────────────────────────────
        // The package's randomness_value must equal the DVRF output value.
        // This prevents a coordinator from using one DVRF for the package digest
        // and a different (biased) randomness for the DCTLS proofs.
        if package.randomness_value != dvrf_output.value {
            return fail("package randomness_value does not match DVRF output".into());
        }

        // ── Check 15: Transcript binding consistency ─────────────────────────
        // Verify that HSP, QP, and PGP all reference the same session and DVRF
        // randomness, and that PGP is correctly linked to both QP and HSP.
        //
        // This check is independent of the individual proof verifications in
        // Checks 11–13. A coordinator could (theoretically) present individually
        // valid proofs that reference different sessions. This check catches that.
        //
        // The `TranscriptBinding` returned here could be used as the public input
        // to a future co-SNARK backend.
        if let Err(e) = crate::dctls::verify_transcript_consistency(
            &dctls_evidence.hsp_proof,
            &dctls_evidence.query_record,
            &dctls_evidence.pgp_proof,
        ) {
            return fail(format!("transcript binding consistency check failed: {e}"));
        }

        VerificationResult {
            verifier_id: self.verifier_id.clone(),
            package_digest: package.package_digest.clone(),
            approved: true,
            failure_reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::{AttestationPackage, ExportableEvidence, PrototypeAttestationEngine, PROTOTYPE_ENGINE_TAG, AttestationEngine},
        session::SessionContext,
        statement::StatementPayload,
    };
    use tls_attestation_core::{
        hash::DigestBytes,
        ids::{ProverId, SessionId, VerifierId},
        types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
    };

    fn make_session(created: u64, expires: u64) -> SessionContext {
        let quorum = QuorumSpec::new(
            vec![VerifierId::from_bytes([1u8; 32]), VerifierId::from_bytes([2u8; 32])],
            2,
        )
        .unwrap();
        SessionContext::new(
            SessionId::from_bytes([5u8; 16]),
            ProverId::from_bytes([0u8; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum,
            Epoch::GENESIS,
            UnixTimestamp(created),
            UnixTimestamp(expires),
            Nonce::from_bytes([7u8; 32]),
        )
    }

    fn make_package(session: SessionContext, rng: DigestBytes) -> (AttestationPackage, StatementPayload) {
        let engine = PrototypeAttestationEngine;
        let (transcript, evidence) = engine.execute(&session, &rng, b"GET /", b"200 OK").unwrap();

        let statement = StatementPayload::new(
            b"result".to_vec(),
            "test/v1".into(),
            &transcript.session_transcript_digest,
        );

        let package = AttestationPackage::build(session, rng, transcript, evidence);
        (package, statement)
    }

    fn verifier() -> AuxiliaryVerifier {
        AuxiliaryVerifier::new(
            VerifierId::from_bytes([99u8; 32]),
            VerificationPolicy::permissive(),
        )
    }

    #[test]
    fn valid_package_is_approved() {
        // Session duration: 1000s, within the policy max of 3600s.
        let session = make_session(1000, 2000);
        let (package, statement) = make_package(session, DigestBytes::from_bytes([1u8; 32]));
        let result = verifier().check(&package, &statement, UnixTimestamp(1500));
        assert!(result.approved, "expected approval, got: {:?}", result.failure_reason);
    }

    #[test]
    fn expired_session_is_rejected() {
        let session = make_session(100, 200);
        let (package, statement) = make_package(session, DigestBytes::from_bytes([1u8; 32]));
        let result = verifier().check(&package, &statement, UnixTimestamp(300));
        assert!(!result.approved);
        assert!(result.failure_reason.unwrap().contains("expired"));
    }

    #[test]
    fn tampered_statement_content_is_rejected() {
        let session = make_session(100, 9999999);
        let (package, mut statement) = make_package(session, DigestBytes::from_bytes([1u8; 32]));
        statement.content = b"tampered".to_vec();
        let result = verifier().check(&package, &statement, UnixTimestamp(500));
        assert!(!result.approved);
        assert!(result.failure_reason.unwrap().contains("statement digest"));
    }

    #[test]
    fn tampered_package_digest_is_rejected() {
        let session = make_session(100, 9999999);
        let (mut package, statement) = make_package(session, DigestBytes::from_bytes([1u8; 32]));
        package.package_digest = DigestBytes::from_bytes([0xFF; 32]);
        let result = verifier().check(&package, &statement, UnixTimestamp(500));
        assert!(!result.approved);
        assert!(result.failure_reason.unwrap().contains("package digest"));
    }

    #[test]
    fn disallowed_engine_tag_is_rejected() {
        let session = make_session(100, 9999999);
        let (mut package, statement) = make_package(session, DigestBytes::from_bytes([1u8; 32]));

        // Directly mutate the engine tag without recomputing digests.
        // This simulates a coordinator substituting a different engine after packaging.
        // However, that would also break the package digest, so this test focuses
        // on the engine tag check by using a fresh package and policy.
        let policy = VerificationPolicy {
            allowed_engine_tags: vec!["real-tls-engine/v1".into()],
            allowed_statement_tags: vec![],
            max_session_duration_secs: 3600,
        };
        let v = AuxiliaryVerifier::new(VerifierId::from_bytes([99u8; 32]), policy);
        let result = v.check(&package, &statement, UnixTimestamp(500));
        assert!(!result.approved);
        assert!(result.failure_reason.unwrap().contains("engine tag"));
    }
}
