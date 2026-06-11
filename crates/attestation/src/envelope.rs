//! The `AttestationEnvelope` — the canonical, on-chain-consumable output.
//!
//! The envelope is the final artifact of the attestation protocol. It binds
//! together the session context, randomness, transcript, statement, coordinator
//! evidence, and threshold approval into a single value with a canonical digest.
//!
//! # Security
//!
//! The `envelope_digest` commits to every field in a fixed, documented order.
//! Any modification of any field produces a different digest, which will not
//! match the signatures in `threshold_approval`. This makes the envelope
//! tamper-evident and non-repudiable.

use crate::{engine::CoordinatorEvidence, session::SessionContext, statement::StatementPayload};
use serde::{Deserialize, Serialize};
use tls_attestation_core::{
    hash::{CanonicalHasher, DigestBytes},
    ids::RandomnessId,
    types::Epoch,
};
use tls_attestation_crypto::{
    threshold::ThresholdApproval, transcript::TranscriptCommitments,
};

/// The randomness binding included in an `AttestationEnvelope`.
///
/// Aux verifiers check that:
/// 1. `session_binding` matches `H("session-binding/v1" || session_id || nonce)`.
/// 2. `value` is consistent with the verifier set's DVRF output.
/// 3. `epoch` matches the current epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomnessBinding {
    pub id: RandomnessId,
    /// The combined DVRF output for this session.
    pub value: DigestBytes,
    /// The epoch during which randomness was generated.
    pub epoch: Epoch,
    /// H("session-binding/v1" || session_id || nonce)
    pub session_binding: DigestBytes,
}

/// The final, canonical attestation artifact.
///
/// This value is suitable for on-chain consumption. A smart contract verifier
/// can:
/// 1. Recompute `envelope_digest` from the fields.
/// 2. Verify the threshold approval signatures against known verifier public keys.
/// 3. Check that `quorum.threshold` is satisfied.
/// 4. Check `expires_at` against the current block time.
///
/// # Canonical digest field order
///
/// All fields are hashed in the order they appear in the struct:
/// 1. session_id
/// 2. prover_id
/// 3. coordinator_id
/// 4. epoch
/// 5. created_at
/// 6. expires_at
/// 7. nonce
/// 8. threshold
/// 9. verifier_count
/// 10. each verifier_id
/// 11. randomness.id
/// 12. randomness.value
/// 13. randomness.epoch
/// 14. randomness.session_binding
/// 15. transcript.query_digest
/// 16. transcript.response_digest
/// 17. transcript.session_transcript_digest
/// 18. statement.derivation_tag
/// 19. statement.statement_digest
/// 20. coordinator_evidence.engine_tag
/// 21. coordinator_evidence.evidence_digest
/// 22. coordinator_evidence.package_digest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEnvelope {
    pub session: SessionContext,
    pub randomness: RandomnessBinding,
    pub transcript: TranscriptCommitments,
    pub statement: StatementPayload,
    pub coordinator_evidence: CoordinatorEvidence,
    pub threshold_approval: ThresholdApproval,
    /// Canonical digest over all above fields, in the documented order.
    pub envelope_digest: DigestBytes,
}

impl AttestationEnvelope {
    /// Compute the canonical `envelope_digest` from the envelope components.
    ///
    /// This is the only method that defines the canonical field order.
    /// Any change to the field order is a protocol-breaking change.
    pub fn compute_digest(
        session: &SessionContext,
        randomness: &RandomnessBinding,
        transcript: &TranscriptCommitments,
        statement: &StatementPayload,
        coordinator_evidence: &CoordinatorEvidence,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/envelope/v1");

        // Session fields.
        h.update_fixed(session.session_id.as_bytes());
        h.update_fixed(session.prover_id.as_bytes());
        h.update_fixed(session.coordinator_id.as_bytes());
        h.update_u64(session.epoch.0);
        h.update_u64(session.created_at.0);
        h.update_u64(session.expires_at.0);
        h.update_fixed(session.nonce.as_bytes());
        h.update_u64(session.quorum.threshold as u64);
        h.update_u64(session.quorum.verifiers.len() as u64);
        for v in &session.quorum.verifiers {
            h.update_fixed(v.as_bytes());
        }

        // Randomness binding.
        h.update_fixed(randomness.id.as_bytes());
        h.update_digest(&randomness.value);
        h.update_u64(randomness.epoch.0);
        h.update_digest(&randomness.session_binding);

        // Transcript commitments.
        h.update_digest(&transcript.query.digest);
        h.update_digest(&transcript.response.digest);
        h.update_digest(&transcript.session_transcript_digest);

        // Statement.
        h.update_bytes(statement.derivation_tag.as_bytes());
        h.update_digest(&statement.statement_digest);

        // Coordinator evidence.
        h.update_bytes(coordinator_evidence.engine_tag.as_bytes());
        h.update_digest(&coordinator_evidence.evidence_digest);
        h.update_digest(&coordinator_evidence.package_digest);

        h.finalize()
    }

    /// Construct an envelope from assembled components, computing the digest.
    pub fn assemble(
        session: SessionContext,
        randomness: RandomnessBinding,
        transcript: TranscriptCommitments,
        statement: StatementPayload,
        coordinator_evidence: CoordinatorEvidence,
        threshold_approval: ThresholdApproval,
    ) -> Self {
        let envelope_digest =
            Self::compute_digest(&session, &randomness, &transcript, &statement, &coordinator_evidence);
        Self {
            session,
            randomness,
            transcript,
            statement,
            coordinator_evidence,
            threshold_approval,
            envelope_digest,
        }
    }

    /// Verify the envelope's internal consistency.
    ///
    /// Checks that `envelope_digest` matches the recomputed digest from fields.
    /// Does NOT verify the threshold approval signatures (use
    /// `tls_attestation_crypto::threshold::verify_threshold_approval` for that).
    pub fn verify_digest(&self) -> bool {
        let expected = Self::compute_digest(
            &self.session,
            &self.randomness,
            &self.transcript,
            &self.statement,
            &self.coordinator_evidence,
        );
        self.envelope_digest == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::{CoordinatorEvidence, PrototypeAttestationEngine, PROTOTYPE_ENGINE_TAG, AttestationEngine, AttestationPackage},
        session::SessionContext,
        statement::StatementPayload,
    };
    use tls_attestation_core::{
        hash::DigestBytes,
        ids::{ProverId, RandomnessId, SessionId, VerifierId},
        types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
    };
    use tls_attestation_crypto::threshold::{ThresholdApproval, aggregate_signatures, approval_signed_digest, PrototypeThresholdSigner, ThresholdSigner};

    fn make_session() -> SessionContext {
        let quorum = QuorumSpec::new(
            vec![VerifierId::from_bytes([1u8; 32]), VerifierId::from_bytes([2u8; 32])],
            2,
        )
        .unwrap();
        SessionContext::new(
            SessionId::from_bytes([0u8; 16]),
            ProverId::from_bytes([0u8; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum,
            Epoch::GENESIS,
            UnixTimestamp(100),
            UnixTimestamp(9999999),
            Nonce::from_bytes([42u8; 32]),
        )
    }

    #[test]
    fn envelope_digest_is_deterministic() {
        let session = make_session();
        let rng_value = DigestBytes::from_bytes([1u8; 32]);
        let engine = PrototypeAttestationEngine;
        let (transcript, evidence) = engine
            .execute(&session, &rng_value, b"query", b"response")
            .unwrap();

        let randomness = RandomnessBinding {
            id: RandomnessId::from_bytes([0u8; 16]),
            value: rng_value.clone(),
            epoch: Epoch::GENESIS,
            session_binding: DigestBytes::from_bytes([3u8; 32]),
        };

        let statement = StatementPayload::new(
            b"claim".to_vec(),
            "test/v1".into(),
            &transcript.session_transcript_digest,
        );

        let package_digest = AttestationPackage::compute_digest(
            &session.session_digest,
            &rng_value,
            &transcript.session_transcript_digest,
            &evidence.evidence_digest,
        );

        let coord_evidence = CoordinatorEvidence {
            engine_tag: PROTOTYPE_ENGINE_TAG.to_string(),
            evidence_digest: evidence.evidence_digest.clone(),
            package_digest,
        };

        let d1 = AttestationEnvelope::compute_digest(
            &session, &randomness, &transcript, &statement, &coord_evidence,
        );
        let d2 = AttestationEnvelope::compute_digest(
            &session, &randomness, &transcript, &statement, &coord_evidence,
        );
        assert_eq!(d1, d2);
    }

    #[test]
    fn envelope_verify_digest_passes_for_valid() {
        let session = make_session();
        let rng_value = DigestBytes::from_bytes([1u8; 32]);
        let engine = PrototypeAttestationEngine;
        let (transcript, evidence) = engine
            .execute(&session, &rng_value, b"GET /", b"200 OK")
            .unwrap();

        let randomness = RandomnessBinding {
            id: RandomnessId::from_bytes([0u8; 16]),
            value: rng_value.clone(),
            epoch: Epoch::GENESIS,
            session_binding: DigestBytes::from_bytes([3u8; 32]),
        };

        let statement = StatementPayload::new(
            b"the result is X".to_vec(),
            "result/v1".into(),
            &transcript.session_transcript_digest,
        );

        let package_digest = AttestationPackage::compute_digest(
            &session.session_digest,
            &rng_value,
            &transcript.session_transcript_digest,
            &evidence.evidence_digest,
        );

        let coord_evidence = CoordinatorEvidence {
            engine_tag: PROTOTYPE_ENGINE_TAG.to_string(),
            evidence_digest: evidence.evidence_digest.clone(),
            package_digest,
        };

        let s1 = PrototypeThresholdSigner::from_seed([10u8; 32]);
        let s2 = PrototypeThresholdSigner::from_seed([20u8; 32]);

        // We need the actual verifier IDs from the signers, not hardcoded ones.
        // Build quorum from actual signer IDs.
        let quorum = QuorumSpec::new(
            vec![s1.verifier_id().clone(), s2.verifier_id().clone()],
            2,
        ).unwrap();

        // Reuse session with correct quorum
        let session2 = {
            SessionContext::new(
                SessionId::from_bytes([0u8; 16]),
                ProverId::from_bytes([0u8; 32]),
                s1.verifier_id().clone(),
                quorum.clone(),
                Epoch::GENESIS,
                UnixTimestamp(100),
                UnixTimestamp(9999999),
                Nonce::from_bytes([42u8; 32]),
            )
        };

        let (transcript2, evidence2) = engine
            .execute(&session2, &rng_value, b"GET /", b"200 OK")
            .unwrap();

        let randomness2 = RandomnessBinding {
            id: RandomnessId::from_bytes([0u8; 16]),
            value: rng_value.clone(),
            epoch: Epoch::GENESIS,
            session_binding: DigestBytes::from_bytes([3u8; 32]),
        };

        let statement2 = StatementPayload::new(
            b"the result is X".to_vec(),
            "result/v1".into(),
            &transcript2.session_transcript_digest,
        );

        let package_digest2 = AttestationPackage::compute_digest(
            &session2.session_digest,
            &rng_value,
            &transcript2.session_transcript_digest,
            &evidence2.evidence_digest,
        );

        let coord_evidence2 = CoordinatorEvidence {
            engine_tag: PROTOTYPE_ENGINE_TAG.to_string(),
            evidence_digest: evidence2.evidence_digest.clone(),
            package_digest: package_digest2,
        };

        // Compute envelope digest to sign.
        let envelope_digest = AttestationEnvelope::compute_digest(
            &session2, &randomness2, &transcript2, &statement2, &coord_evidence2,
        );

        let signed_digest = approval_signed_digest(&envelope_digest);

        let p1 = s1.sign_partial(signed_digest.as_bytes()).unwrap();
        let p2 = s2.sign_partial(signed_digest.as_bytes()).unwrap();

        let pks = vec![
            (s1.verifier_id().clone(), s1.verifying_key()),
            (s2.verifier_id().clone(), s2.verifying_key()),
        ];

        let approval = aggregate_signatures(vec![p1, p2], &quorum, &envelope_digest, &pks).unwrap();

        let envelope = AttestationEnvelope::assemble(
            session2,
            randomness2,
            transcript2,
            statement2,
            coord_evidence2,
            approval,
        );

        assert!(envelope.verify_digest());
    }
}
