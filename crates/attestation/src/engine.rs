//! Attestation engine abstraction and prototype implementation.
//!
//! The `AttestationEngine` trait represents the component that executes the
//! attested interaction (e.g., a TLS session) and produces verifiable evidence.
//!
//! # Production gap
//!
//! `PrototypeAttestationEngine` simulates an attestation by accepting pre-supplied
//! query/response bytes and producing transcript commitments. It does not perform
//! real TLS or interact with any remote server.
//!
//! A production implementation would:
//! 1. Establish a TLS 1.3 connection with transcript capture.
//! 2. Extract session keys / exporters for external verification.
//! 3. Commit to the transcript in a way that can be verified by a ZK proof backend.

use crate::{error::AttestationError, session::SessionContext};
use serde::{Deserialize, Serialize};
use tls_attestation_core::hash::{CanonicalHasher, DigestBytes};
use tls_attestation_crypto::transcript::TranscriptCommitments;

/// The tag identifying which engine produced evidence.
/// Version the tag whenever the evidence format changes.
pub const PROTOTYPE_ENGINE_TAG: &str = "prototype-attestation/v1";

/// Engine-specific evidence from executing the attested interaction.
///
/// This is opaque to the general protocol layer; aux verifiers check the
/// `evidence_digest` (which is committed into the envelope) rather than
/// interpreting the raw evidence bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportableEvidence {
    /// Tag identifying which engine produced this evidence.
    pub engine_tag: String,
    /// Engine-specific bytes. For prototype: JSON-encoded simulated transcript.
    /// For production: TLS session key material, exporter values, ZK proof.
    pub bytes: Vec<u8>,
    /// H("evidence/v1" || engine_tag || bytes)
    pub evidence_digest: DigestBytes,
}

impl ExportableEvidence {
    pub fn new(engine_tag: String, bytes: Vec<u8>) -> Self {
        let evidence_digest = {
            let mut h = CanonicalHasher::new("tls-attestation/evidence/v1");
            h.update_bytes(engine_tag.as_bytes());
            h.update_bytes(&bytes);
            h.finalize()
        };
        Self {
            engine_tag,
            bytes,
            evidence_digest,
        }
    }
}

/// Coordinator-side summary of the evidence, included in the attestation envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorEvidence {
    pub engine_tag: String,
    pub evidence_digest: DigestBytes,
    /// Digest of the full `AttestationPackage` (including raw evidence bytes).
    pub package_digest: DigestBytes,
}

/// The full evidence bundle assembled by the coordinator and sent to aux verifiers.
///
/// Aux verifiers receive this package and independently verify all fields before
/// issuing a partial approval signature. They do NOT trust the coordinator's claims —
/// they recompute digests and check bindings themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPackage {
    pub session_context: SessionContext,
    pub randomness_value: DigestBytes,
    pub transcript_commitments: TranscriptCommitments,
    pub evidence: ExportableEvidence,
    /// H("attestation-package/v1" || session_digest || randomness_value ||
    ///    session_transcript_digest || evidence_digest)
    pub package_digest: DigestBytes,
}

impl AttestationPackage {
    /// Compute the canonical package digest from its components.
    ///
    /// # Field order (canonical)
    ///
    /// 1. session_digest (32 bytes)
    /// 2. randomness_value (32 bytes)
    /// 3. session_transcript_digest (32 bytes)
    /// 4. evidence_digest (32 bytes)
    pub fn compute_digest(
        session_digest: &DigestBytes,
        randomness_value: &DigestBytes,
        session_transcript_digest: &DigestBytes,
        evidence_digest: &DigestBytes,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/attestation-package/v1");
        h.update_digest(session_digest);
        h.update_digest(randomness_value);
        h.update_digest(session_transcript_digest);
        h.update_digest(evidence_digest);
        h.finalize()
    }

    pub fn build(
        session_context: SessionContext,
        randomness_value: DigestBytes,
        transcript_commitments: TranscriptCommitments,
        evidence: ExportableEvidence,
    ) -> Self {
        let package_digest = Self::compute_digest(
            &session_context.session_digest,
            &randomness_value,
            &transcript_commitments.session_transcript_digest,
            &evidence.evidence_digest,
        );
        Self {
            session_context,
            randomness_value,
            transcript_commitments,
            evidence,
            package_digest,
        }
    }
}

/// The attestation engine trait.
///
/// Implementations execute the attested interaction and return a verifiable
/// evidence bundle.
pub trait AttestationEngine: Send + Sync {
    /// Execute the attested interaction for the given session.
    ///
    /// # Parameters
    ///
    /// - `session`: Session context (for binding commitments to the session).
    /// - `randomness`: The DVRF output for this session (mixed into transcript commitments).
    /// - `query`: Application-level query to the remote endpoint.
    /// - `response`: Application-level response from the remote endpoint.
    ///
    /// # Production note
    ///
    /// In a real engine, `query` and `response` are not supplied — they result
    /// from the engine actually executing the TLS connection. They are parameters
    /// here only for the prototype to enable testing without real network access.
    fn execute(
        &self,
        session: &SessionContext,
        randomness: &DigestBytes,
        query: &[u8],
        response: &[u8],
    ) -> Result<(TranscriptCommitments, ExportableEvidence), AttestationError>;
}

/// Prototype attestation engine.
///
/// # WARNING: PROTOTYPE ONLY
///
/// Does not perform real TLS. Accepts query/response bytes as inputs and
/// produces transcript commitments. The evidence bytes are a JSON summary
/// for debugging; they have no cryptographic meaning.
pub struct PrototypeAttestationEngine;

impl AttestationEngine for PrototypeAttestationEngine {
    fn execute(
        &self,
        session: &SessionContext,
        randomness: &DigestBytes,
        query: &[u8],
        response: &[u8],
    ) -> Result<(TranscriptCommitments, ExportableEvidence), AttestationError> {
        let transcript_commitments =
            TranscriptCommitments::build(&session.session_id, randomness, query, response);

        // Prototype evidence: a JSON summary. Has no cryptographic meaning.
        // A real engine would include TLS exporter values or a ZK proof here.
        let evidence_bytes = format!(
            r#"{{"engine":"prototype","query_len":{},"response_len":{},"session_id":"{}"}}"#,
            query.len(),
            response.len(),
            session.session_id,
        )
        .into_bytes();

        let evidence = ExportableEvidence::new(PROTOTYPE_ENGINE_TAG.to_string(), evidence_bytes);

        Ok((transcript_commitments, evidence))
    }
}

/// The dx-DCTLS attestation engine trait.
///
/// Extends `AttestationEngine` with the three protocol phases of dx-DCTLS:
/// HSP (handshake with proof), QP (query phase), and PGP (proof generation).
pub trait DxDctlsAttestationEngine: AttestationEngine {
    fn execute_dctls(
        &self,
        session: &SessionContext,
        randomness: &tls_attestation_core::hash::DigestBytes,
        query: &[u8],
        response: &[u8],
        server_cert_hash: &tls_attestation_core::hash::DigestBytes,
    ) -> Result<
        (TranscriptCommitments, ExportableEvidence, crate::dctls::DctlsEvidence),
        AttestationError,
    >;
}

/// Prototype dx-DCTLS engine simulating HSP/QP/PGP with commitment-based proofs.
pub struct PrototypeDctlsEngine;

impl AttestationEngine for PrototypeDctlsEngine {
    fn execute(
        &self,
        session: &SessionContext,
        randomness: &tls_attestation_core::hash::DigestBytes,
        query: &[u8],
        response: &[u8],
    ) -> Result<(TranscriptCommitments, ExportableEvidence), AttestationError> {
        let server_cert_hash = tls_attestation_core::hash::DigestBytes::from_bytes([0u8; 32]);
        let (tc, ev, _) = self.execute_dctls(session, randomness, query, response, &server_cert_hash)?;
        Ok((tc, ev))
    }
}

impl DxDctlsAttestationEngine for PrototypeDctlsEngine {
    fn execute_dctls(
        &self,
        session: &SessionContext,
        randomness: &tls_attestation_core::hash::DigestBytes,
        query: &[u8],
        response: &[u8],
        server_cert_hash: &tls_attestation_core::hash::DigestBytes,
    ) -> Result<
        (TranscriptCommitments, ExportableEvidence, crate::dctls::DctlsEvidence),
        AttestationError,
    > {
        use crate::dctls::{
            DctlsEvidence, HSPProof, PGPProof, QueryRecord, SessionParamsPublic,
            SessionParamsSecret, Statement, DCTLS_ENGINE_TAG,
        };
        use tls_attestation_core::hash::CanonicalHasher;

        // Simulate TLS exporter.
        let mut he = CanonicalHasher::new("tls-attestation/prototype-exporter/v1");
        he.update_fixed(session.session_id.as_bytes());
        he.update_digest(randomness);
        let dvrf_exporter = he.finalize();

        let mut hn = CanonicalHasher::new("tls-attestation/prototype-session-nonce/v1");
        hn.update_fixed(session.session_id.as_bytes());
        let session_nonce = hn.finalize();

        let sps = SessionParamsSecret {
            dvrf_exporter: dvrf_exporter.clone(),
            session_nonce,
        };

        let spp = SessionParamsPublic {
            server_cert_hash: server_cert_hash.clone(),
            tls_version: 0x0304,
            server_name: format!("prototype-server/{}", session.session_id),
            established_at: session.created_at.0,
        };

        let hsp_proof = HSPProof::generate(&session.session_id, randomness, &sps, &spp);
        let query_record = QueryRecord::build(&session.session_id, randomness, query, response);
        let transcript_commitments = TranscriptCommitments::build(
            &session.session_id, randomness, query, response,
        );

        let statement = Statement::derive(
            b"attested-session".to_vec(),
            "dx-dctls/prototype-statement/v1".into(),
            &query_record.transcript_commitment,
        );
        let pgp_proof = PGPProof::generate(
            &session.session_id, randomness, &query_record, statement, &hsp_proof,
        );

        let dctls_evidence = DctlsEvidence {
            hsp_proof,
            query_record,
            pgp_proof,
        };

        // Use ExportableEvidence::new() so that evidence_digest is computed as
        // H("evidence/v1" || engine_tag || bytes), which is what the auxiliary
        // verifier's Check 9 recomputes for tamper detection.
        let evidence_bytes = serde_json::to_vec(&dctls_evidence)
            .unwrap_or_else(|_| b"{}".to_vec());
        let evidence = ExportableEvidence::new(DCTLS_ENGINE_TAG.to_string(), evidence_bytes);

        Ok((transcript_commitments, evidence, dctls_evidence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::{
        hash::DigestBytes,
        ids::{ProverId, SessionId, VerifierId},
        types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
    };
    use crate::session::SessionContext;

    fn make_session() -> SessionContext {
        let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
        SessionContext::new(
            SessionId::from_bytes([0u8; 16]),
            ProverId::from_bytes([0u8; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum,
            Epoch::GENESIS,
            UnixTimestamp(100),
            UnixTimestamp(200),
            Nonce::from_bytes([0u8; 32]),
        )
    }

    #[test]
    fn prototype_engine_produces_transcript() {
        let engine = PrototypeAttestationEngine;
        let session = make_session();
        let rng = DigestBytes::from_bytes([1u8; 32]);
        let (tc, evidence) = engine.execute(&session, &rng, b"GET /", b"200 OK").unwrap();
        assert!(tc.query.verify(&session.session_id, &rng, b"GET /"));
        assert!(tc.response.verify(&session.session_id, &rng, b"200 OK"));
        assert_eq!(evidence.engine_tag, PROTOTYPE_ENGINE_TAG);
    }

    #[test]
    fn package_digest_is_deterministic() {
        let d1 = AttestationPackage::compute_digest(
            &DigestBytes::from_bytes([1u8; 32]),
            &DigestBytes::from_bytes([2u8; 32]),
            &DigestBytes::from_bytes([3u8; 32]),
            &DigestBytes::from_bytes([4u8; 32]),
        );
        let d2 = AttestationPackage::compute_digest(
            &DigestBytes::from_bytes([1u8; 32]),
            &DigestBytes::from_bytes([2u8; 32]),
            &DigestBytes::from_bytes([3u8; 32]),
            &DigestBytes::from_bytes([4u8; 32]),
        );
        assert_eq!(d1, d2);
    }
}
