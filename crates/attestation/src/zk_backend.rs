//! Pluggable ZK-TLS backend interface for dx-DCTLS proof generation and verification.
//!
//! # Motivation
//!
//! The current dx-DCTLS implementation uses **commitment-based proofs** (SHA-256
//! commitments). This is sound under the honest-but-curious model but does not
//! provide zero-knowledge: verifiers learn the DVRF exporter value.
//!
//! A production system should replace the commitment backend with a real ZK-TLS
//! backend (e.g., a co-SNARK over the TLS transcript, as in DECO or Distefano et al.)
//! that proves the HSP/QP/PGP statements in zero knowledge.
//!
//! # Architecture
//!
//! The `ZkTlsBackend` trait is the abstraction boundary:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  dx-DCTLS Protocol (dctls.rs)                                   │
//! │                                                                 │
//! │  HSPProof::generate()  ──►  ZkTlsBackend::prove_session_params │
//! │  verify_hsp_proof()    ──►  ZkTlsBackend::verify_session_params │
//! └───────────────────────────────────┬─────────────────────────────┘
//!                                     │
//!             ┌───────────────────────┴───────────────────────┐
//!             │                                               │
//!     ┌───────▼────────┐                           ┌──────────▼──────────┐
//!     │ CommitmentBackend │                         │ (Future) ZkBackend  │
//!     │ (this file)       │                         │ e.g. co-SNARK,      │
//!     │ SHA-256 commits   │                         │ DECO, TLS-N, etc.   │
//!     └───────────────────┘                         └─────────────────────┘
//! ```
//!
//! # Security levels
//!
//! | Backend              | Model              | ZK | PQ | Production-ready |
//! |----------------------|--------------------|----|----|-----------------|
//! | `CommitmentBackend`  | Honest-but-curious | No | No | Prototype only  |
//! | (future) ZkBackend   | Fully malicious    | Yes| TBD| Target          |
//!
//! # Usage
//!
//! To swap backends, replace `CommitmentBackend` with your ZK backend implementation
//! in `engine.rs`. All other protocol code (`verify.rs`, `dctls.rs`) remains unchanged
//! because they operate on `HSPProof` / `QueryRecord` / `PGPProof` structs, not the
//! backend directly.
//!
//! # `TranscriptBinding` as co-SNARK public input
//!
//! The `TranscriptBinding::binding_digest` (produced by `verify_transcript_consistency()`)
//! is designed to serve as the public input to a future co-SNARK. A co-SNARK would
//! prove, in zero knowledge:
//! ```text
//! SNARK.Prove(
//!   public: binding_digest,
//!   private: tls_master_secret, dvrf_exporter, session_nonce, query, response
//! ) → π
//! ```
//! This would give full ZK-TLS security without changing the outer protocol.

use crate::dctls::{
    DctlsError, HSPProof, QueryRecord, PGPProof, SessionParamsPublic, SessionParamsSecret,
    Statement,
};
use tls_attestation_core::{hash::DigestBytes, ids::SessionId};

// ── ZkTlsBackend trait ─────────────────────────────────────────────────────────

/// Backend trait for generating and verifying dx-DCTLS proofs.
///
/// Implementations differ in their security model:
/// - [`CommitmentBackend`]: commitment-based (honest-but-curious, prototype).
/// - Future ZK backend: zero-knowledge (fully malicious coordinator model).
///
/// The trait is object-safe and `Send + Sync` to allow dynamic dispatch in
/// multi-threaded coordinator implementations.
pub trait ZkTlsBackend: Send + Sync {
    /// Generate an HSP proof binding the TLS session to the DVRF randomness.
    ///
    /// In a real backend this would generate a ZK proof. In `CommitmentBackend`
    /// it generates a SHA-256 commitment.
    fn prove_session_params(
        &self,
        session_id: &SessionId,
        rand_value: &DigestBytes,
        sps: &SessionParamsSecret,
        spp: &SessionParamsPublic,
    ) -> Result<HSPProof, DctlsError>;

    /// Verify an HSP proof.
    ///
    /// In a real backend this would verify a ZK proof. In `CommitmentBackend`
    /// it recomputes the SHA-256 commitment.
    fn verify_session_params(
        &self,
        proof: &HSPProof,
        rand_value: &DigestBytes,
        server_cert_hash: &DigestBytes,
    ) -> Result<(), DctlsError>;

    /// Generate a QP record committing to the query and response.
    fn prove_query_response(
        &self,
        session_id: &SessionId,
        rand_value: &DigestBytes,
        query: &[u8],
        response: &[u8],
    ) -> Result<QueryRecord, DctlsError>;

    /// Verify a QP record against the provided query and response.
    fn verify_query_response(
        &self,
        record: &QueryRecord,
        query: &[u8],
        response: &[u8],
    ) -> Result<(), DctlsError>;

    /// Generate a PGP proof binding the statement to the transcript.
    fn prove_pgp(
        &self,
        session_id: &SessionId,
        rand_value: &DigestBytes,
        qr: &QueryRecord,
        statement: Statement,
        hsp: &HSPProof,
    ) -> Result<PGPProof, DctlsError>;

    /// Verify a PGP proof.
    fn verify_pgp(
        &self,
        proof: &PGPProof,
        rand_value: &DigestBytes,
        hsp: &HSPProof,
    ) -> Result<(), DctlsError>;

    /// A human-readable tag identifying this backend.
    fn backend_tag(&self) -> &'static str;
}

// ── CommitmentBackend ──────────────────────────────────────────────────────────

/// Commitment-based dx-DCTLS backend using SHA-256 domain-separated hashes.
///
/// # Security model
///
/// Sound under the **honest-but-curious** (passive) verifier model. The DVRF
/// exporter and session nonce are revealed in the HSP proof. This is acceptable
/// for prototype deployments where verifiers are assumed not to act on this data.
///
/// # Production gap
///
/// Replace with a ZK backend to achieve full dx-DCTLS security:
/// - Verifiers learn nothing about the TLS session parameters.
/// - The `handshake_transcript_hash` would be proved in ZK rather than committed.
pub struct CommitmentBackend;

impl ZkTlsBackend for CommitmentBackend {
    fn prove_session_params(
        &self,
        session_id: &SessionId,
        rand_value: &DigestBytes,
        sps: &SessionParamsSecret,
        spp: &SessionParamsPublic,
    ) -> Result<HSPProof, DctlsError> {
        Ok(HSPProof::generate(session_id, rand_value, sps, spp))
    }

    fn verify_session_params(
        &self,
        proof: &HSPProof,
        rand_value: &DigestBytes,
        server_cert_hash: &DigestBytes,
    ) -> Result<(), DctlsError> {
        crate::dctls::verify_hsp_proof(proof, rand_value, server_cert_hash)
    }

    fn prove_query_response(
        &self,
        session_id: &SessionId,
        rand_value: &DigestBytes,
        query: &[u8],
        response: &[u8],
    ) -> Result<QueryRecord, DctlsError> {
        Ok(QueryRecord::build(session_id, rand_value, query, response))
    }

    fn verify_query_response(
        &self,
        record: &QueryRecord,
        query: &[u8],
        response: &[u8],
    ) -> Result<(), DctlsError> {
        crate::dctls::verify_query_record(record, query, response)
    }

    fn prove_pgp(
        &self,
        _session_id: &SessionId,
        _rand_value: &DigestBytes,
        qr: &QueryRecord,
        statement: Statement,
        hsp: &HSPProof,
    ) -> Result<PGPProof, DctlsError> {
        // Use the session_id and rand_value from qr/hsp (they are consistent after
        // verify_transcript_consistency). Pass qr.rand_value as the rand.
        Ok(PGPProof::generate(
            &qr.session_id,
            &qr.rand_value,
            qr,
            statement,
            hsp,
        ))
    }

    fn verify_pgp(
        &self,
        proof: &PGPProof,
        rand_value: &DigestBytes,
        hsp: &HSPProof,
    ) -> Result<(), DctlsError> {
        crate::dctls::verify_pgp_proof(proof, rand_value, hsp)
    }

    fn backend_tag(&self) -> &'static str {
        "commitment/sha256-v1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::{
        hash::{CanonicalHasher, DigestBytes},
        ids::SessionId,
    };

    fn sid() -> SessionId { SessionId::from_bytes([1u8; 16]) }
    fn rand() -> DigestBytes { DigestBytes::from_bytes([2u8; 32]) }
    fn cert() -> DigestBytes { DigestBytes::from_bytes([3u8; 32]) }

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

    fn make_spp(cert_hash: DigestBytes) -> SessionParamsPublic {
        let established_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        SessionParamsPublic {
            server_cert_hash: cert_hash,
            tls_version: 0x0304,
            server_name: "example.com".into(),
            established_at,
        }
    }

    #[test]
    fn commitment_backend_full_prove_verify_cycle() {
        let backend = CommitmentBackend;
        let session_id = sid();
        let rand = rand();
        let cert = cert();
        let sps = make_sps(&session_id, &rand);
        let spp = make_spp(cert.clone());

        let hsp = backend.prove_session_params(&session_id, &rand, &sps, &spp).unwrap();
        backend.verify_session_params(&hsp, &rand, &cert).unwrap();

        let qr = backend.prove_query_response(&session_id, &rand, b"GET /", b"200 OK").unwrap();
        backend.verify_query_response(&qr, b"GET /", b"200 OK").unwrap();

        let stmt = Statement::derive(b"result".to_vec(), "test/v1".into(), &qr.transcript_commitment);
        let pgp = backend.prove_pgp(&session_id, &rand, &qr, stmt, &hsp).unwrap();
        backend.verify_pgp(&pgp, &rand, &hsp).unwrap();
    }

    #[test]
    fn commitment_backend_wrong_query_rejected() {
        let backend = CommitmentBackend;
        let session_id = sid();
        let rand = rand();
        let qr = backend.prove_query_response(&session_id, &rand, b"GET /", b"200 OK").unwrap();
        assert!(backend.verify_query_response(&qr, b"POST /", b"200 OK").is_err());
    }

    #[test]
    fn commitment_backend_tag() {
        let backend = CommitmentBackend;
        assert_eq!(backend.backend_tag(), "commitment/sha256-v1");
    }
}
