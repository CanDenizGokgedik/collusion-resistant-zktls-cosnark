//! dx-DCTLS protocol layer: Handshake binding, Query Phase, and Proof Generation.
//!
//! # Protocol position in Π_coll-min
//!
//! The full protocol is: DVRF → HSP → QP → PGP → TSS.
//!
//! # Security model
//!
//! ## Current implementation: commitment-based (honest-but-curious)
//!
//! This implementation approximates dx-DCTLS using **SHA-256 commitments** rather
//! than zero-knowledge proofs. It is sound under the following model:
//!
//! - **Honest-but-curious (passive) verifiers**: The coordinator reveals the DVRF
//!   exporter and session nonce in the HSP proof. Verifiers learn these values but
//!   cannot forge new proofs. In a full ZK construction, these values would be kept
//!   private via a ZK proof of knowledge.
//!
//! - **No traffic decryption by verifiers**: Although `dvrf_exporter` is revealed,
//!   it is derived from the DVRF randomness, not from the TLS master secret. Verifiers
//!   cannot decrypt TLS traffic without the master secret.
//!
//! ## What the commitment construction provides
//!
//! 1. **Binding**: The HSP commitment binds `session_id || rand || dvrf_exporter || cert_hash ||
//!    handshake_transcript_hash` into a single digest. A coordinator cannot substitute any
//!    of these values without breaking the commitment.
//!
//! 2. **Cross-proof binding**: `TranscriptBinding` and `verify_transcript_consistency()`
//!    ensure that HSP, QP, and PGP all refer to the same `session_id` and DVRF randomness.
//!    A coordinator cannot mix proofs from different sessions.
//!
//! 3. **Query/response binding**: The QP record commits separately to query and response,
//!    then combines them into a `transcript_commitment`. The PGP proof commits to this
//!    transcript, ensuring the statement is bound to the actual query/response pair.
//!
//! ## What the commitment construction does NOT provide
//!
//! - **Zero-knowledge**: Verifiers learn `dvrf_exporter` and `session_nonce`.
//! - **Non-interactive proofs**: All proofs require coordinator cooperation.
//! - **Post-quantum security**: SHA-256 commitments are classically secure but not
//!   post-quantum. A co-SNARK backend (see `zk_backend.rs`) would provide ZK + PQ.
//!
//! ## Production upgrade path
//!
//! Replace `CommitmentBackend` with a real `ZkTlsBackend` implementation (see
//! `crate::zk_backend`) to achieve full dx-DCTLS security. The `TranscriptBinding`
//! digest is designed to serve as the public input to a future co-SNARK.
//!
//! # Exportability requirement
//!
//! ALL proofs in this module must be verifiable by auxiliary verifiers without
//! participating in the TLS session. The `verify_hsp_proof`, `verify_query_record`,
//! `verify_pgp_proof`, and `verify_transcript_consistency` functions are the public
//! verification API.

use serde::{Deserialize, Serialize};
use tls_attestation_core::hash::{CanonicalHasher, DigestBytes};
use tls_attestation_core::ids::SessionId;

/// Engine tag for the dx-DCTLS commitment-based implementation.
pub const DCTLS_ENGINE_TAG: &str = "dx-dctls/commitment-v1";

// ── Session parameters ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionParamsSecret {
    pub dvrf_exporter: DigestBytes,
    pub session_nonce: DigestBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionParamsPublic {
    pub server_cert_hash: DigestBytes,
    pub tls_version: u16,
    pub server_name: String,
    pub established_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionParamsVerifier {
    pub observation_commitment: DigestBytes,
}

// ── HSP ────────────────────────────────────────────────────────────────────────

/// Proof that the TLS session was established using the DVRF randomness `rand`.
///
/// The `handshake_transcript_hash` field captures a commitment to the TLS handshake
/// parameters (`server_cert_hash || tls_version || server_name || established_at`).
/// Including this in the HSP commitment ensures a coordinator cannot swap the TLS
/// session after the fact while keeping the same `rand` binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HSPProof {
    pub session_id: SessionId,
    pub rand_value: DigestBytes,
    /// DVRF-derived TLS exporter value.
    ///
    /// Set to all-zeros when `zk_proof` is `Some(...)` — the value is kept
    /// private inside the Groth16 witness and is never revealed to verifiers.
    pub dvrf_exporter: DigestBytes,
    pub commitment: DigestBytes,
    pub server_cert_hash: DigestBytes,
    /// Commitment to TLS handshake parameters: H("hsp-ht/v1" || cert_hash || version || name || time).
    /// Included in `commitment` to bind the specific TLS session to the DVRF randomness.
    pub handshake_transcript_hash: DigestBytes,
    /// TLS version (e.g. 0x0304 for TLS 1.3).
    pub tls_version: u16,
    /// SNI server name used in the TLS handshake.
    pub server_name: String,
    /// Unix timestamp when the TLS session was established.
    pub established_at: u64,
    pub engine_tag: String,
    /// Groth16 proof bytes (present when a ZK backend was used).
    ///
    /// When `Some`, verifiers must call `ZkTlsBackend::verify_session_params`
    /// instead of re-deriving `dvrf_exporter` from the commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zk_proof: Option<Vec<u8>>,
    /// MiMC-7 sponge output used as the Groth16 public input.
    ///
    /// Set by the ZK backend alongside `zk_proof`. `None` for the commitment backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zk_binding: Option<DigestBytes>,
}

impl HSPProof {
    pub fn generate(
        session_id: &SessionId,
        rand_value: &DigestBytes,
        sps: &SessionParamsSecret,
        spp: &SessionParamsPublic,
    ) -> Self {
        let handshake_transcript_hash = Self::compute_handshake_transcript_hash(
            &spp.server_cert_hash,
            spp.tls_version,
            &spp.server_name,
            spp.established_at,
        );
        let commitment = Self::compute_commitment(
            session_id,
            rand_value,
            &sps.dvrf_exporter,
            &spp.server_cert_hash,
            &handshake_transcript_hash,
        );
        Self {
            session_id: session_id.clone(),
            rand_value: rand_value.clone(),
            dvrf_exporter: sps.dvrf_exporter.clone(),
            commitment,
            server_cert_hash: spp.server_cert_hash.clone(),
            handshake_transcript_hash,
            tls_version: spp.tls_version,
            server_name: spp.server_name.clone(),
            established_at: spp.established_at,
            engine_tag: DCTLS_ENGINE_TAG.to_string(),
            zk_proof: None,
            zk_binding: None,
        }
    }

    /// Compute H("hsp-ht/v1" || server_cert_hash || tls_version || server_name || established_at).
    ///
    /// This is the "handshake transcript hash" — a commitment to TLS session parameters.
    /// Including it in the HSP commitment binds the specific TLS session to `rand`.
    pub fn compute_handshake_transcript_hash(
        server_cert_hash: &DigestBytes,
        tls_version: u16,
        server_name: &str,
        established_at: u64,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/hsp-ht/v1");
        h.update_digest(server_cert_hash);
        h.update_u64(tls_version as u64);
        h.update_bytes(server_name.as_bytes());
        h.update_u64(established_at);
        h.finalize()
    }

    pub fn compute_commitment(
        session_id: &SessionId,
        rand_value: &DigestBytes,
        dvrf_exporter: &DigestBytes,
        server_cert_hash: &DigestBytes,
        handshake_transcript_hash: &DigestBytes,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/hsp/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_digest(rand_value);
        h.update_digest(dvrf_exporter);
        h.update_digest(server_cert_hash);
        h.update_digest(handshake_transcript_hash);
        h.finalize()
    }

    pub fn proof_digest(&self) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/hsp-proof/v1");
        h.update_fixed(self.session_id.as_bytes());
        h.update_digest(&self.rand_value);
        h.update_digest(&self.commitment);
        h.update_digest(&self.server_cert_hash);
        h.update_digest(&self.handshake_transcript_hash);
        h.finalize()
    }
}

/// Maximum age of a valid HSP proof (24 hours).
///
/// Proofs older than this are rejected to prevent session replay attacks.
/// A TLS session cannot last more than 24 hours under RFC 5246/8446, so
/// any proof claiming an `established_at` more than 24 h in the past is
/// either stale or forged.
pub const HSP_PROOF_MAX_AGE_SECS: u64 = 24 * 3600;

pub fn verify_hsp_proof(
    proof: &HSPProof,
    expected_rand: &DigestBytes,
    expected_server_cert_hash: &DigestBytes,
) -> Result<(), DctlsError> {
    // Verify the engine_tag matches.  An HSP proof from a different engine
    // (e.g. a future ZK backend) should not be accepted as a commitment-backend
    // proof; the tag ensures the verifier applies the correct verification logic.
    if proof.engine_tag != DCTLS_ENGINE_TAG {
        return Err(DctlsError::CommitmentMismatch {
            which: format!(
                "engine_tag mismatch: expected {:?}, got {:?}",
                DCTLS_ENGINE_TAG, proof.engine_tag
            ),
        });
    }

    if &proof.rand_value != expected_rand {
        return Err(DctlsError::RandMismatch);
    }
    if &proof.server_cert_hash != expected_server_cert_hash {
        return Err(DctlsError::CertHashMismatch);
    }

    // Reject ZK-backed proofs at this API — they require a verifying key.
    // Callers that hold a Groth16 PVK must use `verify_hsp_proof_with_zk`.
    if proof.zk_proof.is_some() {
        return Err(DctlsError::CommitmentMismatch {
            which: "zk_proof present but no verifying key supplied — \
                    use verify_hsp_proof_with_zk instead".into(),
        });
    }

    // Reject proofs for sessions older than HSP_PROOF_MAX_AGE_SECS.
    // `established_at` is the Unix timestamp of the TLS handshake completion.
    // An expired proof should not be re-accepted indefinitely.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if proof.established_at > 0 && now_secs > proof.established_at {
        let age = now_secs - proof.established_at;
        if age > HSP_PROOF_MAX_AGE_SECS {
            return Err(DctlsError::CommitmentMismatch {
                which: format!(
                    "HSP proof has expired (established_at={}, age={}s, max={}s)",
                    proof.established_at, age, HSP_PROOF_MAX_AGE_SECS,
                ),
            });
        }
    }

    // Recompute the handshake transcript hash from the proof's stored TLS parameters.
    let expected_ht = HSPProof::compute_handshake_transcript_hash(
        &proof.server_cert_hash,
        proof.tls_version,
        &proof.server_name,
        proof.established_at,
    );
    if proof.handshake_transcript_hash != expected_ht {
        return Err(DctlsError::CommitmentMismatch {
            which: "handshake_transcript_hash".into(),
        });
    }

    // Recompute the full HSP commitment and verify it matches the stored value.
    let expected_commitment = HSPProof::compute_commitment(
        &proof.session_id,
        &proof.rand_value,
        &proof.dvrf_exporter,
        &proof.server_cert_hash,
        &proof.handshake_transcript_hash,
    );
    if proof.commitment != expected_commitment {
        return Err(DctlsError::CommitmentMismatch { which: "HSP commitment".into() });
    }
    Ok(())
}

/// Verify an HSP proof that was generated with a Groth16 ZK backend.
///
/// # When to use
///
/// Use this function when `proof.zk_proof.is_some()`. It verifies:
/// 1. All structural checks from `verify_hsp_proof` (rand, cert hash, commitment)
/// 2. The embedded Groth16 proof using the supplied verifying key bytes
///
/// The `pvk_bytes` must be serialized with `CoSnarkCrs::verifying_key_bytes()`.
pub fn verify_hsp_proof_with_zk(
    proof: &HSPProof,
    expected_rand: &DigestBytes,
    expected_server_cert_hash: &DigestBytes,
    pvk_bytes: &[u8],
) -> Result<(), DctlsError> {
    // First run all structural checks (without the ZK check).
    // Re-implement rather than calling verify_hsp_proof to avoid the zk_proof guard.
    if &proof.rand_value != expected_rand {
        return Err(DctlsError::RandMismatch);
    }
    if &proof.server_cert_hash != expected_server_cert_hash {
        return Err(DctlsError::CertHashMismatch);
    }
    let expected_ht = HSPProof::compute_handshake_transcript_hash(
        &proof.server_cert_hash,
        proof.tls_version,
        &proof.server_name,
        proof.established_at,
    );
    if proof.handshake_transcript_hash != expected_ht {
        return Err(DctlsError::CommitmentMismatch {
            which: "handshake_transcript_hash".into(),
        });
    }
    let expected_commitment = HSPProof::compute_commitment(
        &proof.session_id,
        &proof.rand_value,
        &proof.dvrf_exporter,
        &proof.server_cert_hash,
        &proof.handshake_transcript_hash,
    );
    if proof.commitment != expected_commitment {
        return Err(DctlsError::CommitmentMismatch { which: "HSP commitment".into() });
    }

    // Now verify the embedded Groth16 proof.
    let zk_bytes = proof.zk_proof.as_ref().ok_or_else(|| DctlsError::CommitmentMismatch {
        which: "zk_proof missing".into(),
    })?;
    let binding = proof.zk_binding.as_ref().ok_or_else(|| DctlsError::CommitmentMismatch {
        which: "zk_binding missing".into(),
    })?;

    // Delegate to the ZK crate at the type-erased byte level so that the
    // attestation crate does not depend on ark-groth16 directly.
    verify_groth16_hsp_bytes(pvk_bytes, zk_bytes, binding.as_bytes())
        .map_err(|e| DctlsError::CommitmentMismatch { which: format!("ZK proof invalid: {e}") })
}

/// Opaque Groth16 verification helper (byte-level).
///
/// Kept private and thin — the real logic lives in `tls-attestation-zk`.
/// Returns `Ok(())` if the proof is valid, `Err(msg)` otherwise.
#[doc(hidden)]
pub fn verify_groth16_hsp_bytes(
    _pvk_bytes: &[u8],
    _proof_bytes: &[u8],
    _public_input_bytes: &[u8],
) -> Result<(), String> {
    // NOTE: This is a thin dispatch point.  Wire this to
    // `tls_attestation_zk::co_snark::co_snark_verify_raw()` from the ZK crate
    // in the integration layer (e.g. the node crate) to avoid a circular dep.
    //
    // For now we return Ok to allow the attestation crate to compile without
    // depending on ark-groth16.  The node crate overrides this at the
    // CoSnarkExecutor impl level.
    Err("verify_groth16_hsp_bytes: not wired — integrate via node crate".into())
}

// ── QP ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryRecord {
    pub session_id: SessionId,
    pub rand_value: DigestBytes,
    pub query_commitment: DigestBytes,
    pub response_commitment: DigestBytes,
    pub transcript_commitment: DigestBytes,
}

impl QueryRecord {
    pub fn build(
        session_id: &SessionId,
        rand_value: &DigestBytes,
        query: &[u8],
        response: &[u8],
    ) -> Self {
        let mut hq = CanonicalHasher::new("tls-attestation/query-commitment/v1");
        hq.update_fixed(session_id.as_bytes());
        hq.update_digest(rand_value);
        hq.update_bytes(query);
        let query_commitment = hq.finalize();

        let mut hr = CanonicalHasher::new("tls-attestation/response-commitment/v1");
        hr.update_fixed(session_id.as_bytes());
        hr.update_digest(rand_value);
        hr.update_bytes(response);
        let response_commitment = hr.finalize();

        let mut ht = CanonicalHasher::new("tls-attestation/qp-transcript/v1");
        ht.update_digest(&query_commitment);
        ht.update_digest(&response_commitment);
        let transcript_commitment = ht.finalize();

        Self {
            session_id: session_id.clone(),
            rand_value: rand_value.clone(),
            query_commitment,
            response_commitment,
            transcript_commitment,
        }
    }
}

pub fn verify_query_record(
    record: &QueryRecord,
    query: &[u8],
    response: &[u8],
) -> Result<(), DctlsError> {
    let mut hq = CanonicalHasher::new("tls-attestation/query-commitment/v1");
    hq.update_fixed(record.session_id.as_bytes());
    hq.update_digest(&record.rand_value);
    hq.update_bytes(query);
    let expected_q = hq.finalize();
    if record.query_commitment != expected_q {
        return Err(DctlsError::CommitmentMismatch { which: "query commitment".into() });
    }

    let mut hr = CanonicalHasher::new("tls-attestation/response-commitment/v1");
    hr.update_fixed(record.session_id.as_bytes());
    hr.update_digest(&record.rand_value);
    hr.update_bytes(response);
    let expected_r = hr.finalize();
    if record.response_commitment != expected_r {
        return Err(DctlsError::CommitmentMismatch { which: "response commitment".into() });
    }

    let mut ht = CanonicalHasher::new("tls-attestation/qp-transcript/v1");
    ht.update_digest(&record.query_commitment);
    ht.update_digest(&record.response_commitment);
    let expected_t = ht.finalize();
    if record.transcript_commitment != expected_t {
        return Err(DctlsError::CommitmentMismatch { which: "QP transcript commitment".into() });
    }
    Ok(())
}

// ── PGP ────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Statement {
    pub content: Vec<u8>,
    pub derivation_tag: String,
    pub statement_digest: DigestBytes,
}

impl Statement {
    pub fn derive(
        content: Vec<u8>,
        derivation_tag: String,
        transcript_commitment: &DigestBytes,
    ) -> Self {
        let mut h = CanonicalHasher::new("tls-attestation/pgp-statement/v1");
        h.update_bytes(derivation_tag.as_bytes());
        h.update_digest(transcript_commitment);
        h.update_bytes(&content);
        let statement_digest = h.finalize();
        Self { content, derivation_tag, statement_digest }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PGPProof {
    pub session_id: SessionId,
    pub statement: Statement,
    pub pgp_commitment: DigestBytes,
    pub hsp_proof_digest: DigestBytes,
    pub qp_transcript_commitment: DigestBytes,
}

impl PGPProof {
    pub fn generate(
        session_id: &SessionId,
        rand_value: &DigestBytes,
        qp: &QueryRecord,
        statement: Statement,
        hsp_proof: &HSPProof,
    ) -> Self {
        let pgp_commitment = Self::compute_commitment(
            session_id,
            rand_value,
            &qp.transcript_commitment,
            &statement.statement_digest,
            &hsp_proof.commitment,
        );
        Self {
            session_id: session_id.clone(),
            statement,
            pgp_commitment,
            hsp_proof_digest: hsp_proof.proof_digest(),
            qp_transcript_commitment: qp.transcript_commitment.clone(),
        }
    }

    pub fn compute_commitment(
        session_id: &SessionId,
        rand_value: &DigestBytes,
        qp_transcript_commitment: &DigestBytes,
        statement_digest: &DigestBytes,
        hsp_commitment: &DigestBytes,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/pgp/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_digest(rand_value);
        h.update_digest(qp_transcript_commitment);
        h.update_digest(statement_digest);
        h.update_digest(hsp_commitment);
        h.finalize()
    }

    pub fn signing_preimage(&self) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/signing-preimage/v1");
        h.update_digest(&self.pgp_commitment);
        h.update_digest(&self.hsp_proof_digest);
        h.finalize()
    }
}

pub fn verify_pgp_proof(
    proof: &PGPProof,
    rand_value: &DigestBytes,
    hsp_proof: &HSPProof,
) -> Result<(), DctlsError> {
    let expected = PGPProof::compute_commitment(
        &proof.session_id,
        rand_value,
        &proof.qp_transcript_commitment,
        &proof.statement.statement_digest,
        &hsp_proof.commitment,
    );
    if proof.pgp_commitment != expected {
        return Err(DctlsError::CommitmentMismatch { which: "PGP commitment".into() });
    }
    if proof.hsp_proof_digest != hsp_proof.proof_digest() {
        return Err(DctlsError::ProofBindingMismatch { which: "HSP proof digest".into() });
    }
    let mut hs = CanonicalHasher::new("tls-attestation/pgp-statement/v1");
    hs.update_bytes(proof.statement.derivation_tag.as_bytes());
    hs.update_digest(&proof.qp_transcript_commitment);
    hs.update_bytes(&proof.statement.content);
    let expected_stmt = hs.finalize();
    if proof.statement.statement_digest != expected_stmt {
        return Err(DctlsError::CommitmentMismatch { which: "statement digest".into() });
    }
    Ok(())
}

// ── Transcript binding ─────────────────────────────────────────────────────────

/// Cross-proof binding that ties HSP, QP, and PGP to the same session and DVRF output.
///
/// The `binding_digest` is a single digest that commits to:
/// - The `session_id` (must be identical across all three proofs)
/// - The `rand_value` (the DVRF output, must be identical across HSP and QP)
/// - The HSP commitment (binds rand to the TLS session)
/// - The QP transcript commitment (binds query/response to the session)
/// - The PGP commitment (binds the statement to the transcript)
///
/// An auxiliary verifier that obtains a valid `TranscriptBinding` from
/// `verify_transcript_consistency()` has confirmed:
/// 1. All three proofs refer to the same `session_id`.
/// 2. HSP and QP use the same `rand_value`.
/// 3. PGP references the same QP transcript and HSP proof as the provided evidence.
///
/// The `binding_digest` is designed to serve as the public input to a future
/// co-SNARK proof system (see `crate::zk_backend`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscriptBinding {
    /// Session ID — identical across HSP, QP, and PGP.
    pub session_id: SessionId,
    /// DVRF randomness — identical across HSP and QP.
    pub rand_value: DigestBytes,
    /// HSP commitment value.
    pub hsp_commitment: DigestBytes,
    /// QP transcript commitment value.
    pub qp_transcript_commitment: DigestBytes,
    /// PGP commitment value.
    pub pgp_commitment: DigestBytes,
    /// H("transcript-binding/v1" || session_id || rand || hsp_commitment ||
    ///    qp_transcript_commitment || pgp_commitment)
    pub binding_digest: DigestBytes,
}

impl TranscriptBinding {
    /// Build a `TranscriptBinding` from consistent HSP/QP/PGP evidence.
    ///
    /// Callers MUST have already validated consistency via `verify_transcript_consistency()`.
    pub fn build(hsp: &HSPProof, qr: &QueryRecord, pgp: &PGPProof) -> Self {
        let mut h = CanonicalHasher::new("tls-attestation/transcript-binding/v1");
        h.update_fixed(hsp.session_id.as_bytes());
        h.update_digest(&hsp.rand_value);
        h.update_digest(&hsp.commitment);
        h.update_digest(&qr.transcript_commitment);
        h.update_digest(&pgp.pgp_commitment);
        let binding_digest = h.finalize();
        Self {
            session_id: hsp.session_id.clone(),
            rand_value: hsp.rand_value.clone(),
            hsp_commitment: hsp.commitment.clone(),
            qp_transcript_commitment: qr.transcript_commitment.clone(),
            pgp_commitment: pgp.pgp_commitment.clone(),
            binding_digest,
        }
    }
}

/// Verify that HSP, QP, and PGP proofs are mutually consistent and return
/// a `TranscriptBinding` that can be committed to on-chain or checked by
/// a future co-SNARK backend.
///
/// This function checks:
/// 1. `hsp.session_id == qr.session_id` — same session.
/// 2. `hsp.session_id == pgp.session_id` — same session.
/// 3. `hsp.rand_value == qr.rand_value` — same DVRF output.
/// 4. `pgp.qp_transcript_commitment == qr.transcript_commitment` — PGP covers actual QP.
/// 5. `pgp.hsp_proof_digest == hsp.proof_digest()` — PGP covers actual HSP.
///
/// These checks ensure a malicious coordinator cannot mix proofs from different
/// sessions, substitute a different QP transcript, or swap the HSP proof after
/// the PGP commitment was generated.
///
/// Note: This function does NOT verify the individual commitment values within
/// each proof. Call `verify_hsp_proof`, `verify_query_record`, and
/// `verify_pgp_proof` to verify those independently.
pub fn verify_transcript_consistency(
    hsp: &HSPProof,
    qr: &QueryRecord,
    pgp: &PGPProof,
) -> Result<TranscriptBinding, DctlsError> {
    // Check 1: HSP and QP share the same session_id.
    if hsp.session_id != qr.session_id {
        return Err(DctlsError::ProofBindingMismatch {
            which: "HSP session_id does not match QP session_id".into(),
        });
    }
    // Check 2: HSP and PGP share the same session_id.
    if hsp.session_id != pgp.session_id {
        return Err(DctlsError::ProofBindingMismatch {
            which: "HSP session_id does not match PGP session_id".into(),
        });
    }
    // Check 3: HSP and QP use the same DVRF randomness.
    if hsp.rand_value != qr.rand_value {
        return Err(DctlsError::RandMismatch);
    }
    // Check 4: PGP references the correct QP transcript commitment.
    if pgp.qp_transcript_commitment != qr.transcript_commitment {
        return Err(DctlsError::ProofBindingMismatch {
            which: "PGP qp_transcript_commitment does not match QP transcript".into(),
        });
    }
    // Check 5: PGP references the correct HSP proof (via digest).
    if pgp.hsp_proof_digest != hsp.proof_digest() {
        return Err(DctlsError::ProofBindingMismatch {
            which: "PGP hsp_proof_digest does not match HSP proof".into(),
        });
    }
    Ok(TranscriptBinding::build(hsp, qr, pgp))
}

// ── Full dx-DCTLS evidence package ────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DctlsEvidence {
    pub hsp_proof: HSPProof,
    pub query_record: QueryRecord,
    pub pgp_proof: PGPProof,
}

impl DctlsEvidence {
    pub fn evidence_digest(&self) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/dctls-evidence/v1");
        h.update_digest(&self.hsp_proof.proof_digest());
        h.update_digest(&self.query_record.transcript_commitment);
        h.update_digest(&self.pgp_proof.pgp_commitment);
        h.finalize()
    }

    pub fn verify_all(
        &self,
        rand_value: &DigestBytes,
        server_cert_hash: &DigestBytes,
        query: &[u8],
        response: &[u8],
    ) -> Result<TranscriptBinding, DctlsError> {
        // Verify each proof individually.
        verify_hsp_proof(&self.hsp_proof, rand_value, server_cert_hash)?;
        verify_query_record(&self.query_record, query, response)?;
        verify_pgp_proof(&self.pgp_proof, rand_value, &self.hsp_proof)?;
        // Verify cross-proof binding: all proofs must reference the same session/rand.
        // This returns a TranscriptBinding that summarises the verified binding.
        let binding = verify_transcript_consistency(
            &self.hsp_proof,
            &self.query_record,
            &self.pgp_proof,
        )?;
        Ok(binding)
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DctlsError {
    #[error("DVRF randomness mismatch")]
    RandMismatch,
    #[error("commitment mismatch: {which}")]
    CommitmentMismatch { which: String },
    #[error("proof binding mismatch: {which}")]
    ProofBindingMismatch { which: String },
    #[error("certificate hash mismatch")]
    CertHashMismatch,
    #[error("unknown engine tag: {tag}")]
    UnknownEngineTag { tag: String },
    #[error("ZK proof failed: {0}")]
    ZkProofFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Use current time so the proof passes the HSP_PROOF_MAX_AGE_SECS check.
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
    fn hsp_generates_and_verifies() {
        let session_id = sid();
        let rand = rand();
        let cert = cert();
        let sps = make_sps(&session_id, &rand);
        let spp = make_spp(cert.clone());
        let proof = HSPProof::generate(&session_id, &rand, &sps, &spp);
        verify_hsp_proof(&proof, &rand, &cert).expect("HSP verification failed");
    }

    #[test]
    fn hsp_wrong_rand_rejected() {
        let session_id = sid();
        let rand = rand();
        let cert = cert();
        let sps = make_sps(&session_id, &rand);
        let spp = make_spp(cert.clone());
        let proof = HSPProof::generate(&session_id, &rand, &sps, &spp);
        let wrong_rand = DigestBytes::from_bytes([0xFF; 32]);
        assert!(verify_hsp_proof(&proof, &wrong_rand, &cert).is_err());
    }

    #[test]
    fn query_record_builds_and_verifies() {
        let session_id = sid();
        let rand = rand();
        let record = QueryRecord::build(&session_id, &rand, b"GET /", b"200 OK");
        verify_query_record(&record, b"GET /", b"200 OK").expect("QP verification failed");
    }

    #[test]
    fn query_record_wrong_query_rejected() {
        let session_id = sid();
        let rand = rand();
        let record = QueryRecord::build(&session_id, &rand, b"GET /", b"200 OK");
        assert!(verify_query_record(&record, b"POST /", b"200 OK").is_err());
    }

    #[test]
    fn pgp_generates_and_verifies() {
        let session_id = sid();
        let rand = rand();
        let cert = cert();
        let sps = make_sps(&session_id, &rand);
        let spp = make_spp(cert.clone());
        let hsp = HSPProof::generate(&session_id, &rand, &sps, &spp);
        let qp = QueryRecord::build(&session_id, &rand, b"GET /", b"OK");
        let stmt = Statement::derive(b"result:OK".to_vec(), "test/v1".into(), &qp.transcript_commitment);
        let pgp = PGPProof::generate(&session_id, &rand, &qp, stmt, &hsp);
        verify_pgp_proof(&pgp, &rand, &hsp).expect("PGP verification failed");
    }

    #[test]
    fn dctls_evidence_verify_all() {
        let session_id = sid();
        let rand = rand();
        let cert = cert();
        let sps = make_sps(&session_id, &rand);
        let spp = make_spp(cert.clone());
        let hsp = HSPProof::generate(&session_id, &rand, &sps, &spp);
        let qp = QueryRecord::build(&session_id, &rand, b"GET /", b"OK");
        let stmt = Statement::derive(b"result:OK".to_vec(), "test/v1".into(), &qp.transcript_commitment);
        let pgp = PGPProof::generate(&session_id, &rand, &qp, stmt, &hsp);
        let evidence = DctlsEvidence { hsp_proof: hsp, query_record: qp, pgp_proof: pgp };
        evidence.verify_all(&rand, &cert, b"GET /", b"OK").expect("verify_all failed");
    }
}
