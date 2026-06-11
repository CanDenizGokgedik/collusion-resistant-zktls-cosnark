//! Distefano-based dx-DCTLS — TLS 1.3 variant using verifiable 2PC (v2PC).
//!
//! # Paper reference — §VIII.C (Modified Distefano as dx-DCTLS)
//!
//! > "Unlike the DECO setting, co-SNARKs cannot be employed here because,
//! > while K_MAC in TLS 1.2 can be made transparent to all parties, TLS 1.3
//! > does not separate message authentication from encryption."
//! >
//! > "For this reason, the sum of spp and spv is never revealed to V_coord
//! > or the auxiliary verifiers in the Distefano construction."
//! >
//! > "A Distefano-based dx-DCTLS instantiation is obtained by replacing all
//! > two-party computations with verifiable two-party computation (v2PC)
//! > primitives."
//! >
//! > `(spp, spv, π_2PC) ← v2PC.Execute(sp, sv)` (equation 3)
//!
//! # TLS 1.3 vs TLS 1.2 difference
//!
//! In TLS 1.2 (DECO):
//! - K_MAC is separate from the encryption key → can be revealed
//! - co-SNARK can expose K_MAC to all parties
//!
//! In TLS 1.3 (Distefano):
//! - AEAD integrates authentication and encryption → cannot reveal joint secret
//! - v2PC proves correct derivation WITHOUT revealing the secret sum
//! - Each party proves their share is correctly derived from DVRF output sv
//!
//! # v2PC abstraction
//!
//! ```text
//! v2PC = (Execute, Verify) where:
//!
//!   Execute(sp, sv):
//!     P (prover) holds sp (their traffic secret share)
//!     V (verifier) holds sv (the DVRF-derived randomness)
//!     Output: (spp, spv, π_2PC) where spp+spv = f(sp, sv) [never revealed]
//!
//!   Verify(spp, spv, π_2PC, sv) = {0,1}
//!     Any Vi can verify the derivation was correct using only public data.
//! ```
//!
//! # Security (paper §VIII.C)
//!
//! > "Any deviation from a correctly derived traffic secret tuple (spp, spv)
//! > would necessitate either forging one of the v2PC proof π_HSP, thereby
//! > contradicting the soundness property of the underlying v2PC instances."
//!
//! # Implementation note
//!
//! This implements a commitment-based v2PC approximation. The full v2PC
//! would use a garbled circuit or ZK proof of TLS 1.3 key derivation.
//! The `V2pcExecutor` trait provides the abstraction point for swapping in
//! a full implementation.

use crate::error::AttestationError;
use serde::{Deserialize, Serialize};
use tls_attestation_core::{
    hash::{CanonicalHasher, DigestBytes},
    ids::SessionId,
};

// ── TLS 1.3 traffic secret structure ─────────────────────────────────────────

/// TLS 1.3 handshake traffic secret derivation parameters.
///
/// Captures the HKDF-based key schedule for TLS 1.3:
/// ```text
/// early_secret       = HKDF-Extract(0, 0)
/// handshake_secret   = HKDF-Extract(derived_secret, DHE)
/// master_secret      = HKDF-Extract(derived_secret, 0)
/// client_traffic_sec = HKDF-Expand-Label(handshake_secret, "c hs traffic", H, 32)
/// server_traffic_sec = HKDF-Expand-Label(handshake_secret, "s hs traffic", H, 32)
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tls13SecretParams {
    /// H(ClientHello || ServerHello) — transcript hash at handshake secret stage.
    pub transcript_hash: [u8; 32],
    /// DH shared secret from key exchange.
    pub dhe_secret: [u8; 32],
    /// TLS 1.3 ALPN / SNI.
    pub server_name: String,
}

// ── v2PC output (spp, spv) ────────────────────────────────────────────────────

/// Prover's traffic secret share (spp).
///
/// Private to the Prover. Never revealed to V_coord.
/// Contributed to the v2PC execution to derive the joint key material.
#[derive(Clone, Debug, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ProverTrafficShare {
    /// Prover's share of the client_write_key derivation.
    pub client_key_share: [u8; 32],
    /// Prover's share of the server_write_key derivation.
    pub server_key_share: [u8; 32],
}

/// Coordinator Verifier's traffic secret share (spv).
///
/// Held by V_coord. Used together with spp to prove correct key derivation.
#[derive(Clone, Debug, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct VerifierTrafficShare {
    /// Verifier's share of the client_write_key derivation.
    pub client_key_share: [u8; 32],
    /// Verifier's share of the server_write_key derivation.
    pub server_key_share: [u8; 32],
}

// ── v2PC Proof (π_2PC) ────────────────────────────────────────────────────────

/// The v2PC proof π_2PC for Distefano-based dx-DCTLS.
///
/// Paper equation (3): `(spp, spv, π_2PC) ← v2PC.Execute(sp, sv)`
///
/// Verifiable by any V_i via: `{0,1} ← v2PC.Verify(spp, spv, π_2PC, sv)`
///
/// In this commitment-based implementation, π_2PC is a hash commitment chain
/// binding the shares to sv (DVRF output) without revealing the traffic secret sum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct V2pcProof {
    pub session_id: SessionId,
    /// DVRF randomness sv used to derive the key material.
    pub sv: DigestBytes,
    /// H("v2pc/prover-commit/v1" || session_id || sv || spp.client_key_share)
    /// Commits to spp without revealing it.
    pub prover_share_commitment: DigestBytes,
    /// H("v2pc/verifier-commit/v1" || session_id || sv || spv.server_key_share)
    /// Commits to spv without revealing it.
    pub verifier_share_commitment: DigestBytes,
    /// H("v2pc/joint-commit/v1" || prover_commit || verifier_commit)
    /// Joint commitment — public input for aux verifier verification.
    pub joint_commitment: DigestBytes,
    /// H("v2pc/session-binding/v1" || session_id || sv || joint_commitment || cert_hash)
    pub session_binding: DigestBytes,
}

impl V2pcProof {
    pub fn compute_prover_commitment(
        session_id: &SessionId,
        sv: &DigestBytes,
        spp: &ProverTrafficShare,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/v2pc/prover-commit/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_digest(sv);
        h.update_fixed(&spp.client_key_share);
        h.update_fixed(&spp.server_key_share);
        h.finalize()
    }

    pub fn compute_verifier_commitment(
        session_id: &SessionId,
        sv: &DigestBytes,
        spv: &VerifierTrafficShare,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/v2pc/verifier-commit/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_digest(sv);
        h.update_fixed(&spv.client_key_share);
        h.update_fixed(&spv.server_key_share);
        h.finalize()
    }

    pub fn compute_joint_commitment(
        prover_commit: &DigestBytes,
        verifier_commit: &DigestBytes,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/v2pc/joint-commit/v1");
        h.update_digest(prover_commit);
        h.update_digest(verifier_commit);
        h.finalize()
    }

    pub fn compute_session_binding(
        session_id: &SessionId,
        sv: &DigestBytes,
        joint_commitment: &DigestBytes,
        server_cert_hash: &DigestBytes,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/v2pc/session-binding/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_digest(sv);
        h.update_digest(joint_commitment);
        h.update_digest(server_cert_hash);
        h.finalize()
    }
}

// ── Distefano HSP (π_HSP for TLS 1.3) ────────────────────────────────────────

/// The Distefano-based dx-DCTLS HSP proof.
///
/// Unlike DECO, this proof does NOT reveal the traffic secret sum.
/// It proves that (spp, spv) were correctly derived from sv (DVRF output)
/// through v2PC, without disclosing the joint key material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistefanoHspProof {
    pub session_id: SessionId,
    /// DVRF randomness sv.
    pub sv: DigestBytes,
    /// v2PC proof binding (spp, spv) to sv.
    pub pi_2pc: V2pcProof,
    /// TLS 1.3 server certificate hash.
    pub server_cert_hash: DigestBytes,
    /// TLS version (should be 0x0304).
    pub tls_version: u16,
    /// SNI server name.
    pub server_name: String,
    /// Session timestamp.
    pub established_at: u64,
}

// ── QP for Distefano (TLS 1.3 CBC-free) ──────────────────────────────────────

/// Distefano Query Phase record.
///
/// In TLS 1.3 (AEAD), the query/response binding uses GCM authentication tags
/// rather than HMAC-SHA256. The server_auth_tag proves the response is authentic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistefanoQueryRecord {
    pub session_id: SessionId,
    /// H("distefano-qp/query/v1" || session_id || query)
    pub query_commitment: DigestBytes,
    /// H("distefano-qp/response/v1" || session_id || response)
    pub response_commitment: DigestBytes,
    /// H("distefano-qp/transcript/v1" || qc || rc)
    pub transcript_commitment: DigestBytes,
    /// AES-GCM authentication tag (16 bytes) proving server authenticated response.
    pub server_auth_tag: [u8; 16],
}

impl DistefanoQueryRecord {
    /// Commit to (Q, R) using session_id only (traffic key never revealed).
    pub fn commit(
        session_id: &SessionId,
        query: &[u8],
        response: &[u8],
        server_auth_tag: [u8; 16],
    ) -> Self {
        let query_commitment = {
            let mut h = CanonicalHasher::new("tls-attestation/distefano-qp/query/v1");
            h.update_fixed(session_id.as_bytes());
            h.update_bytes(query);
            h.finalize()
        };
        let response_commitment = {
            let mut h = CanonicalHasher::new("tls-attestation/distefano-qp/response/v1");
            h.update_fixed(session_id.as_bytes());
            h.update_bytes(response);
            h.finalize()
        };
        let mut th = CanonicalHasher::new("tls-attestation/distefano-qp/transcript/v1");
        th.update_digest(&query_commitment);
        th.update_digest(&response_commitment);
        let transcript_commitment = th.finalize();

        Self {
            session_id: session_id.clone(),
            query_commitment,
            response_commitment,
            transcript_commitment,
            server_auth_tag,
        }
    }
}

// ── Full Distefano dx-DCTLS Proof ─────────────────────────────────────────────

/// The full Distefano-based π_dx-DCTLS proof bundle.
///
/// ```text
/// π_dx-DCTLS ← ZKP.Prove(x, w):
///   private x = (Q, R, auth_tag)
///   public  w = (Q̂, R̂, spv, b)
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistefanoDxDctlsProof {
    /// π_HSP: v2PC proof that (spp, spv) derive from sv.
    pub pi_hsp: DistefanoHspProof,
    /// Query Phase record.
    pub query_record: DistefanoQueryRecord,
    /// The disclosed statement b.
    pub statement: Vec<u8>,
    /// H("distefano-pgp/proof/v1" || session_id || transcript || statement)
    pub proof_digest: DigestBytes,
    /// Cross-binding: π_HSP ↔ π_dx-DCTLS.
    pub cross_binding: DigestBytes,
}

impl DistefanoDxDctlsProof {
    pub fn generate(
        pi_hsp: DistefanoHspProof,
        query_record: DistefanoQueryRecord,
        statement: Vec<u8>,
    ) -> Self {
        let proof_digest = {
            let mut h = CanonicalHasher::new("tls-attestation/distefano-pgp/proof/v1");
            h.update_fixed(query_record.session_id.as_bytes());
            h.update_digest(&query_record.transcript_commitment);
            h.update_bytes(&statement);
            h.finalize()
        };
        let cross_binding = {
            let mut h = CanonicalHasher::new("tls-attestation/distefano-pgp/cross-binding/v1");
            h.update_digest(&pi_hsp.pi_2pc.session_binding);
            h.update_digest(&query_record.transcript_commitment);
            h.finalize()
        };
        Self { pi_hsp, query_record, statement, proof_digest, cross_binding }
    }
}

// ── v2PC Executor trait ───────────────────────────────────────────────────────

/// Trait abstracting the v2PC execution.
///
/// Implement this with a garbled circuit or ZK proof backend.
/// The default `CommitmentV2pcExecutor` provides the commitment-based approximation.
pub trait V2pcExecutor {
    fn execute(
        &self,
        session_id: &SessionId,
        sv: &DigestBytes,
        sp: &Tls13SecretParams,
    ) -> Result<(ProverTrafficShare, VerifierTrafficShare, V2pcProof), AttestationError>;

    fn verify(
        &self,
        pi_2pc: &V2pcProof,
        sv: &DigestBytes,
    ) -> Result<(), AttestationError>;
}

/// Commitment-based v2PC executor (honest-but-curious model).
///
/// Derives traffic secret shares from sv using HKDF-like expansion.
/// Does not provide ZK — shares are revealed to the coordinator.
pub struct CommitmentV2pcExecutor;

impl V2pcExecutor for CommitmentV2pcExecutor {
    fn execute(
        &self,
        session_id: &SessionId,
        sv: &DigestBytes,
        sp: &Tls13SecretParams,
    ) -> Result<(ProverTrafficShare, VerifierTrafficShare, V2pcProof), AttestationError> {
        // Derive joint traffic key using sv and TLS 1.3 params.
        let joint_material = Self::derive_traffic_material(sv, sp);

        // Split into shares using deterministic seeding from (sv, session_id).
        let (spp, spv) = Self::split_shares(&joint_material, session_id, sv);

        // Build commitments.
        let pc = V2pcProof::compute_prover_commitment(session_id, sv, &spp);
        let vc = V2pcProof::compute_verifier_commitment(session_id, sv, &spv);
        let jc = V2pcProof::compute_joint_commitment(&pc, &vc);

        // Server cert hash placeholder — set by the session context in production.
        let cert_hash = DigestBytes::from_bytes([0u8; 32]);
        let sb = V2pcProof::compute_session_binding(session_id, sv, &jc, &cert_hash);

        let pi_2pc = V2pcProof {
            session_id: session_id.clone(),
            sv: sv.clone(),
            prover_share_commitment: pc,
            verifier_share_commitment: vc,
            joint_commitment: jc,
            session_binding: sb,
        };

        Ok((spp, spv, pi_2pc))
    }

    fn verify(
        &self,
        pi_2pc: &V2pcProof,
        sv: &DigestBytes,
    ) -> Result<(), AttestationError> {
        if pi_2pc.sv != *sv {
            return Err(AttestationError::Crypto("v2PC: sv mismatch".into()));
        }
        // Recompute joint commitment from stored prover/verifier commitments.
        let expected_jc = V2pcProof::compute_joint_commitment(
            &pi_2pc.prover_share_commitment,
            &pi_2pc.verifier_share_commitment,
        );
        if pi_2pc.joint_commitment != expected_jc {
            return Err(AttestationError::Crypto("v2PC: joint commitment mismatch".into()));
        }
        Ok(())
    }
}

impl CommitmentV2pcExecutor {
    fn derive_traffic_material(sv: &DigestBytes, sp: &Tls13SecretParams) -> [[u8; 32]; 2] {
        use sha2::Digest;
        // Simulate TLS 1.3 HKDF-Expand-Label using SHA-256.
        let derive = |label: &[u8]| -> [u8; 32] {
            let mut h = sha2::Sha256::new();
            h.update(b"tls-attestation/tls13-key-derive/v1\x00");
            h.update(sv.as_bytes());
            h.update(&sp.transcript_hash);
            h.update(&sp.dhe_secret);
            h.update(label);
            h.finalize().into()
        };
        [derive(b"c-traffic"), derive(b"s-traffic")]
    }

    fn split_shares(
        material: &[[u8; 32]; 2],
        session_id: &SessionId,
        sv: &DigestBytes,
    ) -> (ProverTrafficShare, VerifierTrafficShare) {
        use sha2::Digest;
        // Deterministic prover share derived from (session_id, sv).
        let prover_seed = {
            let mut h = sha2::Sha256::new();
            h.update(b"tls-attestation/v2pc/prover-seed/v1\x00");
            h.update(session_id.as_bytes());
            h.update(sv.as_bytes());
            let d: [u8; 32] = h.finalize().into();
            d
        };

        let mut p_client = [0u8; 32];
        let mut p_server = [0u8; 32];
        let mut v_client = [0u8; 32];
        let mut v_server = [0u8; 32];

        // P share = seed bytes; V share = material XOR P share.
        for i in 0..32 {
            p_client[i] = prover_seed[i];
            v_client[i] = material[0][i] ^ prover_seed[i];
            // Different seed for server.
            p_server[i] = prover_seed[(i + 7) % 32];
            v_server[i] = material[1][i] ^ prover_seed[(i + 7) % 32];
        }

        (
            ProverTrafficShare { client_key_share: p_client, server_key_share: p_server },
            VerifierTrafficShare { client_key_share: v_client, server_key_share: v_server },
        )
    }
}

// ── Distefano Attestation Session ─────────────────────────────────────────────

/// Orchestrates Distefano-based dx-DCTLS attestation (TLS 1.3 path).
///
/// Implements Fig. 8 — Attestation Phase for TLS 1.3:
/// ```text
/// (S, P, V_coord): (spp, spv, π_2PC) ← v2PC.Execute(sp, sv)
/// V_coord: π_HSP ← v2PC generates commitments binding to sv
/// P: (Q, R, Q̂, R̂) ← QP(sps, spp, spv) — TLS 1.3 AEAD records
/// P: π_dx-DCTLS ← ZKP.Prove(x, w)
/// ```
pub struct DistefanoAttestationSession {
    session_id: SessionId,
    spp: ProverTrafficShare,
    spv: VerifierTrafficShare,
    pi_hsp: DistefanoHspProof,
}

impl DistefanoAttestationSession {
    /// Execute HSP: `(spp, spv, π_2PC) ← v2PC.Execute(sp, sv)`
    pub fn hsp<E: V2pcExecutor>(
        session_id: SessionId,
        sv: &DigestBytes,
        sp: &Tls13SecretParams,
        server_cert_hash: DigestBytes,
        tls_version: u16,
        executor: &E,
    ) -> Result<Self, AttestationError> {
        let (spp, spv, mut pi_2pc) = executor.execute(&session_id, sv, sp)?;

        // Update session binding with actual cert hash.
        pi_2pc.session_binding = V2pcProof::compute_session_binding(
            &session_id,
            sv,
            &pi_2pc.joint_commitment,
            &server_cert_hash,
        );

        let pi_hsp = DistefanoHspProof {
            session_id: session_id.clone(),
            sv: sv.clone(),
            pi_2pc,
            server_cert_hash,
            tls_version,
            server_name: sp.server_name.clone(),
            established_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };

        Ok(Self { session_id, spp, spv, pi_hsp })
    }

    /// QP: Commit to (Q, R) with the TLS 1.3 auth tag.
    pub fn qp(
        &self,
        query: &[u8],
        response: &[u8],
        server_auth_tag: [u8; 16],
    ) -> DistefanoQueryRecord {
        DistefanoQueryRecord::commit(&self.session_id, query, response, server_auth_tag)
    }

    /// PGP: Generate the full π_dx-DCTLS proof.
    pub fn pgp(
        &self,
        query_record: DistefanoQueryRecord,
        statement: Vec<u8>,
    ) -> DistefanoDxDctlsProof {
        DistefanoDxDctlsProof::generate(self.pi_hsp.clone(), query_record, statement)
    }
}

// ── Verification ─────────────────────────────────────────────────────────────

/// Verify a Distefano-based dx-DCTLS proof bundle.
///
/// Each V_i calls this during the Signing Phase.
#[derive(Debug, thiserror::Error)]
pub enum DistefanoError {
    #[error("sv mismatch in π_2PC")]
    SvMismatch,
    #[error("v2PC joint commitment mismatch")]
    JointCommitmentMismatch,
    #[error("session binding mismatch")]
    SessionBindingMismatch,
    #[error("cross-binding mismatch")]
    CrossBindingMismatch,
    #[error("proof digest mismatch")]
    ProofDigestMismatch,
    #[error("session ID mismatch between π_HSP and query record")]
    SessionIdMismatch,
}

pub fn verify_distefano_dx_dctls(
    proof: &DistefanoDxDctlsProof,
    expected_sv: &DigestBytes,
    expected_server_cert_hash: &DigestBytes,
) -> Result<(), DistefanoError> {
    let pi_2pc = &proof.pi_hsp.pi_2pc;

    // 1. sv binding.
    if &pi_2pc.sv != expected_sv {
        return Err(DistefanoError::SvMismatch);
    }

    // 2. Joint commitment integrity.
    let expected_jc = V2pcProof::compute_joint_commitment(
        &pi_2pc.prover_share_commitment,
        &pi_2pc.verifier_share_commitment,
    );
    if pi_2pc.joint_commitment != expected_jc {
        return Err(DistefanoError::JointCommitmentMismatch);
    }

    // 3. Session binding.
    let expected_sb = V2pcProof::compute_session_binding(
        &pi_2pc.session_id,
        expected_sv,
        &pi_2pc.joint_commitment,
        expected_server_cert_hash,
    );
    if pi_2pc.session_binding != expected_sb {
        return Err(DistefanoError::SessionBindingMismatch);
    }

    // 4. Cross-binding: π_HSP ↔ π_dx-DCTLS.
    let expected_cb = {
        let mut h = CanonicalHasher::new("tls-attestation/distefano-pgp/cross-binding/v1");
        h.update_digest(&pi_2pc.session_binding);
        h.update_digest(&proof.query_record.transcript_commitment);
        h.finalize()
    };
    if proof.cross_binding != expected_cb {
        return Err(DistefanoError::CrossBindingMismatch);
    }

    // 5. Session IDs match.
    if proof.pi_hsp.session_id != proof.query_record.session_id {
        return Err(DistefanoError::SessionIdMismatch);
    }

    // 6. Proof digest.
    let expected_pd = {
        let mut h = CanonicalHasher::new("tls-attestation/distefano-pgp/proof/v1");
        h.update_fixed(proof.query_record.session_id.as_bytes());
        h.update_digest(&proof.query_record.transcript_commitment);
        h.update_bytes(&proof.statement);
        h.finalize()
    };
    if proof.proof_digest != expected_pd {
        return Err(DistefanoError::ProofDigestMismatch);
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::ids::SessionId;

    fn make_session() -> (SessionId, DigestBytes, DigestBytes, Tls13SecretParams) {
        let sid = SessionId::new_random();
        let sv = DigestBytes::from_bytes([0x42u8; 32]);
        let cert_hash = DigestBytes::from_bytes([0x11u8; 32]);
        let sp = Tls13SecretParams {
            transcript_hash: [0x33u8; 32],
            dhe_secret: [0x44u8; 32],
            server_name: "api.example.com".into(),
        };
        (sid, sv, cert_hash, sp)
    }

    #[test]
    fn distefano_hsp_qp_pgp_roundtrip() {
        let (sid, sv, cert_hash, sp) = make_session();
        let executor = CommitmentV2pcExecutor;

        let session = DistefanoAttestationSession::hsp(
            sid.clone(),
            &sv,
            &sp,
            cert_hash.clone(),
            0x0304, // TLS 1.3
            &executor,
        ).unwrap();

        let qr = session.qp(b"GET /balance", b"200 OK {\"balance\":42}", [0xCCu8; 16]);
        let proof = session.pgp(qr, b"balance:42".to_vec());

        verify_distefano_dx_dctls(&proof, &sv, &cert_hash).unwrap();
        assert_eq!(proof.statement, b"balance:42");
    }

    #[test]
    fn verify_wrong_sv_fails() {
        let (sid, sv, cert_hash, sp) = make_session();
        let executor = CommitmentV2pcExecutor;

        let session = DistefanoAttestationSession::hsp(
            sid, &sv, &sp, cert_hash.clone(), 0x0304, &executor,
        ).unwrap();

        let qr = session.qp(b"GET /", b"200 OK", [0u8; 16]);
        let proof = session.pgp(qr, b"data".to_vec());

        let wrong_sv = DigestBytes::from_bytes([0xFFu8; 32]);
        let result = verify_distefano_dx_dctls(&proof, &wrong_sv, &cert_hash);
        assert!(result.is_err(), "wrong sv must fail verification");
    }

    #[test]
    fn v2pc_proof_verify_roundtrip() {
        let (sid, sv, _, sp) = make_session();
        let executor = CommitmentV2pcExecutor;
        let (_, _, pi_2pc) = executor.execute(&sid, &sv, &sp).unwrap();
        executor.verify(&pi_2pc, &sv).unwrap();
    }

    #[test]
    fn traffic_shares_xor_to_joint() {
        let (sid, sv, _, sp) = make_session();
        let executor = CommitmentV2pcExecutor;
        let material = CommitmentV2pcExecutor::derive_traffic_material(&sv, &sp);
        let (spp, spv) = CommitmentV2pcExecutor::split_shares(&material, &sid, &sv);

        // Verify XOR reconstruction.
        for i in 0..32 {
            assert_eq!(
                spp.client_key_share[i] ^ spv.client_key_share[i],
                material[0][i],
                "client key share XOR must equal joint material"
            );
        }
    }

    #[test]
    fn different_sv_different_shares() {
        let (sid, sv1, _, sp) = make_session();
        let sv2 = DigestBytes::from_bytes([0x99u8; 32]);
        let executor = CommitmentV2pcExecutor;
        let (spp1, _, _) = executor.execute(&sid, &sv1, &sp).unwrap();
        let (spp2, _, _) = executor.execute(&sid, &sv2, &sp).unwrap();
        assert_ne!(spp1.client_key_share, spp2.client_key_share);
    }
}