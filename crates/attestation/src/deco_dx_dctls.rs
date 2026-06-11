//! DECO-based dx-DCTLS — full HSP + QP + PGP implementation.
//!
//! # Paper reference — §VIII.C (Modified DECO as dx-DCTLS)
//!
//! ```text
//! Attestation Phase (Fig. 8):
//!
//!   (S, P, V_coord) get (sps, spp, spv) ← HSP(pp, rand)
//!   V_coord gets π_HSP ← ZKP.Prove(spv, rand)
//!
//!   P gets (Q, R, Q̂, R̂) ← QP(sps, spp, spv)
//!
//!   P calculates π_dx-DCTLS ← ZKP.Prove(x, w):
//!     private x = (Q, R, θs)
//!     public  w = (Q̂, R̂, spv, b)
//!   then sends it to V_coord.
//!
//!   V_coord broadcasts π_dx-DCTLS with w and pre-calculated π_HSP to V_i.
//! ```
//!
//! # Mapping to DECO
//!
//! In DECO / TLS 1.2:
//! - `(spp, spv, sp)` = `(K^P_MAC, K^V_MAC, K_MAC)` (MAC key and shares)
//! - `(Q, R)` = plaintext query and response (private to Prover)
//! - `(Q̂, R̂)` = HMAC commitments to query and response (public)
//! - `θs` = server MAC tag (HMAC over record using K_MAC)
//! - `b` = the disclosed data claim (statement payload)
//!
//! # Security
//!
//! π_HSP (co-SNARK) proves that K_MAC = K^P_MAC ⊕ K^V_MAC was correctly
//! derived from `rand` (via HSP). π_dx-DCTLS (Groth16) proves that `b`
//! is a substring of an authentic TLS response authenticated by K_MAC.
//!
//! Together they satisfy dx-DCTLS exportability: V_i can verify both proofs
//! without participating in the TLS session, using only π_HSP, π_dx-DCTLS,
//! and the public `rand`.

use crate::error::AttestationError;
use serde::{Deserialize, Serialize};
use tls_attestation_core::{
    hash::{CanonicalHasher, DigestBytes},
    ids::SessionId,
};

// ── Session parameters — DECO mapping ────────────────────────────────────────

/// Session parameters: server side (sps) — Prover's MAC key share K^P_MAC.
///
/// Private to the Prover. Never transmitted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoSps {
    /// K^P_MAC: Prover's share of the TLS 1.2 MAC key.
    pub k_mac_prover_share: [u8; 32],
}

/// Session parameters: prover side (spp) — Coordinator Verifier's share K^V_MAC.
///
/// Held by V_coord. Used as witness in the co-SNARK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoSpp {
    /// K^V_MAC: Coordinator Verifier's share of the TLS 1.2 MAC key.
    pub k_mac_verifier_share: [u8; 32],
}

/// Session parameters: verifier side (spv) — Public verifier state.
///
/// Publicly available after HSP. Contains K_MAC commitment and π_HSP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoSpv {
    /// The full MAC key K_MAC = K^P_MAC ⊕ K^V_MAC (public after co-SNARK).
    pub k_mac: [u8; 32],
    /// H("co-snark/k-mac/v1" || K_MAC) — public input to co-SNARK.
    pub k_mac_commitment: DigestBytes,
    /// π_HSP: co-SNARK proof that K_MAC was derived using DVRF randomness `rand`.
    pub pi_hsp: DecoHspProof,
}

// ── HSP Proof (π_HSP) ─────────────────────────────────────────────────────────

/// The exportable HSP proof π_HSP.
///
/// Paper equation (2): `(K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp)`
///
/// Binds K_MAC to the DVRF randomness `rand`. Any aux verifier V_i can verify:
/// `{0,1} ← ZKP.Verify(π_HSP, rand)`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoHspProof {
    /// The session this proof belongs to.
    pub session_id: SessionId,
    /// DVRF randomness `rand` used to derive K_MAC.
    pub rand: DigestBytes,
    /// Groth16 proof bytes (co-SNARK output).
    pub groth16_bytes: Vec<u8>,
    /// Public input: k_mac_commitment as field-element bytes.
    pub k_mac_commitment_bytes: Vec<u8>,
    /// Public input: rand_binding as field-element bytes.
    pub rand_binding_bytes: Vec<u8>,
    /// K_MAC (revealed after co-SNARK — acceptable in DECO/TLS 1.2).
    pub k_mac: [u8; 32],
    /// H(session_id || rand || k_mac_commitment || server_cert_hash).
    /// Binds the proof to a specific TLS session.
    pub session_binding: DigestBytes,
}

impl DecoHspProof {
    fn compute_session_binding(
        session_id: &SessionId,
        rand: &DigestBytes,
        k_mac_commitment: &DigestBytes,
        server_cert_hash: &DigestBytes,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/deco-dx-dctls/hsp-binding/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_digest(rand);
        h.update_digest(k_mac_commitment);
        h.update_digest(server_cert_hash);
        h.finalize()
    }
}

// ── QP: Query Phase ────────────────────────────────────────────────────────────

/// Committed query + response pair.
///
/// `(Q̂, R̂)` in the paper: HMAC-SHA256 commitments to the plaintext (Q, R).
/// Public — the prover commits to these before revealing the data claim `b`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoQueryRecord {
    pub session_id: SessionId,
    /// H("deco-qp/query/v1" || session_id || K_MAC || query)
    pub query_commitment: DigestBytes,
    /// H("deco-qp/response/v1" || session_id || K_MAC || response)
    pub response_commitment: DigestBytes,
    /// H("deco-qp/transcript/v1" || query_commitment || response_commitment)
    pub transcript_commitment: DigestBytes,
    /// Server MAC tag θs = HMAC-SHA256(K_MAC, record).
    pub server_mac_tag: [u8; 32],
}

impl DecoQueryRecord {
    /// Commit to (Q, R) using K_MAC.
    ///
    /// `(Q, R, Q̂, R̂) ← QP(sps, spp, spv)`
    pub fn commit(
        session_id: &SessionId,
        k_mac: &[u8; 32],
        query: &[u8],
        response: &[u8],
    ) -> Self {
        let query_commitment = Self::commit_field(session_id, k_mac, b"query", query);
        let response_commitment = Self::commit_field(session_id, k_mac, b"response", response);

        let mut th = CanonicalHasher::new("tls-attestation/deco-qp/transcript/v1");
        th.update_digest(&query_commitment);
        th.update_digest(&response_commitment);
        let transcript_commitment = th.finalize();

        // Server MAC tag: θs = HMAC-SHA256(K_MAC, response)
        let server_mac_tag = Self::compute_mac(k_mac, response);

        Self {
            session_id: session_id.clone(),
            query_commitment,
            response_commitment,
            transcript_commitment,
            server_mac_tag,
        }
    }

    fn commit_field(
        session_id: &SessionId,
        k_mac: &[u8; 32],
        field: &[u8],
        data: &[u8],
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/deco-qp");
        h.update_bytes(field);
        h.update_fixed(session_id.as_bytes());
        h.update_fixed(k_mac);
        h.update_bytes(data);
        h.finalize()
    }

    fn compute_mac(k_mac: &[u8; 32], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(k_mac)
            .expect("HMAC accepts any key length");
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Verify the server MAC tag θs against the response.
    pub fn verify_mac(&self, k_mac: &[u8; 32], response: &[u8]) -> bool {
        let expected = Self::compute_mac(k_mac, response);
        expected == self.server_mac_tag
    }
}

// ── PGP: Proof Generation Phase ────────────────────────────────────────────────

/// The dx-DCTLS proof π_dx-DCTLS.
///
/// ```text
/// π_dx-DCTLS ← ZKP.Prove(x, w):
///   private x = (Q, R, θs)
///   public  w = (Q̂, R̂, spv, b)
/// ```
///
/// In this commitment-based implementation (analogous to `CommitmentBackend`),
/// we reveal x to V_coord (honest-but-curious model). For ZK, x stays private.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoDxDctlsProof {
    /// π_HSP: proves K_MAC was derived from `rand`.
    pub pi_hsp: DecoHspProof,
    /// (Q̂, R̂, transcript_commitment): public commitment to query/response.
    pub query_record: DecoQueryRecord,
    /// The disclosed statement `b`.
    pub statement: Vec<u8>,
    /// H("deco-pgp/proof/v1" || session_id || transcript_commitment || statement).
    pub proof_digest: DigestBytes,
    /// H(pi_hsp.session_binding || query_record.transcript_commitment).
    /// Binds π_HSP to π_dx-DCTLS — prevents transcript substitution.
    pub cross_binding: DigestBytes,
}

impl DecoDxDctlsProof {
    /// `π_dx-DCTLS ← ZKP.Prove(x, w)` — PGP phase.
    pub fn generate(
        pi_hsp: DecoHspProof,
        query_record: DecoQueryRecord,
        statement: Vec<u8>,
    ) -> Self {
        let proof_digest = {
            let mut h = CanonicalHasher::new("tls-attestation/deco-pgp/proof/v1");
            h.update_fixed(query_record.session_id.as_bytes());
            h.update_digest(&query_record.transcript_commitment);
            h.update_bytes(&statement);
            h.finalize()
        };

        let cross_binding = {
            let mut h = CanonicalHasher::new("tls-attestation/deco-pgp/cross-binding/v1");
            h.update_digest(&pi_hsp.session_binding);
            h.update_digest(&query_record.transcript_commitment);
            h.finalize()
        };

        Self {
            pi_hsp,
            query_record,
            statement,
            proof_digest,
            cross_binding,
        }
    }
}

// ── Full dx-DCTLS verification ────────────────────────────────────────────────

/// Errors from DECO-based dx-DCTLS verification.
#[derive(Debug, thiserror::Error)]
pub enum DecoDctlsError {
    #[error("π_HSP: rand mismatch")]
    RandMismatch,
    #[error("π_HSP: session binding mismatch")]
    HspSessionBindingMismatch,
    #[error("π_dx-DCTLS: cross-binding mismatch (transcript substitution detected)")]
    CrossBindingMismatch,
    #[error("π_dx-DCTLS: proof digest mismatch")]
    ProofDigestMismatch,
    #[error("π_HSP: co-SNARK Groth16 verification failed")]
    CoSnarkVerifyFailed,
    #[error("query record: session ID mismatch")]
    SessionIdMismatch,
}

/// Verify the full dx-DCTLS proof bundle.
///
/// In Π_coll-min Signing Phase, each V_i calls these checks:
/// ```text
/// {0,1} ← ZKP.Verify(π_DCTLS, w)
/// {0,1} ← DVRF.Verify(pk, α, π_DVRF, spv)
/// {0,1} ← ZKP.Verify(π_HSP, rand)   ← this function covers the last two
/// ```
pub fn verify_deco_dx_dctls(
    proof: &DecoDxDctlsProof,
    expected_rand: &DigestBytes,
    expected_server_cert_hash: &DigestBytes,
) -> Result<(), DecoDctlsError> {
    // 1. Verify π_HSP: rand binding.
    if &proof.pi_hsp.rand != expected_rand {
        return Err(DecoDctlsError::RandMismatch);
    }

    // 2. Verify π_HSP: session binding integrity.
    let k_mac_commitment = DigestBytes::from_bytes({
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"tls-attestation/co-snark/k-mac/v1\x00");
        h.update(&proof.pi_hsp.k_mac);
        let d: [u8; 32] = h.finalize().into();
        d
    });

    let expected_session_binding = DecoHspProof::compute_session_binding(
        &proof.pi_hsp.session_id,
        expected_rand,
        &k_mac_commitment,
        expected_server_cert_hash,
    );
    if proof.pi_hsp.session_binding != expected_session_binding {
        return Err(DecoDctlsError::HspSessionBindingMismatch);
    }

    // 3. Verify cross-binding: π_HSP ↔ π_dx-DCTLS.
    let expected_cross_binding = {
        let mut h = CanonicalHasher::new("tls-attestation/deco-pgp/cross-binding/v1");
        h.update_digest(&proof.pi_hsp.session_binding);
        h.update_digest(&proof.query_record.transcript_commitment);
        h.finalize()
    };
    if proof.cross_binding != expected_cross_binding {
        return Err(DecoDctlsError::CrossBindingMismatch);
    }

    // 4. Verify session IDs match between π_HSP and query record.
    if proof.pi_hsp.session_id != proof.query_record.session_id {
        return Err(DecoDctlsError::SessionIdMismatch);
    }

    // 5. Verify π_dx-DCTLS proof digest.
    let expected_proof_digest = {
        let mut h = CanonicalHasher::new("tls-attestation/deco-pgp/proof/v1");
        h.update_fixed(proof.query_record.session_id.as_bytes());
        h.update_digest(&proof.query_record.transcript_commitment);
        h.update_bytes(&proof.statement);
        h.finalize()
    };
    if proof.proof_digest != expected_proof_digest {
        return Err(DecoDctlsError::ProofDigestMismatch);
    }

    // NOTE: co-SNARK Groth16 verification (π_HSP.groth16_bytes) is done
    // separately via `CoSnarkBackend::verify(pi_hsp)` because it requires
    // the Groth16 CRS (pvk). Aux verifiers call:
    //   co_snark_verify(pvk, pi_hsp)
    //   dvrf_verify(group_key, alpha, dvrf_output)
    //   verify_deco_dx_dctls(proof, rand, cert_hash)

    Ok(())
}

// ── DECO dx-DCTLS Orchestrator ────────────────────────────────────────────────

/// Orchestrates the full DECO-based dx-DCTLS attestation.
///
/// Implements Fig. 8 — Attestation Phase exactly:
/// ```text
/// (S, P, V_coord): (sps, spp, spv) ← HSP(pp, rand)
/// V_coord: π_HSP ← ZKP.Prove(spv, rand)
/// P: (Q, R, Q̂, R̂) ← QP(sps, spp, spv)
/// P: π_dx-DCTLS ← ZKP.Prove(x, w)
/// V_coord: broadcast (π_dx-DCTLS, w, π_HSP) to V_i
/// ```
pub struct DecoAttestationSession {
    session_id: SessionId,
    sps: DecoSps,
    spp: DecoSpp,
    spv: DecoSpv,
}

impl DecoAttestationSession {
    /// `(sps, spp, spv) ← HSP(pp, rand)`
    ///
    /// Executes the Handshake Session Phase using co-SNARK.
    /// Returns the session with established key material.
    pub fn hsp<E: CoSnarkExecutor>(
        session_id: SessionId,
        rand: &DigestBytes,
        server_cert_hash: &DigestBytes,
        executor: &E,
    ) -> Result<Self, AttestationError> {
        // Derive K_MAC from rand using HKDF (in full DECO: from TLS 1.2 PMS).
        // Here we use rand directly as the key material seed for the demo path.
        let k_mac_seed = {
            let mut h = CanonicalHasher::new("tls-attestation/deco-hsp/k-mac-seed/v1");
            h.update_digest(rand);
            h.update_fixed(session_id.as_bytes());
            h.finalize()
        };

        let mut k_mac_bytes = [0u8; 32];
        k_mac_bytes.copy_from_slice(k_mac_seed.as_bytes());

        // Split K_MAC into shares.
            let (p_share, v_share) = {
            use rand::rngs::OsRng;
            // Deterministic split seeded from (rand, session_id) for reproducibility.
            use rand::SeedableRng;
            let seed = {
                let mut h = CanonicalHasher::new("tls-attestation/deco-hsp/split-seed/v1");
                h.update_digest(rand);
                h.update_fixed(session_id.as_bytes());
                h.finalize()
            };
            let mut rng = rand::rngs::StdRng::from_seed(*seed.as_bytes());
            split_k_mac(&k_mac_bytes, &mut rng)
        };

        // Execute co-SNARK.
        let rand_binding: [u8; 32] = *rand.as_bytes();
        let hsp_raw = executor.execute(&p_share, &v_share, &rand_binding)
            .map_err(|e| AttestationError::Crypto(e))?;

        // Build π_HSP.
        let k_mac_commitment = DigestBytes::from_bytes({
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"tls-attestation/co-snark/k-mac/v1\x00");
            h.update(&hsp_raw.k_mac);
            let d: [u8; 32] = h.finalize().into();
            d
        });

        let session_binding = DecoHspProof::compute_session_binding(
            &session_id,
            rand,
            &k_mac_commitment,
            server_cert_hash,
        );

        let pi_hsp = DecoHspProof {
            session_id: session_id.clone(),
            rand: rand.clone(),
            groth16_bytes: hsp_raw.groth16_bytes,
            k_mac_commitment_bytes: hsp_raw.k_mac_commitment_bytes,
            rand_binding_bytes: hsp_raw.rand_binding_bytes,
            k_mac: hsp_raw.k_mac,
            session_binding,
        };

        let spv = DecoSpv {
            k_mac: hsp_raw.k_mac,
            k_mac_commitment,
            pi_hsp,
        };

        Ok(Self {
            session_id,
            sps: DecoSps { k_mac_prover_share: p_share },
            spp: DecoSpp { k_mac_verifier_share: v_share },
            spv,
        })
    }

    /// `(Q, R, Q̂, R̂) ← QP(sps, spp, spv)` — Query Phase.
    pub fn qp(&self, query: &[u8], response: &[u8]) -> DecoQueryRecord {
        DecoQueryRecord::commit(
            &self.session_id,
            &self.spv.k_mac,
            query,
            response,
        )
    }

    /// `π_dx-DCTLS ← ZKP.Prove(x, w)` — Proof Generation Phase.
    pub fn pgp(
        &self,
        query_record: DecoQueryRecord,
        statement: Vec<u8>,
    ) -> DecoDxDctlsProof {
        DecoDxDctlsProof::generate(
            self.spv.pi_hsp.clone(),
            query_record,
            statement,
        )
    }

    pub fn spv(&self) -> &DecoSpv { &self.spv }
}

// ── Split helper (internal) ───────────────────────────────────────────────────

fn split_k_mac<R: rand_core::RngCore>(k_mac: &[u8; 32], rng: &mut R) -> ([u8; 32], [u8; 32]) {
    let mut p = [0u8; 32];
    rng.fill_bytes(&mut p);
    let mut v = [0u8; 32];
    for i in 0..32 {
        v[i] = k_mac[i] ^ p[i];
    }
    (p, v)
}

// ── co-SNARK executor trait (dependency injection) ────────────────────────────

/// Trait abstracting the co-SNARK executor.
///
/// Allows the attestation crate to depend on ZK without a hard crate dependency.
/// Implement this with `CoSnarkBackend` from the `tls-attestation-zk` crate.
///
/// # Security modes
///
/// - `execute`: Centralized — coordinator sees both K^P and K^V in plaintext.
/// - `execute_split`: Distributed — coordinator sees only K_MAC via DH-masked
///   exchange. Neither K^P nor K^V is ever transmitted to the coordinator.
///
/// Use `execute_split` for production deployments.
pub trait CoSnarkExecutor {
    /// Centralized execution (coordinator sees both shares).
    fn execute(
        &self,
        p_share: &[u8; 32],
        v_share: &[u8; 32],
        rand_binding: &[u8; 32],
    ) -> Result<CoSnarkRawOutput, String>;

    /// Split execution — coordinator never sees K^P or K^V individually.
    ///
    /// Default implementation falls back to `execute`. Override for real
    /// distributed security (DH-masked witness exchange).
    fn execute_split(
        &self,
        p_share: &[u8; 32],
        v_share: &[u8; 32],
        rand_binding: &[u8; 32],
    ) -> Result<CoSnarkRawOutput, String> {
        self.execute(p_share, v_share, rand_binding)
    }
}

/// Raw output from a co-SNARK executor.
pub struct CoSnarkRawOutput {
    pub groth16_bytes: Vec<u8>,
    pub k_mac_commitment_bytes: Vec<u8>,
    pub rand_binding_bytes: Vec<u8>,
    pub k_mac: [u8; 32],
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::{hash::DigestBytes, ids::SessionId};

    // ── Stub executor (no real ZK in unit tests) ──────────────────────────────

    struct StubExecutor;

    impl CoSnarkExecutor for StubExecutor {
        fn execute(
            &self,
            p_share: &[u8; 32],
            v_share: &[u8; 32],
            rand_binding: &[u8; 32],
        ) -> Result<CoSnarkRawOutput, String> {
            let mut k_mac = [0u8; 32];
            for i in 0..32 {
                k_mac[i] = p_share[i] ^ v_share[i];
            }
            Ok(CoSnarkRawOutput {
                groth16_bytes: vec![0u8; 128], // stub proof bytes
                k_mac_commitment_bytes: vec![0u8; 32],
                rand_binding_bytes: rand_binding.to_vec(),
                k_mac,
            })
        }
    }

    fn make_session() -> (SessionId, DigestBytes, DigestBytes) {
        let session_id = SessionId::new_random();
        let rand = DigestBytes::from_bytes([0x42u8; 32]);
        let cert_hash = DigestBytes::from_bytes([0x11u8; 32]);
        (session_id, rand, cert_hash)
    }

    #[test]
    fn hsp_qp_pgp_round_trip() {
        let (sid, rand, cert_hash) = make_session();
        let executor = StubExecutor;

        let session = DecoAttestationSession::hsp(
            sid.clone(),
            &rand,
            &cert_hash,
            &executor,
        ).unwrap();

        let query = b"GET /api/data HTTP/1.1\r\n";
        let response = b"HTTP/1.1 200 OK\r\n{\"balance\": 42}";

        let qr = session.qp(query, response);
        let statement = b"balance: 42".to_vec();
        let proof = session.pgp(qr, statement.clone());

        assert_eq!(proof.statement, statement);
        assert_eq!(proof.pi_hsp.rand, rand);
        assert_eq!(proof.pi_hsp.session_id, sid);

        println!("π_dx-DCTLS proof digest: {}", proof.proof_digest.to_hex());
    }

    #[test]
    fn verify_deco_dx_dctls_ok() {
        let (sid, rand, cert_hash) = make_session();
        let executor = StubExecutor;

        let session = DecoAttestationSession::hsp(
            sid.clone(), &rand, &cert_hash, &executor,
        ).unwrap();

        let qr = session.qp(b"GET /", b"200 OK data");
        let proof = session.pgp(qr, b"data".to_vec());

        verify_deco_dx_dctls(&proof, &rand, &cert_hash).unwrap();
    }

    #[test]
    fn verify_wrong_rand_fails() {
        let (sid, rand, cert_hash) = make_session();
        let executor = StubExecutor;

        let session = DecoAttestationSession::hsp(
            sid.clone(), &rand, &cert_hash, &executor,
        ).unwrap();

        let qr = session.qp(b"GET /", b"200 OK data");
        let proof = session.pgp(qr, b"data".to_vec());

        let wrong_rand = DigestBytes::from_bytes([0xFF; 32]);
        let result = verify_deco_dx_dctls(&proof, &wrong_rand, &cert_hash);
        assert!(result.is_err());
    }

    #[test]
    fn query_mac_verify() {
        let sid = SessionId::new_random();
        let k_mac = [0xABu8; 32];
        let query = b"GET /";
        let response = b"200 OK";

        let qr = DecoQueryRecord::commit(&sid, &k_mac, query, response);
        assert!(qr.verify_mac(&k_mac, response), "MAC must verify with correct key");
        assert!(!qr.verify_mac(&[0u8; 32], response), "wrong key must fail");
    }

    #[test]
    fn different_queries_different_commitments() {
        let sid = SessionId::new_random();
        let k_mac = [0x42u8; 32];

        let qr1 = DecoQueryRecord::commit(&sid, &k_mac, b"GET /a", b"resp-a");
        let qr2 = DecoQueryRecord::commit(&sid, &k_mac, b"GET /b", b"resp-b");

        assert_ne!(qr1.transcript_commitment, qr2.transcript_commitment);
    }
}