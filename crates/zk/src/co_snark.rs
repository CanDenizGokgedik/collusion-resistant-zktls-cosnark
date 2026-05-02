//! Collaborative zk-SNARK (co-SNARK) for dx-DCTLS π_HSP.
//!
//! # Paper reference
//!
//! Paper §III.B (Collaborative zk-SNARKs):
//!
//! > "A co-SNARK scheme consists of two algorithms, denoted as
//! > co-SNARK = (Execute, Verify) algorithms."
//! >
//! > `Execute`: Given a public statement x and a set of private witnesses
//! > {w_i}^n_{i=1} held by n collaborating provers, this algorithm performs
//! > a joint computation and outputs a public result y along with a succinct
//! > proof π attesting to the correctness of the computation.
//! >
//! > `Verify`: This deterministic algorithm takes as input the proof π and
//! > the public statement x, and verifies whether y was correctly computed
//! > with respect to x and some valid and hidden witnesses {w_i}.
//!
//! # Paper equation (2)
//!
//! ```text
//! (K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp)
//! ```
//!
//! where:
//! - K^P_MAC: Prover P's private witness (MAC key share)
//! - K^V_MAC: Coordinator Verifier V_coord's private witness (MAC key share)
//! - Zp: Pre-master secret (public to aux verifiers after the handshake)
//! - K_MAC: Reconstructed MAC key (output)
//! - π_HSP: Groth16 proof that K_MAC = K^P_MAC ⊕ K^V_MAC
//!
//! # Security
//!
//! From Appendix E (co-SNARK Security Definition):
//! > "While a co-SNARK scheme satisfies completeness, soundness, t-zero
//! > knowledge, succinctness, and knowledge soundness, our analysis focuses
//! > solely on the soundness property."
//!
//! Soundness guarantee: Any deviation from a correctly derived K_MAC would
//! necessitate forging a valid proof π_HSP, contradicting the soundness
//! property of the underlying Groth16 system (under the q-DLOG assumption).
//!
//! # Implementation note
//!
//! This implements collaborative proof generation by having both parties
//! submit their witness shares to a trusted coordinator who assembles the
//! full witness and generates the Groth16 proof. In a fully distributed
//! co-SNARK (Ozdemir & Boneh, S&P 2022, reference [32]), each party runs
//! their own sub-prover and never reveals their witness to the other party.
//! The `run_distributed` method documents where the distributed extension
//! would be integrated.

use crate::tls_prf_circuit::{TlsPrfCircuit, k_mac_commitment, bytes32_to_fr, pms_hash};
use crate::tls12_hmac::{ProverMacKeyShare, VerifierMacKeyShare, MacKey, combine_mac_key_shares};

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CoSnarkError {
    #[error("Groth16 setup failed: {0}")]
    Setup(String),
    #[error("Groth16 proof generation failed: {0}")]
    Prove(String),
    #[error("Groth16 verification failed")]
    Verify,
    #[error("Serialization error: {0}")]
    Serialize(String),
}

// ── Proving key ───────────────────────────────────────────────────────────────

type Pk  = <Groth16<Bn254> as SNARK<Fr>>::ProvingKey;
type Pvk = <Groth16<Bn254> as SNARK<Fr>>::ProcessedVerifyingKey;
type Pf  = <Groth16<Bn254> as SNARK<Fr>>::Proof;

/// Groth16 CRS (Common Reference String) for the TlsPrfCircuit.
///
/// Generated once during setup. In production, this should come from a
/// multi-party trusted setup ceremony.
pub struct CoSnarkCrs {
    pub(crate) pk:  Pk,
    pub(crate) pvk: Pvk,
}

impl CoSnarkCrs {
    /// Run Groth16 trusted setup for the TlsPrfCircuit.
    ///
    /// # Security
    ///
    /// Uses `OsRng` so the toxic waste τ is not recoverable from a known seed.
    /// For production deployments, replace this function with a multi-party
    /// computation (MPC) trusted setup ceremony that provably destroys τ.
    ///
    /// The old implementation seeded from a public constant (`"co-snark-setup/v1"`),
    /// making τ fully recoverable by any third party — which breaks Groth16 soundness
    /// completely (a forger can produce valid proofs for false statements).
    pub fn setup() -> Result<Self, CoSnarkError> {
        use rand::rngs::OsRng;
        let mut rng = OsRng;

        let circuit = TlsPrfCircuit::dummy();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| CoSnarkError::Setup(e.to_string()))?;

        let pvk = Groth16::<Bn254>::process_vk(&vk)
            .map_err(|e| CoSnarkError::Setup(e.to_string()))?;

        Ok(Self { pk, pvk })
    }

    /// Run Groth16 trusted setup for the full TLS-PRF circuit (Mode 2).
    ///
    /// Mode 2 adds a third public input `pms_hash_fe` binding the proof to a
    /// specific TLS session via the pre-master secret hash.  This requires a
    /// **separate** CRS from Mode 1 — the Groth16 VK encodes the exact number
    /// of public inputs and cannot be shared between circuit variants.
    ///
    /// # Security
    ///
    /// Same τ-destruction caveat as `setup()`.  In production, run an MPC
    /// ceremony over `TlsPrfCircuit::dummy_full_prf()`.
    pub fn setup_mode2() -> Result<Self, CoSnarkError> {
        use rand::rngs::OsRng;
        let mut rng = OsRng;

        let circuit = TlsPrfCircuit::dummy_full_prf(); // 3 public inputs

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| CoSnarkError::Setup(e.to_string()))?;

        let pvk = Groth16::<Bn254>::process_vk(&vk)
            .map_err(|e| CoSnarkError::Setup(e.to_string()))?;

        Ok(Self { pk, pvk })
    }

    /// Serialize the verifying key for distribution to aux verifiers.
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.pvk.serialize_compressed(&mut buf)
            .expect("pvk serialization must succeed");
        buf
    }
}

// ── π_HSP proof ───────────────────────────────────────────────────────────────

/// The HSP handshake proof π_HSP.
///
/// In Π_coll-min Signing Phase, each Vi verifies:
/// `{0,1} ← ZKP.Verify(π_HSP, rand)`
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HspProof {
    /// Groth16 proof bytes (compressed).
    pub groth16_bytes: Vec<u8>,
    /// Public input: pack(K_MAC) + rand_binding as little-endian Fr bytes.
    pub k_mac_commitment_bytes: Vec<u8>,
    /// Public input: DVRF randomness binding as little-endian Fr bytes.
    pub rand_binding_bytes: Vec<u8>,
    /// The reconstructed K_MAC — public after the co-SNARK execution.
    ///
    /// In DECO (TLS 1.2), K_MAC can be disclosed to all parties since
    /// it is separate from the encryption key.
    pub k_mac: [u8; 32],
    /// Public input (Mode 2 only): pack(SHA256(Zp)[0..32]) as little-endian Fr bytes.
    ///
    /// Auxiliary verifiers independently compute Zp = DH(sv, ys) from the DVRF
    /// output sv and the server's ephemeral DH share ys, then verify this field
    /// equals pms_hash(Zp).  Empty in Mode 1 proofs.
    ///
    /// This is the key fix for paper §VIII.C: the proof is now bound to a
    /// specific TLS session via the pre-master secret hash, not just to rand.
    pub pms_hash_bytes: Vec<u8>,
}

// ── co-SNARK Execute ──────────────────────────────────────────────────────────

/// `co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp) → (K_MAC, π_HSP)`
///
/// Produces the HSP proof by combining both parties' witness shares.
///
/// # Distributed extension
///
/// In a fully distributed co-SNARK (reference [32]), `execute` would be split
/// into:
/// - `execute_prover`: Prover runs sub-proof with K^P_MAC on their machine.
/// - `execute_verifier`: Verifier runs sub-proof with K^V_MAC on their machine.
/// - `combine_proofs`: Coordinator combines the two sub-proofs.
///
/// This would ensure neither party ever sees the other's witness share.
/// The current implementation assembles the full witness at the coordinator
/// level, which requires both parties to trust the coordinator (or the
/// coordinator is the verifier).
pub fn co_snark_execute(
    crs:      &CoSnarkCrs,
    p_share:  &ProverMacKeyShare,
    v_share:  &VerifierMacKeyShare,
    rand_binding: &[u8; 32],
) -> Result<HspProof, CoSnarkError> {
    // Reconstruct K_MAC = K^P_MAC ⊕ K^V_MAC.
    let k_mac = combine_mac_key_shares(p_share, v_share);

    // Build the circuit with split witnesses.
    let circuit = TlsPrfCircuit::new(
        p_share.0,
        v_share.0,
        rand_binding,
    );

    let commitment_fe = circuit.k_mac_commitment_fe;
    let rand_fe       = circuit.rand_binding_fe;

    // Build public input list — pms_hash_fe is a third public input in Mode 2.
    let pms_fe_opt = circuit.pms_hash_fe;
    let mut public_inputs = vec![commitment_fe, rand_fe];
    if let Some(pms_fe) = pms_fe_opt {
        public_inputs.push(pms_fe);
    }

    // Generate the Groth16 proof.
    // Security: use OsRng so the Groth16 blinding scalars (r, s) are not
    // recoverable from the witness.
    use rand::rngs::OsRng;
    let mut rng = OsRng;

    let proof = Groth16::<Bn254>::prove(&crs.pk, circuit, &mut rng)
        .map_err(|e| CoSnarkError::Prove(e.to_string()))?;

    // Serialize proof.
    let mut groth16_bytes = Vec::new();
    proof.serialize_compressed(&mut groth16_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    // Serialize public inputs.
    let mut commitment_bytes = Vec::new();
    commitment_fe.serialize_compressed(&mut commitment_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    let mut rand_bytes = Vec::new();
    rand_fe.serialize_compressed(&mut rand_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    let mut pms_hash_bytes = Vec::new();
    if let Some(pms_fe) = pms_fe_opt {
        pms_fe.serialize_compressed(&mut pms_hash_bytes)
            .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;
    }

    Ok(HspProof {
        groth16_bytes,
        k_mac_commitment_bytes: commitment_bytes,
        rand_binding_bytes: rand_bytes,
        k_mac: k_mac.0,
        pms_hash_bytes,
    })
}

/// `co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp) → (K_MAC, π_HSP)` — **Mode 2**
///
/// Like `co_snark_execute` but also binds the proof to the TLS session via the
/// pre-master secret `pms`.  The circuit proves:
///
/// 1. `K_MAC = K^P_MAC ⊕ K^V_MAC`              (2PC split correctness)
/// 2. `pack(K_MAC) + rand == commitment`         (randomness binding)
/// 3. `SHA256(pms) == pms_hash_fe`               (Zp identity binding)
/// 4. `TLS-PRF(pms, …) → K_MAC` — fully constrained HMAC-SHA256 chain
///
/// **Requires a Mode 2 CRS** produced by `CoSnarkCrs::setup_mode2()`.
/// Passing a Mode 1 CRS will cause `Groth16::prove` to fail with a public
/// input count mismatch.
pub fn co_snark_execute_mode2(
    crs:          &CoSnarkCrs,
    p_share:      &ProverMacKeyShare,
    v_share:      &VerifierMacKeyShare,
    rand_binding: &[u8; 32],
    pms:          &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<HspProof, CoSnarkError> {
    use crate::tls_prf_circuit::pms_hash;

    let k_mac = combine_mac_key_shares(p_share, v_share);

    let circuit = TlsPrfCircuit::with_tls_prf(
        p_share.0,
        v_share.0,
        rand_binding,
        pms.to_vec(),
        *client_random,
        *server_random,
    );

    let commitment_fe = circuit.k_mac_commitment_fe;
    let rand_fe       = circuit.rand_binding_fe;
    let pms_fe        = pms_hash(pms); // public input 3

    let public_inputs = vec![commitment_fe, rand_fe, pms_fe];

    use rand::rngs::OsRng;
    let mut rng = OsRng;

    let proof = Groth16::<Bn254>::prove(&crs.pk, circuit, &mut rng)
        .map_err(|e| CoSnarkError::Prove(e.to_string()))?;

    let mut groth16_bytes = Vec::new();
    proof.serialize_compressed(&mut groth16_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    let mut commitment_bytes = Vec::new();
    commitment_fe.serialize_compressed(&mut commitment_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    let mut rand_bytes = Vec::new();
    rand_fe.serialize_compressed(&mut rand_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    let mut pms_hash_bytes = Vec::new();
    pms_fe.serialize_compressed(&mut pms_hash_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    // Suppress unused warning — public_inputs is consumed by prove().
    let _ = public_inputs;

    Ok(HspProof {
        groth16_bytes,
        k_mac_commitment_bytes: commitment_bytes,
        rand_binding_bytes: rand_bytes,
        k_mac: k_mac.0,
        pms_hash_bytes,
    })
}

// ── co-SNARK Verify ───────────────────────────────────────────────────────────

/// `co-SNARK.Verify(y, π) = 1`
///
/// Verifies the π_HSP proof. Used by each aux verifier V_i in the Signing Phase.
///
/// In Π_coll-min: `{0,1} ← ZKP.Verify(π_HSP, rand)`
///
/// For Mode 2 proofs (pms_hash_bytes non-empty), callers should additionally
/// supply `expected_pms_hash` — the value they independently computed as
/// `pms_hash(Zp)` where `Zp = DH(sv, ys)`.  Pass `None` for Mode 1 proofs.
///
/// # Paper §VIII.C binding guarantee
///
/// When `expected_pms_hash` is provided and matches `proof.pms_hash_bytes`,
/// the Groth16 proof guarantees that the prover knew a PMS that:
///   (a) hashes to the expected value (Zp binding, via circuit constraint), and
///   (b) produces a K_MAC whose commitment matches `rand_binding` (session binding).
/// Together these prevent transcript substitution across TLS sessions.
pub fn co_snark_verify(
    pvk:                 &<Groth16<Bn254> as SNARK<Fr>>::ProcessedVerifyingKey,
    proof:               &HspProof,
    expected_pms_hash:   Option<Fr>,
) -> Result<(), CoSnarkError> {
    let groth16_proof = Pf::deserialize_compressed(proof.groth16_bytes.as_slice())
        .map_err(|e| CoSnarkError::Serialize(format!("proof deserialize: {e}")))?;

    let commitment_fe = Fr::deserialize_compressed(proof.k_mac_commitment_bytes.as_slice())
        .map_err(|e| CoSnarkError::Serialize(format!("commitment deserialize: {e}")))?;

    let rand_fe = Fr::deserialize_compressed(proof.rand_binding_bytes.as_slice())
        .map_err(|e| CoSnarkError::Serialize(format!("rand deserialize: {e}")))?;

    // Mode 2: include pms_hash as the third public input if present.
    let mut public_inputs = vec![commitment_fe, rand_fe];
    let proof_pms_fe_opt: Option<Fr> = if proof.pms_hash_bytes.is_empty() {
        None
    } else {
        Some(
            Fr::deserialize_compressed(proof.pms_hash_bytes.as_slice())
                .map_err(|e| CoSnarkError::Serialize(format!("pms_hash deserialize: {e}")))?,
        )
    };
    if let Some(pms_fe) = proof_pms_fe_opt {
        public_inputs.push(pms_fe);
    }

    let valid = Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &groth16_proof)
        .map_err(|e| CoSnarkError::Prove(e.to_string()))?;

    if !valid {
        return Err(CoSnarkError::Verify);
    }

    // Check: pack(K_MAC) + rand_binding == commitment (matches in-circuit constraint).
    let expected_commitment = k_mac_commitment(&proof.k_mac, rand_fe);
    if expected_commitment != commitment_fe {
        return Err(CoSnarkError::Verify);
    }

    // Mode 2: verify that the proof's pms_hash matches what the aux verifier
    // independently computed from Zp = DH(sv, ys).
    // This is the core Zp binding check from paper §VIII.C.
    match (expected_pms_hash, proof_pms_fe_opt) {
        (Some(expected_fe), Some(proof_fe)) => {
            // Mode 2: caller supplied expected hash AND proof carries one — must match.
            if proof_fe != expected_fe {
                return Err(CoSnarkError::Verify);
            }
        }
        (Some(_), None) => {
            // Caller expects Mode 2 binding but proof is Mode 1 — reject.
            return Err(CoSnarkError::Verify);
        }
        (None, Some(_)) => {
            // Proof carries pms_hash but caller did not supply expected value.
            // This is a caller error: Mode 2 proofs MUST be verified with
            // `expected_pms_hash = Some(pms_hash(Zp))`.  Reject to prevent
            // accidental Zp binding bypass.
            return Err(CoSnarkError::Verify);
        }
        (None, None) => {
            // Mode 1 proof, Mode 1 verification — no Zp binding check needed.
        }
    }

    Ok(())
}

/// Count R1CS constraints for a TlsPrfCircuit instance.
///
/// Used in benchmarks to report circuit sizes without running a full proof.
pub fn count_r1cs_constraints(circuit: TlsPrfCircuit) -> usize {
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::r1cs::ConstraintSynthesizer;
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).ok();
    cs.num_constraints()
}

/// High-level co-SNARK backend wrapping setup + execute + verify.
///
/// Use `CoSnarkBackend::setup()` once, then call `execute` per attestation session.
pub struct CoSnarkBackend {
    pub crs: CoSnarkCrs,
}

impl CoSnarkBackend {
    /// Create a Mode 1 backend (K_MAC split only).
    pub fn setup() -> Result<Self, CoSnarkError> {
        let crs = CoSnarkCrs::setup()?;
        Ok(Self { crs })
    }

    /// Create a Mode 2 backend (K_MAC split + full TLS-PRF + Zp binding).
    ///
    /// **Must** be used with `execute_mode2` and `verify` with
    /// `expected_pms_hash = Some(…)`.  Cannot be used with `execute`.
    pub fn setup_mode2() -> Result<Self, CoSnarkError> {
        let crs = CoSnarkCrs::setup_mode2()?;
        Ok(Self { crs })
    }

    /// `(K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC})` — Mode 1
    pub fn execute(
        &self,
        p_share:  &ProverMacKeyShare,
        v_share:  &VerifierMacKeyShare,
        rand_binding: &[u8; 32],
    ) -> Result<HspProof, CoSnarkError> {
        co_snark_execute(&self.crs, p_share, v_share, rand_binding)
    }

    /// `(K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp)` — Mode 2
    ///
    /// Requires a Mode 2 backend from `setup_mode2()`.
    pub fn execute_mode2(
        &self,
        p_share:       &ProverMacKeyShare,
        v_share:       &VerifierMacKeyShare,
        rand_binding:  &[u8; 32],
        pms:           &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Result<HspProof, CoSnarkError> {
        co_snark_execute_mode2(
            &self.crs, p_share, v_share, rand_binding, pms, client_random, server_random,
        )
    }

    /// `co-SNARK.Verify(y, π) = 1`
    ///
    /// - Mode 1: `expected_pms_hash = None`
    /// - Mode 2: `expected_pms_hash = Some(pms_hash(Zp))` — **required**,
    ///   passing `None` for a Mode 2 proof will return `Err(CoSnarkError::Verify)`.
    pub fn verify(
        &self,
        proof: &HspProof,
        expected_pms_hash: Option<Fr>,
    ) -> Result<(), CoSnarkError> {
        co_snark_verify(&self.crs.pvk, proof, expected_pms_hash)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls12_hmac::{split_mac_key, MacKey};
    use rand::rngs::OsRng;

    fn setup() -> CoSnarkBackend {
        CoSnarkBackend::setup().expect("CoSNARK setup must succeed")
    }

    /// Fast check: does constrained HMAC produce the same bytes as native HMAC?
    #[test]
    fn constrained_hmac_matches_native() {
        use ark_relations::r1cs::ConstraintSystem;
        use ark_r1cs_std::{alloc::AllocVar, bits::uint8::UInt8};
        use crate::hmac_sha256_gadget::{hmac_sha256_gadget, hmac_sha256_gadget_constrained};

        let key  = vec![0x22u8; 48];
        let data = b"test data for hmac".to_vec();
        let cs   = ConstraintSystem::<ark_bn254::Fr>::new_ref();

        // Native HMAC.
        let native_out = hmac_sha256_gadget(cs.clone(), &key, &data)
            .expect("native HMAC must succeed");

        // Constrained HMAC with constant vars (same values as native).
        let key_vars: Vec<UInt8<ark_bn254::Fr>> = key.iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let data_vars: Vec<UInt8<ark_bn254::Fr>> = data.iter()
            .map(|&b| UInt8::constant(b))
            .collect();
        let constrained_out = hmac_sha256_gadget_constrained(cs.clone(), &key_vars, &data_vars)
            .expect("constrained HMAC must succeed");

        // Extract native values from constrained output.
        use ark_r1cs_std::R1CSVar;
        let constrained_bytes: Vec<u8> = constrained_out.iter()
            .map(|b| b.value().unwrap())
            .collect();

        assert_eq!(
            native_out.to_vec(), constrained_bytes,
            "constrained HMAC must match native HMAC"
        );
        println!("HMAC constraint count: {}", cs.num_constraints());
    }

    /// Fast check: is the Mode 2 circuit satisfiable (no Groth16)?
    #[test]
    fn mode2_circuit_is_satisfiable() {
        use ark_relations::r1cs::ConstraintSystem;
        use crate::hmac_sha256_gadget::{tls12_master_secret_gadget, tls12_key_expansion_gadget};
        use crate::tls_prf_circuit::TlsPrfCircuit;

        let pms = vec![0x22u8; 48];
        let cr  = [0x01u8; 32];
        let sr  = [0x02u8; 32];

        // Derive K_MAC natively.
        let tmp_cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        let ms = tls12_master_secret_gadget(tmp_cs.clone(), &pms, &cr, &sr)
            .expect("native master secret");
        let km = tls12_key_expansion_gadget(tmp_cs, &ms, &cr, &sr)
            .expect("native key expansion");
        let k_mac = MacKey(km.client_write_mac_key);
        let (p, v) = split_mac_key(&k_mac, &mut OsRng);
        let rand_binding = [0x77u8; 32];

        // Build Mode 2 circuit with consistent witnesses.
        let circuit = TlsPrfCircuit::with_tls_prf(
            p.0, v.0, &rand_binding, pms.to_vec(), cr, sr,
        );
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        use ark_relations::r1cs::ConstraintSynthesizer;
        circuit.generate_constraints(cs.clone())
            .expect("constraint generation must succeed");

        println!("Mode 2 constraint count: {}", cs.num_constraints());
        assert!(
            cs.is_satisfied().expect("satisfiability check"),
            "Mode 2 circuit must be satisfiable with consistent witnesses"
        );
    }

    #[test]
    fn co_snark_round_trip() {
        let backend = setup();

        let k_mac = MacKey([0x42u8; 32]);
        let (p_share, v_share) = split_mac_key(&k_mac, &mut OsRng);
        let rand_binding = [0x11u8; 32];

        let proof = backend.execute(&p_share, &v_share, &rand_binding).unwrap();
        backend.verify(&proof, None).unwrap();

        assert_eq!(proof.k_mac, k_mac.0, "K_MAC must match after co-SNARK");
        println!("co-SNARK proof size: {} bytes", proof.groth16_bytes.len());
    }

    #[test]
    fn co_snark_wrong_share_fails_verify() {
        let backend = setup();

        let k_mac = MacKey([0x42u8; 32]);
        let (p_share, v_share) = split_mac_key(&k_mac, &mut OsRng);
        let rand_binding = [0x11u8; 32];

        let mut proof = backend.execute(&p_share, &v_share, &rand_binding).unwrap();

        // Tamper with K_MAC.
        proof.k_mac[0] ^= 0xFF;

        let result = backend.verify(&proof, None);
        assert!(result.is_err(), "Tampered K_MAC must fail verify");
    }

    #[test]
    fn co_snark_different_shares_same_k_mac() {
        let backend = setup();
        let k_mac = MacKey([0xABu8; 32]);
        let rand_binding = [0xCDu8; 32];

        // Two different splits of the same K_MAC should both verify.
        let (p1, v1) = split_mac_key(&k_mac, &mut OsRng);
        let (p2, v2) = split_mac_key(&k_mac, &mut OsRng);

        let pf1 = backend.execute(&p1, &v1, &rand_binding).unwrap();
        let pf2 = backend.execute(&p2, &v2, &rand_binding).unwrap();

        backend.verify(&pf1, None).unwrap();
        backend.verify(&pf2, None).unwrap();

        assert_eq!(pf1.k_mac, pf2.k_mac, "Both proofs must encode the same K_MAC");
    }

    #[test]
    fn co_snark_mode1_rejects_none_pms_on_mode2_proof() {
        // A Mode 2 proof requires consistent K_MAC + PMS: the circuit enforces
        //   K^P_MAC ⊕ K^V_MAC  ==  TLS-PRF(PMS, ...)[0..32]
        // So we derive K_MAC from PMS via native gadget before splitting.
        use crate::hmac_sha256_gadget::{tls12_master_secret_gadget, tls12_key_expansion_gadget};
        use ark_relations::r1cs::ConstraintSystem;

        let pms: Vec<u8> = vec![0x22u8; 48];
        let cr  = [0x01u8; 32];
        let sr  = [0x02u8; 32];

        // Derive K_MAC natively (unconstrained gadgets — only the byte output matters here).
        let tmp_cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        let ms = tls12_master_secret_gadget(tmp_cs.clone(), &pms, &cr, &sr)
            .expect("native master secret derivation");
        let km = tls12_key_expansion_gadget(tmp_cs, &ms, &cr, &sr)
            .expect("native key expansion");
        let k_mac = MacKey(km.client_write_mac_key);
        let (p, v) = split_mac_key(&k_mac, &mut OsRng);
        let rand_binding = [0x77u8; 32];

        let backend_m1 = CoSnarkBackend::setup().unwrap();
        let backend_m2 = CoSnarkBackend::setup_mode2().unwrap();

        // Produce a Mode 2 proof with consistent K_MAC + PMS witnesses.
        let proof_m2 = backend_m2
            .execute_mode2(&p, &v, &rand_binding, &pms, &cr, &sr)
            .expect("Mode 2 execute must succeed");

        assert!(!proof_m2.pms_hash_bytes.is_empty(), "Mode 2 proof must carry pms_hash");

        // Verifying Mode 2 proof with None must fail — Zp binding bypass rejected.
        let res_none = backend_m2.verify(&proof_m2, None);
        assert!(res_none.is_err(), "Mode 2 proof must not verify with expected_pms_hash=None");

        // Verifying Mode 2 proof with correct expected_pms_hash must succeed.
        use crate::tls_prf_circuit::pms_hash;
        let expected_fe = pms_hash(&pms);
        backend_m2
            .verify(&proof_m2, Some(expected_fe))
            .expect("Mode 2 verify with correct pms_hash must succeed");

        // Verifying Mode 2 proof with WRONG pms_hash must fail.
        let wrong_fe = pms_hash(&vec![0xFFu8; 48]);
        assert!(
            backend_m2.verify(&proof_m2, Some(wrong_fe)).is_err(),
            "Mode 2 proof must fail with wrong pms_hash"
        );

        // Mode 1 proof verified with Some(pms_hash) must fail (no pms_hash in proof).
        let proof_m1 = backend_m1
            .execute(&p, &v, &rand_binding)
            .expect("Mode 1 execute must succeed");
        assert!(
            backend_m1.verify(&proof_m1, Some(expected_fe)).is_err(),
            "Mode 1 proof must fail when pms_hash expected"
        );
    }
}