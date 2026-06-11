//! Groth16 R1CS circuit for TLS-PRF and 2PC MAC key split verification.
//!
//! # Paper reference
//!
//! Paper §VIII.C, equation (2):
//! `(K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp)`
//!
//! # What this circuit proves
//!
//! ```text
//! Private witnesses (per-party):
//!   - k_mac_prover_share: [u8; 32]   (K^P_MAC, held by Prover)
//!   - k_mac_verifier_share: [u8; 32] (K^V_MAC, held by Coordinator Verifier)
//!
//! Public inputs:
//!   - k_mac_commitment: Fr   pack(K_MAC) + rand_binding
//!   - rand_binding:     Fr   The DVRF randomness binding
//!
//! Constraints (sound):
//!   1. k_mac_bits = bits(k_mac_prover_share ⊕ k_mac_verifier_share)  [in-circuit XOR]
//!   2. packed_k_mac = Σ k_mac_bits[i] * 2^i  [in-circuit bit packing]
//!   3. packed_k_mac + rand_binding == k_mac_commitment  [enforced in R1CS]
//! ```
//!
//! # Soundness
//!
//! All three constraints are enforced within the R1CS system.  A cheating prover
//! cannot fabricate a valid proof without knowing (K^P_MAC, K^V_MAC) such that
//! their XOR packs to exactly `k_mac_commitment - rand_binding`.  The public
//! inputs `k_mac_commitment` and `rand_binding` are fixed by the verifier, so
//! the prover has no freedom.
//!
//! # Previous issue (fixed)
//!
//! The old circuit computed the commitment natively (outside R1CS) and then
//! allocated it as a **witness**, not a value derived from the XOR variables.
//! That allowed any prover to supply arbitrary share values and still pass.
//! This version derives the commitment entirely from in-circuit variables.
//!
//! # Full TLS-PRF extension
//!
//! The paper's full circuit evaluates TLS-PRF(Zp, "key expansion", CR||SR)
//! to derive K_MAC, requiring ~60 SHA-256 compression rounds → ~1,719,598 R1CS
//! constraints (paper §IX, reference [19]). This circuit implements the
//! 2PC-split correctness proof — the TLS-PRF derivation adds the `pms_fe`
//! witness and SHA-256 gadgets on top of this foundation.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, One, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use sha2::{Digest, Sha256};

// ── Helper: byte array to field element ──────────────────────────────────────

/// Pack a 32-byte array into a BN254 Fr field element (254-bit field).
///
/// Clears the top 2 bits to ensure the result fits in Fr without reduction.
/// Used for computing K_MAC commitments and DVRF randomness bindings.
pub fn bytes32_to_fr(bytes: &[u8; 32]) -> Fr {
    // `from_le_bytes_mod_order` treats bytes[0] as the LSB.
    // BN254 Fr is 254 bits, so bits 254-255 must be zero to avoid reduction.
    // Bits 254-255 are bits 6-7 of bytes[31] (the MSB in LE layout).
    // (The old code cleared bytes[0] bits 6-7, which are bits 6-7 of the
    //  *least* significant byte — wrong for LE, and inconsistent with
    //  pack_bytes_to_fpvar which skips bit_count >= 254.)
    let mut b = *bytes;
    b[31] &= 0x3F; // clear bits 254-255 (top 2 bits of LE 256-bit value)
    Fr::from_le_bytes_mod_order(&b)
}

/// Compute the K_MAC commitment as a field element.
///
/// # Formula
///
/// `k_mac_commitment(k_mac, rand_binding) = pack(K_MAC) + rand_binding_fe`
///
/// This is enforced **in-circuit** — the commitment is derived directly from
/// the XOR of the two shares' R1CS variables, not computed outside the circuit.
///
/// # Why not SHA256?
///
/// A SHA256 commitment would require ~40,000 additional R1CS constraints for
/// Mode 1 (which targets ~300 constraints total).  The field-addition approach
/// achieves the same binding property with zero additional constraints: the
/// verifier knows `rand_binding` and can compute `expected = pack(K_MAC) +
/// rand_binding_fe`, so a prover who does not know K_MAC cannot satisfy the
/// constraint.
pub fn k_mac_commitment(k_mac: &[u8; 32], rand_binding_fe: Fr) -> Fr {
    bytes32_to_fr(k_mac) + rand_binding_fe
}

// ── In-circuit bit packing ────────────────────────────────────────────────────

/// Pack `UInt8<Fr>` circuit variables into a single `FpVar<Fr>`.
///
/// Reads bit-by-bit in little-endian order, builds Σ bits[i] * 2^i.
/// Stops after 254 bits (BN254 Fr field size).
pub fn pack_bytes_to_fpvar(
    cs: ConstraintSystemRef<Fr>,
    bytes: &[UInt8<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    // Accumulate Σ bit[i] * 2^i  for the first 254 bits.
    // Each bit contributes a linear constraint via FpVar::new_variable.
    let mut result = FpVar::<Fr>::new_constant(cs.clone(), Fr::zero())?;
    let mut coeff = Fr::one();
    let mut bit_count = 0usize;

    for byte_var in bytes {
        let bits = byte_var.to_bits_le()?; // LSB first, 8 bits
        for bit in bits {
            if bit_count >= 254 {
                break;
            }
            // Convert the Boolean constraint to an FpVar:
            //   bit_fe = if bit { 1 } else { 0 }
            let bit_fe: FpVar<Fr> = FpVar::from(bit);
            let coeff_var = FpVar::<Fr>::new_constant(cs.clone(), coeff)?;
            result += bit_fe * coeff_var;
            coeff = coeff + coeff;
            bit_count += 1;
        }
    }

    Ok(result)
}

// ── TlsPrfCircuit ─────────────────────────────────────────────────────────────

/// Groth16 circuit proving 2PC MAC key split + TLS-PRF derivation.
///
/// # Paper §VIII.C, equation (2)
/// `(K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp)`
///
/// # Circuit modes
///
/// **Mode 1 — K_MAC split only** (pre_master_secret = None, ~300 constraints):
///   Proves K_MAC = K^P_MAC ⊕ K^V_MAC and pack(K_MAC) + rand = k_mac_commitment.
///
/// **Mode 2 — Full TLS-PRF + Zp binding** (pre_master_secret = Some(Zp), ~1.8M constraints):
///   Proves K_MAC = TLS-PRF(Zp, "key expansion", CR||SR)[0..32]
///   AND K_MAC = K^P_MAC ⊕ K^V_MAC AND pack(K_MAC) + rand = k_mac_commitment
///   AND SHA256(Zp) == pms_hash_fe  (Zp binding — auxiliary verifiers supply this).
///   This is the paper's target circuit (§IX, reference [19]).
///
/// # Public inputs (Mode 1)
///   - `k_mac_commitment_fe`: pack(K_MAC) + rand_binding_fe
///   - `rand_binding_fe`:     DVRF randomness binding as Fr
///
/// # Public inputs (Mode 2 adds)
///   - `pms_hash_fe`:  pack(SHA256(Zp)[0..32]) — auxiliary verifiers compute
///                     this from their known Zp = DH(sv, ys) and supply it.
///
/// # Private witnesses
///   - `k_mac_prover_share`:   K^P_MAC  [prover's share]
///   - `k_mac_verifier_share`: K^V_MAC  [verifier's share]
///   - `pre_master_secret`:    Zp (optional, 48 bytes, enables TLS-PRF path)
///   - `client_random`:        CR (32 bytes, for TLS-PRF)
///   - `server_random`:        SR (32 bytes, for TLS-PRF)
#[derive(Clone)]
pub struct TlsPrfCircuit {
    // ── Public inputs (Mode 1 + Mode 2) ───────────────────────────────────
    pub k_mac_commitment_fe: Fr,
    pub rand_binding_fe:     Fr,

    // ── Public input (Mode 2 only) — Zp binding ───────────────────────────
    /// pack(SHA256(Zp)[0..32]) as Fr.  Auxiliary verifiers compute this from
    /// Zp = DH(sv, ys) and supply it as the expected hash of the PMS witness.
    /// `None` in Mode 1 (no TLS-PRF constraint).
    pub pms_hash_fe: Option<Fr>,

    // ── Private witnesses (Prover's share) ────────────────────────────────
    pub k_mac_prover_share: [u8; 32],

    // ── Private witnesses (Verifier's share) ──────────────────────────────
    pub k_mac_verifier_share: [u8; 32],

    // ── Optional: Full TLS-PRF witnesses (Mode 2) ─────────────────────────
    /// Pre-master secret Zp (48 bytes). Set to Some(_) to enable full TLS-PRF.
    pub pre_master_secret: Option<Vec<u8>>,
    /// TLS ClientHello.random (32 bytes).
    pub client_random: Option<[u8; 32]>,
    /// TLS ServerHello.random (32 bytes).
    pub server_random: Option<[u8; 32]>,
}

/// Compute `pms_hash_fe = pack(SHA256(pms)[0..32])` natively.
///
/// Auxiliary verifiers call this with `Zp = DH(sv, ys)` to obtain the
/// expected value to supply as the `pms_hash_fe` public input when verifying
/// a Mode 2 HSP proof.
pub fn pms_hash(pms: &[u8]) -> Fr {
    let hash: [u8; 32] = Sha256::digest(pms).into();
    bytes32_to_fr(&hash)
}

impl TlsPrfCircuit {
    /// Mode 1: K_MAC split-only circuit (~300 constraints).
    pub fn new(
        k_mac_prover_share: [u8; 32],
        k_mac_verifier_share: [u8; 32],
        rand_binding: &[u8; 32],
    ) -> Self {
        let k_mac = Self::xor_shares(&k_mac_prover_share, &k_mac_verifier_share);
        let rand_binding_fe = bytes32_to_fr(rand_binding);
        Self {
            k_mac_commitment_fe: k_mac_commitment(&k_mac, rand_binding_fe),
            rand_binding_fe,
            pms_hash_fe: None,
            k_mac_prover_share,
            k_mac_verifier_share,
            pre_master_secret: None,
            client_random: None,
            server_random: None,
        }
    }

    /// Mode 2: Full TLS-PRF circuit + Zp binding (~1.8M constraints).
    ///
    /// Paper §IX target: `K_MAC = TLS-PRF(Zp, "key expansion", CR||SR)[0..32]`.
    /// Corresponds to reference [19] (gnark implementation, 1,719,598 R1CS).
    ///
    /// Adds a third public input `pms_hash_fe = pack(SHA256(Zp)[0..32])` so
    /// auxiliary verifiers can supply their independently computed Zp hash and
    /// verify the proof binds to the correct TLS pre-master secret.
    pub fn with_tls_prf(
        k_mac_prover_share: [u8; 32],
        k_mac_verifier_share: [u8; 32],
        rand_binding: &[u8; 32],
        pre_master_secret: Vec<u8>,
        client_random: [u8; 32],
        server_random: [u8; 32],
    ) -> Self {
        let k_mac = Self::xor_shares(&k_mac_prover_share, &k_mac_verifier_share);
        let rand_binding_fe = bytes32_to_fr(rand_binding);
        let pms_hash_fe = pms_hash(&pre_master_secret);
        Self {
            k_mac_commitment_fe: k_mac_commitment(&k_mac, rand_binding_fe),
            rand_binding_fe,
            pms_hash_fe: Some(pms_hash_fe),
            k_mac_prover_share,
            k_mac_verifier_share,
            pre_master_secret: Some(pre_master_secret),
            client_random: Some(client_random),
            server_random: Some(server_random),
        }
    }

    /// Convenience: produce a satisfying dummy circuit for trusted setup (Mode 1).
    pub fn dummy() -> Self {
        Self::new([1u8; 32], [2u8; 32], &[0u8; 32])
    }

    /// Convenience: dummy with full TLS-PRF for trusted setup (Mode 2).
    pub fn dummy_full_prf() -> Self {
        Self::with_tls_prf(
            [1u8; 32], [2u8; 32], &[0u8; 32],
            vec![0u8; 48], [0u8; 32], [0u8; 32],
        )
    }

    fn xor_shares(p: &[u8; 32], v: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 { out[i] = p[i] ^ v[i]; }
        out
    }
}

impl ConstraintSynthesizer<Fr> for TlsPrfCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Allocate public inputs (Mode 1) ───────────────────────────────
        let expected_commitment =
            FpVar::new_input(cs.clone(), || Ok(self.k_mac_commitment_fe))?;
        let rand_binding =
            FpVar::new_input(cs.clone(), || Ok(self.rand_binding_fe))?;

        // ── Allocate private witnesses ─────────────────────────────────────
        let p_vars: Vec<UInt8<Fr>> = self.k_mac_prover_share
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        let v_vars: Vec<UInt8<Fr>> = self.k_mac_verifier_share
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        // ── Core constraint 1: K_MAC = K^P_MAC ⊕ K^V_MAC  (in-circuit) ───
        let xor_vars: Vec<UInt8<Fr>> = p_vars
            .iter()
            .zip(v_vars.iter())
            .map(|(p, v)| p.xor(v))
            .collect::<Result<_, _>>()?;

        // ── Core constraint 2: pack(K_MAC) in-circuit ─────────────────────
        let packed_k_mac = pack_bytes_to_fpvar(cs.clone(), &xor_vars)?;

        // ── Core constraint 3: packed_k_mac + rand_binding == commitment ───
        let computed_commitment = packed_k_mac + rand_binding.clone();
        computed_commitment.enforce_equal(&expected_commitment)?;

        // ── Mode 2: Full TLS-PRF derivation + Zp binding (fully constrained) ─
        //
        // Uses constrained HMAC-SHA256 gadgets so every byte of the TLS-PRF
        // output is R1CS-linked to the PMS witness.  A cheating prover cannot
        // fabricate a K_MAC that satisfies both the commitment and the PRF
        // chain without knowing the actual TLS pre-master secret.
        if let (Some(pms), Some(cr), Some(sr), Some(pms_hash_fe)) = (
            &self.pre_master_secret,
            &self.client_random,
            &self.server_random,
            self.pms_hash_fe,
        ) {
            use crate::hmac_sha256_gadget::{
                tls12_master_secret_constrained, tls12_key_expansion_constrained,
            };
            use crate::sha256_gadget::sha256_from_byte_vars;

            // ── Mode 2 public input: pack(SHA256(Zp)) ─────────────────────
            let expected_pms_hash = FpVar::new_input(cs.clone(), || Ok(pms_hash_fe))?;

            // Allocate the PMS bytes as constrained private witnesses.
            let pms_vars: Vec<UInt8<Fr>> = pms
                .iter()
                .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
                .collect::<Result<_, _>>()?;

            // SHA256(pms_witness) in-circuit — fully constrained.
            let pms_hash_byte_vars = sha256_from_byte_vars(cs.clone(), &pms_vars)?;
            let packed_pms_hash = pack_bytes_to_fpvar(cs.clone(), &pms_hash_byte_vars)?;
            packed_pms_hash.enforce_equal(&expected_pms_hash)?;

            // ── TLS-PRF K_MAC derivation — fully constrained R1CS chain ────
            //
            // Every HMAC in the chain uses constrained input variables.
            // The pms_vars witness flows through:
            //   pms_vars → master_secret_vars (constrained HMAC) →
            //   key_block_vars (constrained HMAC) → K_MAC bytes
            //
            // Constraint count: ~12-16 HMAC calls × 74,832 ≈ ~900K-1.2M constraints.
            let ms_vars = tls12_master_secret_constrained(cs.clone(), &pms_vars, cr, sr)?;
            let key_block_vars = tls12_key_expansion_constrained(cs.clone(), &ms_vars, cr, sr)?;

            // K^P_MAC = first 32 bytes of key_block (client_write_mac_key).
            // These are already constrained — no new_witness allocation needed.
            let derived_k_mac_vars = &key_block_vars[0..32];

            // Bind constrained K_MAC to the same commitment as the 2PC split.
            // This enforces: K_MAC_from_TLS_PRF == K^P_MAC ⊕ K^V_MAC (via
            // the shared commitment equation with rand_binding).
            let packed_derived = pack_bytes_to_fpvar(cs.clone(), derived_k_mac_vars)?;
            let derived_commitment = packed_derived + rand_binding;
            derived_commitment.enforce_equal(&expected_commitment)?;
        }

        Ok(())
    }
}

// ── PgpBindingCircuit ─────────────────────────────────────────────────────────

/// Groth16 circuit for the PGP phase transcript binding.
///
/// # Paper §V — PGP(x, w) → π_pgp
///
/// ```text
/// private x = (Q, R, θs)
/// public  w = (Q̂, R̂, spv, b)
/// ```
///
/// This circuit implements a practical approximation of the paper's full ZKP
/// for the proof generation phase.  Rather than proving arbitrary TLS decryption
/// (which would require AES-GCM or HMAC-SHA256 gadgets over Q, R bytes), the
/// circuit proves that:
///
///   (a) The prover knows 32-byte commitment digests `query_hash` and
///       `response_hash` that open the stated public commitments.
///   (b) SHA256(query_hash || response_hash) in-circuit equals the stated
///       `transcript_commitment`.
///
/// This is always a single 64-byte SHA256 block → ~37,416 constraints.
///
/// The proof prevents cross-session transcript substitution: an adversary
/// cannot reuse a (query_hash, response_hash) pair from a different session
/// because the `rand_binding` in each commitment is session-specific (derived
/// from the DVRF output in HSP).
///
/// # Public inputs
///   - `query_commitment_fe`:      pack(query_hash) + rand_binding
///   - `response_commitment_fe`:   pack(response_hash) + rand_binding
///   - `transcript_commitment_fe`: pack(SHA256(query_hash || response_hash)[0..32]) + rand_binding
///   - `rand_binding_fe`:          DVRF randomness binding (same as in HSP proof)
///
/// # Private witnesses
///   - `query_hash`:    32-byte commitment to the TLS query
///   - `response_hash`: 32-byte commitment to the TLS response
#[derive(Clone)]
pub struct PgpBindingCircuit {
    // ── Public inputs ──────────────────────────────────────────────────────
    pub query_commitment_fe:      Fr,
    pub response_commitment_fe:   Fr,
    pub transcript_commitment_fe: Fr,
    pub rand_binding_fe:          Fr,

    // ── Private witnesses ──────────────────────────────────────────────────
    pub query_hash:    [u8; 32],
    pub response_hash: [u8; 32],
}

/// Compute `transcript_commitment_fe` from the two 32-byte hashes.
///
/// `transcript_commitment = pack(SHA256(query_hash || response_hash)[0..32]) + rand_binding_fe`
pub fn pgp_transcript_commitment(
    query_hash:    &[u8; 32],
    response_hash: &[u8; 32],
    rand_binding_fe: Fr,
) -> Fr {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(query_hash);
    h.update(response_hash);
    let digest: [u8; 32] = h.finalize().into();
    bytes32_to_fr(&digest) + rand_binding_fe
}

impl PgpBindingCircuit {
    /// Create a new PgpBindingCircuit with the given witnesses.
    pub fn new(
        query_hash:      [u8; 32],
        response_hash:   [u8; 32],
        rand_binding:    &[u8; 32],
    ) -> Self {
        let rand_binding_fe        = bytes32_to_fr(rand_binding);
        let query_commitment_fe    = bytes32_to_fr(&query_hash) + rand_binding_fe;
        let response_commitment_fe = bytes32_to_fr(&response_hash) + rand_binding_fe;
        let transcript_commitment_fe =
            pgp_transcript_commitment(&query_hash, &response_hash, rand_binding_fe);
        Self {
            query_commitment_fe,
            response_commitment_fe,
            transcript_commitment_fe,
            rand_binding_fe,
            query_hash,
            response_hash,
        }
    }

    /// Dummy circuit for trusted setup.
    pub fn dummy() -> Self {
        Self::new([1u8; 32], [2u8; 32], &[0u8; 32])
    }
}

impl ConstraintSynthesizer<Fr> for PgpBindingCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use crate::sha256_gadget::sha256_from_byte_vars;

        // ── Public inputs ─────────────────────────────────────────────────
        let exp_query_commit      = FpVar::new_input(cs.clone(), || Ok(self.query_commitment_fe))?;
        let exp_response_commit   = FpVar::new_input(cs.clone(), || Ok(self.response_commitment_fe))?;
        let exp_transcript_commit = FpVar::new_input(cs.clone(), || Ok(self.transcript_commitment_fe))?;
        let rand_binding          = FpVar::new_input(cs.clone(), || Ok(self.rand_binding_fe))?;

        // ── Private witnesses ─────────────────────────────────────────────
        let qh_vars: Vec<UInt8<Fr>> = self.query_hash
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        let rh_vars: Vec<UInt8<Fr>> = self.response_hash
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        // ── Constraint 1: pack(query_hash) + rand == query_commitment ─────
        let packed_qh = pack_bytes_to_fpvar(cs.clone(), &qh_vars)?;
        (packed_qh + rand_binding.clone()).enforce_equal(&exp_query_commit)?;

        // ── Constraint 2: pack(response_hash) + rand == response_commitment
        let packed_rh = pack_bytes_to_fpvar(cs.clone(), &rh_vars)?;
        (packed_rh + rand_binding.clone()).enforce_equal(&exp_response_commit)?;

        // ── Constraint 3: SHA256(query_hash || response_hash) in-circuit ──
        //
        // Concatenate the 64 witness bytes (always one SHA256 block).
        let mut combined = qh_vars;
        combined.extend(rh_vars);

        let digest_vars = sha256_from_byte_vars(cs.clone(), &combined)?;

        // Pack first 32 output bytes (SHA256 always produces 32 bytes).
        let packed_digest = pack_bytes_to_fpvar(cs.clone(), &digest_vars)?;
        (packed_digest + rand_binding).enforce_equal(&exp_transcript_commit)?;

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn circuit_is_satisfiable() {
        let circuit = TlsPrfCircuit::new([0x11u8; 32], [0x22u8; 32], &[0x33u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "circuit must be satisfiable with valid witnesses");
        println!("TlsPrfCircuit Mode 1 constraints: {}", cs.num_constraints());
    }

    #[test]
    fn dummy_circuit_satisfiable() {
        let circuit = TlsPrfCircuit::dummy();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn k_mac_commitment_deterministic() {
        let k_mac = [0xDEu8; 32];
        let rand = bytes32_to_fr(&[0x42u8; 32]);
        let c1 = k_mac_commitment(&k_mac, rand);
        let c2 = k_mac_commitment(&k_mac, rand);
        assert_eq!(c1, c2);
    }

    #[test]
    fn commitment_binds_to_rand() {
        let k_mac = [0x11u8; 32];
        let r1 = bytes32_to_fr(&[0x01u8; 32]);
        let r2 = bytes32_to_fr(&[0x02u8; 32]);
        assert_ne!(k_mac_commitment(&k_mac, r1), k_mac_commitment(&k_mac, r2),
            "different rand values must produce different commitments");
    }

    #[test]
    fn commitment_binds_to_k_mac() {
        let k1 = [0x11u8; 32];
        let k2 = [0x22u8; 32];
        let rand = bytes32_to_fr(&[0x42u8; 32]);
        assert_ne!(k_mac_commitment(&k1, rand), k_mac_commitment(&k2, rand),
            "different K_MACs must produce different commitments");
    }

    #[test]
    fn circuit_rejects_wrong_commitment() {
        // Build a circuit with the correct witnesses but a tampered expected commitment.
        let circuit = TlsPrfCircuit::new([0x11u8; 32], [0x22u8; 32], &[0x33u8; 32]);
        // Tamper: change the public input commitment to the wrong value.
        let tampered = TlsPrfCircuit {
            k_mac_commitment_fe: bytes32_to_fr(&[0xFFu8; 32]),
            ..circuit
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        tampered.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(),
            "circuit must be unsatisfied when commitment is tampered");
    }
}