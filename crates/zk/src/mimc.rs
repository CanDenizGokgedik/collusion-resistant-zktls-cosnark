//! MiMC-7 hash for BN254 — native computation and R1CS circuit gadget.
//!
//! # Why MiMC-7?
//!
//! SHA-256 costs ~25 000 R1CS constraints per call, making it prohibitive in
//! Groth16.  MiMC-7 over BN254 costs **91 × 4 = 364 constraints per round**
//! (actually 3 multiplications per round: t → t² → t⁴ → t⁷ · t³ needs 4 muls,
//! so 91 rounds × 4 = 364 constraints total) and provides 128-bit security.
//!
//! # Round constants
//!
//! `MIMC_ROUNDS = 91` constants are derived deterministically as
//! `SHA-256("tls-attestation/mimc7/bn254/rc/v1" || i.to_le_bytes())` for
//! `i = 0 … 90`, then reduced modulo the BN254 scalar field order.
//!
//! # Sponge construction
//!
//! Multiple field elements are absorbed left-to-right using the
//! Miyaguchi–Preneel construction:
//!
//! ```text
//! state = 0
//! for each input x:
//!     state = MiMC_enc(key=0, msg=state + x) + state + x
//! ```
//!
//! This gives a collision-resistant hash over arbitrary-length inputs.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub const MIMC_ROUNDS: usize = 91;

// ── Round constants ────────────────────────────────────────────────────────────

/// Generate the 91 MiMC round constants for a given field.
///
/// Each constant is derived as `SHA-256(domain || i.to_le_bytes())` reduced
/// modulo the field prime — deterministic and publicly verifiable.
pub fn mimc_constants<F: PrimeField>() -> Vec<F> {
    use sha2::{Digest, Sha256};
    (0u32..MIMC_ROUNDS as u32)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"tls-attestation/mimc7/bn254/rc/v1");
            h.update(i.to_le_bytes());
            let bytes: [u8; 32] = h.finalize().into();
            // Reduce modulo field order (from_le_bytes_mod_order ignores
            // leading bits beyond the field size).
            F::from_le_bytes_mod_order(&bytes)
        })
        .collect()
}

// ── Native MiMC-7 ─────────────────────────────────────────────────────────────

/// Compute one MiMC-7 encryption: `msg^7 + key + rc` repeated for 91 rounds.
pub fn mimc7_enc<F: PrimeField>(msg: F, key: F, constants: &[F]) -> F {
    assert_eq!(constants.len(), MIMC_ROUNDS);
    let mut state = msg;
    for c in constants {
        let t = state + key + c;
        // t^7 = t^4 · t^2 · t = (t^2)^2 · t^2 · t
        let t2 = t * t;
        let t4 = t2 * t2;
        let t6 = t4 * t2;
        state = t6 * t;
    }
    state + key
}

/// MiMC-7 sponge: absorb a slice of field elements and return one digest element.
///
/// Uses the Miyaguchi–Preneel construction so the output changes if any input
/// or their ordering changes.
pub fn mimc7_sponge<F: PrimeField>(inputs: &[F], constants: &[F]) -> F {
    let mut state = F::zero();
    for &x in inputs {
        let enc = mimc7_enc(state + x, F::zero(), constants);
        state = enc + state + x;
    }
    state
}

// ── R1CS gadget ───────────────────────────────────────────────────────────────

/// Enforce one MiMC-7 encryption round in R1CS.
///
/// Each round allocates 3 intermediate variables and adds 4 constraints:
/// - w1 = t² (w1 · w1 ... no: one constraint: w1 = t · t)
/// - w2 = w1 · w1  →  t⁴
/// - w3 = w2 · t   →  t⁵  (no: w3 = t² · t = t³, then t^7 = t^4 * t^3)
/// Actually let's be precise:
/// - a = t · t          →  a = t²      [1 constraint]
/// - b = a · a          →  b = t⁴      [1 constraint]
/// - c = a · t          →  c = t³      [1 constraint]
/// - out = b · c        →  out = t⁷    [1 constraint]
/// Total: 4 constraints per round × 91 rounds = 364 constraints per hash call.
pub fn mimc7_enc_gadget<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    msg: &FpVar<F>,
    key: &FpVar<F>,
    constants: &[F],
) -> Result<FpVar<F>, SynthesisError> {
    assert_eq!(constants.len(), MIMC_ROUNDS);
    let mut state = msg.clone();
    for c in constants {
        let c_var = FpVar::new_constant(cs.clone(), *c)?;
        let t = &state + key + &c_var;
        let t2 = t.clone() * t.clone();
        let t4 = t2.clone() * t2.clone();
        let t3 = t2 * t.clone();
        let t7 = t4 * t3;
        state = t7;
    }
    Ok(state + key)
}

/// MiMC-7 sponge gadget: absorb `inputs` (private `FpVar`s) and return digest.
pub fn mimc7_sponge_gadget<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    inputs: &[FpVar<F>],
    constants: &[F],
) -> Result<FpVar<F>, SynthesisError> {
    let zero = FpVar::new_constant(cs.clone(), F::zero())?;
    let mut state = zero;
    for x in inputs {
        let sum = &state + x;
        let key = FpVar::new_constant(cs.clone(), F::zero())?;
        let enc = mimc7_enc_gadget(cs.clone(), &sum, &key, constants)?;
        state = &enc + &state + x;
    }
    Ok(state)
}

// ── Byte ↔ field-element helpers ──────────────────────────────────────────────

/// Encode a 32-byte digest as a BN254 scalar field element.
///
/// Takes the first 31 bytes (248 bits) to guarantee the value is strictly
/// less than the 254-bit field prime.  The last byte is discarded — acceptable
/// because the field has ~254 bits of entropy and we only need uniformity over
/// field elements, not byte-perfect encoding.
pub fn bytes31_to_fe<F: PrimeField>(b: &[u8; 32]) -> F {
    F::from_le_bytes_mod_order(&b[..31])
}

/// Encode a 16-byte session ID as a field element.
pub fn bytes16_to_fe<F: PrimeField>(b: &[u8; 16]) -> F {
    F::from_le_bytes_mod_order(b)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::Zero;

    #[test]
    fn round_constants_deterministic() {
        let c1: Vec<Fr> = mimc_constants();
        let c2: Vec<Fr> = mimc_constants();
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), MIMC_ROUNDS);
        // Constants should not all be zero.
        assert!(c1.iter().any(|x| !x.is_zero()));
    }

    #[test]
    fn mimc7_enc_deterministic() {
        let c = mimc_constants::<Fr>();
        let a = mimc7_enc(Fr::from(1u64), Fr::from(0u64), &c);
        let b = mimc7_enc(Fr::from(1u64), Fr::from(0u64), &c);
        assert_eq!(a, b);
    }

    #[test]
    fn mimc7_enc_different_inputs_differ() {
        let c = mimc_constants::<Fr>();
        let a = mimc7_enc(Fr::from(1u64), Fr::from(0u64), &c);
        let b = mimc7_enc(Fr::from(2u64), Fr::from(0u64), &c);
        assert_ne!(a, b);
    }

    #[test]
    fn mimc7_sponge_order_matters() {
        let c = mimc_constants::<Fr>();
        let x = Fr::from(42u64);
        let y = Fr::from(99u64);
        let h1 = mimc7_sponge(&[x, y], &c);
        let h2 = mimc7_sponge(&[y, x], &c);
        assert_ne!(h1, h2);
    }

    #[test]
    fn bytes31_to_fe_roundtrip_stable() {
        let b = [0xABu8; 32];
        let fe: Fr = bytes31_to_fe(&b);
        let b2 = [0xABu8; 32];
        let fe2: Fr = bytes31_to_fe(&b2);
        assert_eq!(fe, fe2);
    }
}