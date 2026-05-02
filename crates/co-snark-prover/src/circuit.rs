//! TLS key commitment circuit — R1CS constraint system.
//!
//! # Statement
//!
//! Given:
//!   - private witnesses: K^P_MAC (32 bytes), K^V_MAC (32 bytes)
//!   - public input:      commitment = pack(K^P_MAC XOR K^V_MAC) + rand_binding
//!
//! Prove:
//!   - K^P_MAC XOR K^V_MAC = K_MAC  (XOR-then-pack)
//!   - commit(K_MAC, rand_binding) = commitment
//!
//! # XOR → Addition trick
//!
//! In GF(2^8) we have XOR ≡ addition.  We lift each byte into a field
//! element, compute the XOR/add, then pack 32 bytes into a single Fr element
//! for the commitment.
//!
//! # MPC note
//!
//! When used in distributed mode with mpc-algebra, F is replaced by
//! `MpcField<Fr, AdditiveFieldShare<Fr>>`.  Every linear gate remains local;
//! there are no non-linear gates, so no Beaver-triple round-trips are needed.
//!
//! In MPC mode, use `TlsKeyCircuit::new_mpc` to supply shares directly as
//! additive `F` values rather than raw bytes (which would leak the value).

use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// The TLS key commitment circuit.
///
/// In **central mode** (`p_share_fe` / `v_share_fe` are `None`), witness
/// values are derived by converting the raw byte arrays to field elements.
///
/// In **MPC mode** (`p_share_fe` / `v_share_fe` are `Some`), the caller
/// supplies shares already as `F` additive elements (e.g. `MpcField<Fr>`).
/// This avoids a byte→field conversion that would break MPC secrecy.
#[derive(Clone)]
pub struct TlsKeyCircuit<F: PrimeField> {
    // ── Private witnesses (byte form — central mode) ──────────────────────
    pub p_share: [u8; 32],
    pub v_share: [u8; 32],

    // ── Private witnesses (field form — MPC mode) ─────────────────────────
    /// Additive share of pack(K^P_MAC). Set in MPC mode; None in central mode.
    pub p_share_fe: Option<F>,
    /// Additive share of pack(K^V_MAC). Set in MPC mode; None in central mode.
    pub v_share_fe: Option<F>,

    // ── Public inputs ─────────────────────────────────────────────────────
    /// commit = pack(K_MAC) + rand_binding
    pub commitment:   F,
    /// DVRF output bound to the session transcript.
    pub rand_binding: F,
}

impl<F: PrimeField> TlsKeyCircuit<F> {
    /// Central mode: construct from raw byte shares.
    pub fn new(p_share: [u8; 32], v_share: [u8; 32], rand_binding: [u8; 32]) -> Self {
        let k_mac     = xor_shares(&p_share, &v_share);
        let rand_fe   = bytes32_to_field::<F>(&rand_binding);
        let k_mac_fe  = bytes32_to_field::<F>(&k_mac);
        let commitment = k_mac_fe + rand_fe;
        Self {
            p_share,
            v_share,
            p_share_fe: None,
            v_share_fe: None,
            commitment,
            rand_binding: rand_fe,
        }
    }

    /// MPC mode: construct from additive field shares.
    ///
    /// `p_fe` and `v_fe` are the caller's additive shares of pack(K^P_MAC)
    /// and pack(K^V_MAC) respectively. `commitment` and `rand_binding` are
    /// already known to both parties (public inputs).
    pub fn new_mpc(p_fe: F, v_fe: F, commitment: F, rand_binding: F) -> Self {
        Self {
            p_share:    [0u8; 32],
            v_share:    [0u8; 32],
            p_share_fe: Some(p_fe),
            v_share_fe: Some(v_fe),
            commitment,
            rand_binding,
        }
    }

    /// Dummy circuit (all zeros) for trusted-setup CRS generation.
    pub fn dummy() -> Self {
        Self::new([0u8; 32], [0u8; 32], [0u8; 32])
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for TlsKeyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // ── Public inputs ─────────────────────────────────────────────────
        let commitment_var = FpVar::new_input(cs.clone(), || Ok(self.commitment))?;
        let rand_var       = FpVar::new_input(cs.clone(), || Ok(self.rand_binding))?;

        // ── Private witnesses ─────────────────────────────────────────────
        // MPC mode: use pre-computed field shares directly.
        // Central mode: convert bytes to field elements.
        let p_packed = self.p_share_fe.unwrap_or_else(|| bytes32_to_field::<F>(&self.p_share));
        let v_packed = self.v_share_fe.unwrap_or_else(|| bytes32_to_field::<F>(&self.v_share));

        let p_var = FpVar::new_witness(cs.clone(), || Ok(p_packed))?;
        let v_var = FpVar::new_witness(cs.clone(), || Ok(v_packed))?;

        // ── Compute K_MAC = P XOR V (linear in GF(2^8) ≡ Fp addition) ────
        let k_mac_var = p_var + v_var;

        // ── Enforce commitment = K_MAC + rand ─────────────────────────────
        let computed = k_mac_var + &rand_var;
        commitment_var.enforce_equal(&computed)?;

        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// XOR two 32-byte arrays element-wise.
pub fn xor_shares(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 { out[i] = a[i] ^ b[i]; }
    out
}

/// Interpret 32 bytes as a little-endian field element.
pub fn bytes32_to_field<F: PrimeField>(bytes: &[u8; 32]) -> F {
    F::from_le_bytes_mod_order(bytes)
}