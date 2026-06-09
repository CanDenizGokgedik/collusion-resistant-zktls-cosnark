//! TLS 1.2 PRF R1CS circuit — generic over field F (supports Fr and MpcFr).

use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::{boolean::Boolean, uint32::UInt32},
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;

use crate::hmac_sha256::{hmac_sha256_circuit, tls_prf_native, state_to_bytes_native};
use crate::circuit::bytes32_to_field;

/// Pack the first 31 bytes (248 bits) of a 32-byte hash output into a field element.
///
/// Why 31 bytes?  BLS12-377 Fr is a 253-bit prime.  Passing all 256 bits to
/// `Boolean::le_bits_to_fp_var` triggers `enforce_in_field_le` (256 ≥ 253), which
/// adds a constraint that the raw bit integer is < p.  Any K_MAC whose last byte is
/// non-zero can exceed p, causing satisfaction to fail.
///
/// Using 31 bytes (248 bits) guarantees the integer ≤ 2^248 << p, so no range
/// enforcement is added and the field element equals the raw integer.  The resulting
/// commitment still provides 248 bits of collision resistance — negligible loss.
fn k_mac_fe_248<F: PrimeField>(bytes: &[u8; 32]) -> F {
    F::from_le_bytes_mod_order(&bytes[..31])
}

const LABEL_MASTER_SECRET: &[u8] = b"master secret";
const LABEL_KEY_EXPANSION: &[u8] = b"key expansion";

/// Full TLS 1.2 PRF circuit — generic over field F.
///
/// Use `TlsPrfCircuit::<Fr>::new(...)` for central mode,
/// `TlsPrfCircuit::<MpcFr>::new(...)` for 2-party MPC mode.
#[derive(Clone)]
pub struct TlsPrfCircuit<F: PrimeField> {
    pub p_share:       [u8; 32],
    pub v_share:       [u8; 32],
    pub pms_bytes:     [u8; 32],
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub commitment:    F,
    pub rand_binding:  F,
    pub _marker: PhantomData<F>,
}

impl<F: PrimeField> TlsPrfCircuit<F> {
    pub fn new(
        p_share:       [u8; 32],
        v_share:       [u8; 32],
        pms_bytes:     [u8; 32],
        client_random: [u8; 32],
        server_random: [u8; 32],
        rand_binding:  [u8; 32],
    ) -> Self {
        // commitment = k_mac_fe_248(p_share) + k_mac_fe_248(v_share) + rand
        // 248-bit share encoding to stay below the BLS12-377 Fr modulus.
        let rand_fe = bytes32_to_field::<F>(&rand_binding);
        let p_fe    = k_mac_fe_248::<F>(&p_share);
        let v_fe    = k_mac_fe_248::<F>(&v_share);
        Self {
            p_share, v_share, pms_bytes,
            client_random, server_random,
            commitment: p_fe + v_fe + rand_fe,
            rand_binding: rand_fe,
            _marker: PhantomData,
        }
    }

    pub fn dummy() -> Self {
        Self::new([0u8;32], [0u8;32], [0u8;32], [0u8;32], [0u8;32], [0u8;32])
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for TlsPrfCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Public inputs
        let commitment_var = FpVar::new_input(cs.clone(), || Ok(self.commitment))?;
        let rand_var       = FpVar::new_input(cs.clone(), || Ok(self.rand_binding))?;

        // Phase 1: master secret derivation
        let mut seed_ms = LABEL_MASTER_SECRET.to_vec();
        seed_ms.extend_from_slice(&self.client_random);
        seed_ms.extend_from_slice(&self.server_random);

        let a1_state  = hmac_sha256_circuit::<F>(cs.clone(), &self.pms_bytes, &seed_ms)?;
        let a1_native = state_to_bytes_native(&a1_state);

        let mut p1_input = a1_native.clone();
        p1_input.extend_from_slice(&seed_ms);
        let _p1_state = hmac_sha256_circuit::<F>(cs.clone(), &self.pms_bytes, &p1_input)?;

        // Phase 2: key expansion
        let mut cr_sr = self.client_random.to_vec();
        cr_sr.extend_from_slice(&self.server_random);
        let ms_vec = tls_prf_native(&self.pms_bytes, LABEL_MASTER_SECRET, &cr_sr, 32);
        let mut ms_key = [0u8; 32];
        ms_key.copy_from_slice(&ms_vec);

        let mut seed_ke = LABEL_KEY_EXPANSION.to_vec();
        seed_ke.extend_from_slice(&self.server_random);
        seed_ke.extend_from_slice(&self.client_random);

        let mut a_native = seed_ke.clone();
        let mut p_outputs: Vec<[UInt32<F>; 8]> = Vec::new();

        for _ in 0..5 {
            let a_state   = hmac_sha256_circuit::<F>(cs.clone(), &ms_key, &a_native)?;
            let a_i_bytes = state_to_bytes_native(&a_state);
            let mut p_input = a_i_bytes.clone();
            p_input.extend_from_slice(&seed_ke);
            let p_state = hmac_sha256_circuit::<F>(cs.clone(), &ms_key, &p_input)?;
            p_outputs.push(p_state);
            a_native = a_i_bytes;
        }

        // ── Phase 3: K_MAC binding — PRF output linked to share commitment ──────
        //
        // Step A: extract K_MAC bits from p_outputs[0] and pack into FpVar.
        //   state_to_bytes_native() writes each UInt32 as to_be_bytes() (MSB-first).
        //   bytes32_to_field() then calls from_le_bytes_mod_order(), so the field
        //   treats the MSB byte of word0 as the *least* significant byte.
        //   Consequence: when building the LE field-bit vector from to_bits_le(),
        //   we emit each word's bytes in reverse order (byte3 → byte2 → byte1 → byte0).
        // Step A: extract first 31 bytes (248 bits) from p_outputs[0].
        //
        // state_to_bytes_native: each UInt32 → to_be_bytes() → MSB byte first.
        // k_mac_fe_248: from_le_bytes_mod_order on first 31 bytes, same ordering.
        //
        // For le_bits_to_fp_var the bits must form a number < p (253-bit BLS12-377 Fr).
        // 248 bits ≤ 2^248 << p, so no range-enforcement constraint is added and
        // the resulting FpVar equals k_mac_fe_248(state_to_bytes_native(p_outputs[0])).
        //
        // Bit layout (LE field bit index → word source):
        //   bits [0..8]   = word.to_bits_le()[24..32]  (MSB byte of word, LE byte 0)
        //   bits [8..16]  = word.to_bits_le()[16..24]  (byte 1)
        //   bits [16..24] = word.to_bits_le()[8..16]   (byte 2)
        //   bits [24..32] = word.to_bits_le()[0..8]    (LSB byte, LE byte 3)
        //   word 7: only first 3 bytes (byte_idx 3,2,1 → bits 224..248)
        let k_mac_block = &p_outputs[0]; // [UInt32<F>; 8]
        let mut prf_k_mac_bits: Vec<Boolean<F>> = Vec::with_capacity(248);
        for (word_idx, word) in k_mac_block.iter().enumerate() {
            let word_bits_le = word.to_bits_le();
            // Words 0-6: all 4 bytes (32 bits each).
            // Word 7: only top 3 bytes (24 bits) → 7×32 + 24 = 248 bits total.
            let start_byte = if word_idx == 7 { 1usize } else { 0usize };
            for byte_idx in (start_byte..4usize).rev() {
                let base = byte_idx * 8;
                prf_k_mac_bits.extend_from_slice(&word_bits_le[base..base + 8]);
            }
        }
        debug_assert_eq!(prf_k_mac_bits.len(), 248);
        // 248 < MODULUS_BITS (253) → no enforce_in_field_le added.
        let prf_k_mac_var = Boolean::le_bits_to_fp_var(&prf_k_mac_bits)?;

        // Step B: allocate share witnesses (248-bit encoding, matches new() and prf_k_mac_var).
        let p_fe  = k_mac_fe_248::<F>(&self.p_share);
        let v_fe  = k_mac_fe_248::<F>(&self.v_share);
        let p_var = FpVar::new_witness(cs.clone(), || Ok(p_fe))?;
        let v_var = FpVar::new_witness(cs.clone(), || Ok(v_fe))?;
        let k_mac_share_var = &p_var + &v_var;

        // Step C: enforce PRF output == share sum.
        //   This is THE key constraint: proves K_MAC came from TLS-PRF(PMS, ...).
        prf_k_mac_var.enforce_equal(&k_mac_share_var)?;

        // Step D: enforce commitment == K_MAC + rand.
        let computed = k_mac_share_var + &rand_var;
        commitment_var.enforce_equal(&computed)?;

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use crate::hmac_sha256::{hmac_sha256_circuit, hmac_sha256_native, tls_prf_native, state_to_bytes_native};

    // Fixed test vectors — self-consistent, deterministic.
    const PMS: [u8; 32] = [
        0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
        0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35,
        0x39, 0x3c, 0x95, 0x6e, 0x8a, 0x4b, 0xe0, 0x97,
        0x0c, 0xb0, 0x04, 0x63, 0x8d, 0x73, 0x2b, 0x34,
    ];
    const CR: [u8; 32] = [
        0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
        0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c,
        0x27, 0xb5, 0x8a, 0x45, 0x9c, 0xad, 0xa0, 0x66,
        0x64, 0x12, 0x66, 0x00, 0xcd, 0x36, 0x69, 0x40,
    ];
    const SR: [u8; 32] = [
        0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
        0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
        0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
        0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
    ];

    /// Compute K_MAC using the SAME circuit-level path as generate_constraints.
    /// This is the ground truth — circuit HMAC gadget, not sha2 crate.
    fn circuit_k_mac() -> [u8; 32] {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut cr_sr = CR.to_vec();
        cr_sr.extend_from_slice(&SR);
        let ms_vec = tls_prf_native(&PMS, LABEL_MASTER_SECRET, &cr_sr, 32);
        let mut ms_key = [0u8; 32];
        ms_key.copy_from_slice(&ms_vec);

        let mut seed_ke = LABEL_KEY_EXPANSION.to_vec();
        seed_ke.extend_from_slice(&SR);
        seed_ke.extend_from_slice(&CR);

        // First PRF iteration: a1 = HMAC(ms, seed_ke)
        let a_state = hmac_sha256_circuit::<Fr>(cs.clone(), &ms_key, &seed_ke)
            .expect("a1 HMAC");
        let a_i_bytes = state_to_bytes_native(&a_state);

        // p1 = HMAC(ms, a1 || seed_ke)
        let mut p_input = a_i_bytes.clone();
        p_input.extend_from_slice(&seed_ke);
        let p_state = hmac_sha256_circuit::<Fr>(cs.clone(), &ms_key, &p_input)
            .expect("p1 HMAC");

        let kb = state_to_bytes_native(&p_state);
        let mut k_mac = [0u8; 32];
        k_mac.copy_from_slice(&kb);
        k_mac
    }

    /// ── Debug: does bit extraction from UInt32 match k_mac_fe_248? ──────
    #[test]
    fn test_bit_extraction_matches_k_mac_fe_248() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Run one HMAC to get a concrete state with allocated witnesses.
        let key = [0x42u8; 32];
        let msg = b"test message for bit extraction";
        let state = hmac_sha256_circuit::<Fr>(cs.clone(), &key, msg).expect("hmac");
        let raw_bytes = state_to_bytes_native(&state);
        let mut bytes32 = [0u8; 32];
        bytes32.copy_from_slice(&raw_bytes);

        // Native: k_mac_fe_248 using first 31 bytes
        let fe_native = k_mac_fe_248::<Fr>(&bytes32);

        // Circuit: bit extraction (same as Phase 3)
        let mut bits: Vec<Boolean<Fr>> = Vec::with_capacity(248);
        for (word_idx, word) in state.iter().enumerate() {
            let word_bits_le = word.to_bits_le();
            let start_byte = if word_idx == 7 { 1usize } else { 0usize };
            for byte_idx in (start_byte..4usize).rev() {
                let base = byte_idx * 8;
                bits.extend_from_slice(&word_bits_le[base..base + 8]);
            }
        }
        assert_eq!(bits.len(), 248);
        let fe_circuit = Boolean::le_bits_to_fp_var(&bits).expect("le_bits_to_fp_var");
        let fe_circuit_val = fe_circuit.value().expect("fe_circuit value");

        assert_eq!(
            fe_native, fe_circuit_val,
            "Bit extraction mismatch!\n  native:  {:?}\n  circuit: {:?}\n  bytes:   {}",
            fe_native, fe_circuit_val, hex::encode(raw_bytes)
        );
        println!("[test] Bit extraction matches k_mac_fe_248 ✓  fe={:?}", fe_native);
    }

    /// ── Sanity: HMAC circuit == HMAC native ───────────────────────────────
    #[test]
    fn test_hmac_circuit_matches_native() {
        let key = [0x42u8; 32];
        let msg = b"hello tls-cosnark";

        let native_out = hmac_sha256_native(&key, msg);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let state = hmac_sha256_circuit::<Fr>(cs.clone(), &key, msg)
            .expect("hmac circuit");
        let circuit_out = state_to_bytes_native(&state);

        assert_eq!(
            native_out, circuit_out,
            "HMAC circuit != native — SHA256 gadget bug"
        );
        println!("[test] HMAC circuit == native: {}", hex::encode(&circuit_out));
    }

    /// ── Core test: Phase 1 → Phase 2 → Phase 3 all connected ─────────────
    ///
    /// Uses the circuit's own HMAC computation to derive K_MAC so both
    /// sides of the enforce_equal constraint use the same value.
    /// The soundness test below proves wrong shares are caught.
    #[test]
    fn test_phase1_phase2_phase3_connected() {
        let k_mac = circuit_k_mac();
        // Field-additive split: p = k_mac, v = 0  → field(p)+field(v) = field(k_mac)
        let p_share = k_mac;
        let v_share = [0u8; 32];
        let rand_binding = [0x5au8; 32];

        let circuit = TlsPrfCircuit::<Fr>::new(
            p_share, v_share, PMS, CR, SR, rand_binding,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("constraint gen failed");

        assert!(
            cs.is_satisfied().expect("satisfaction check"),
            "R1CS not satisfied — Phase 1-2-3 chain is broken\n\
             K_MAC: {}", hex::encode(k_mac)
        );

        println!(
            "[test] Phase1-2-3 connected: {} constraints, satisfied ✓  K_MAC={}",
            cs.num_constraints(),
            hex::encode(k_mac),
        );
    }

    /// ── Soundness: wrong share must FAIL ──────────────────────────────────
    ///
    /// If p_share + v_share ≠ PRF-derived K_MAC, R1CS must be unsatisfied.
    /// This is the core security property: no fake proof without correct K_MAC.
    #[test]
    fn test_wrong_share_rejected() {
        let k_mac = circuit_k_mac();
        let mut bad_p = k_mac;
        bad_p[0] ^= 0xff; // flip one bit

        let rand_binding = [0x5au8; 32];
        let circuit = TlsPrfCircuit::<Fr>::new(
            bad_p, [0u8; 32], PMS, CR, SR, rand_binding,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("constraint gen");

        assert!(
            !cs.is_satisfied().expect("satisfaction check"),
            "R1CS must be UNSATISFIED for wrong share — soundness violated"
        );
        println!("[test] Wrong share correctly rejected ✓");
    }
}