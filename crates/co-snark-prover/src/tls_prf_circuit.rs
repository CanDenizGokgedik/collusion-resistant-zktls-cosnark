//! TLS 1.2 PRF R1CS circuit — generic over field F (supports Fr and MpcFr).

use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::{uint32::UInt32, ToBitsGadget},
    fields::fp::FpVar,
    prelude::{AllocVar, AllocationMode, EqGadget},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;

use crate::hmac_sha256::{hmac_sha256_circuit, hmac_sha256_native, tls_prf_native, state_to_bytes_native};
use crate::circuit::bytes32_to_field;

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
        let k_mac    = xor32(&p_share, &v_share);
        let rand_fe  = bytes32_to_field::<F>(&rand_binding);
        let k_mac_fe = bytes32_to_field::<F>(&k_mac);
        Self {
            p_share, v_share, pms_bytes,
            client_random, server_random,
            commitment: k_mac_fe + rand_fe,
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

        // Phase 3: K_MAC binding
        let p_fe  = bytes32_to_field::<F>(&self.p_share);
        let v_fe  = bytes32_to_field::<F>(&self.v_share);
        let p_var = FpVar::new_witness(cs.clone(), || Ok(p_fe))?;
        let v_var = FpVar::new_witness(cs.clone(), || Ok(v_fe))?;
        let k_mac_var = p_var + v_var;
        let computed  = k_mac_var + &rand_var;
        commitment_var.enforce_equal(&computed)?;

        Ok(())
    }
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 { out[i] = a[i] ^ b[i]; }
    out
}