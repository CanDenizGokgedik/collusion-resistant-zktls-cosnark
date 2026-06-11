//! Groth16 circuit for dx-DCTLS zero-knowledge proofs.
//!
//! # HSP circuit
//!
//! Proves in zero knowledge:
//!
//! ```text
//! MiMC7_sponge(session_id_fe, rand_fe, dvrf_exporter_fe,
//!              cert_hash_fe,  ht_hash_fe)
//!   == zk_binding   (public)
//! ```
//!
//! Private witnesses: `dvrf_exporter_fe`, `ht_hash_fe` (the latter bundles the
//! session nonce via the handshake transcript hash already committed in `ht_hash`).
//! Public inputs: `session_id_fe`, `rand_fe`, `cert_hash_fe`, `zk_binding`.
//!
//! # Security
//!
//! The verifier only sees the four public inputs.  The DVRF exporter value
//! (and any session-nonce-derived data inside `ht_hash`) is never revealed.

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::mimc::{mimc7_sponge_gadget, mimc_constants};

// ── HspCircuit ─────────────────────────────────────────────────────────────────

/// R1CS circuit that proves HSP commitment integrity in zero knowledge.
///
/// Public inputs (known to verifier):
///   - `session_id_fe` : session ID encoded as a field element
///   - `rand_fe`       : DVRF randomness encoded as a field element
///   - `cert_hash_fe`  : server certificate hash encoded as a field element
///   - `zk_binding`    : the MiMC-7 sponge output to verify against
///
/// Private witnesses (known only to prover):
///   - `dvrf_exporter_fe` : DVRF-derived TLS exporter value (hidden!)
///   - `ht_hash_fe`       : handshake transcript hash (hidden!)
#[derive(Clone)]
pub struct HspCircuit {
    // ── Public inputs ──
    pub session_id_fe:  Fr,
    pub rand_fe:        Fr,
    pub cert_hash_fe:   Fr,
    pub zk_binding:     Fr,

    // ── Private witnesses ──
    pub dvrf_exporter_fe: Fr,
    pub ht_hash_fe:       Fr,
}

impl ConstraintSynthesizer<Fr> for HspCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        let constants = mimc_constants::<Fr>();

        // Allocate public inputs — `new_input` variables go into the instance.
        let session_id = FpVar::new_input(cs.clone(), || Ok(self.session_id_fe))?;
        let rand       = FpVar::new_input(cs.clone(), || Ok(self.rand_fe))?;
        let cert_hash  = FpVar::new_input(cs.clone(), || Ok(self.cert_hash_fe))?;
        let binding    = FpVar::new_input(cs.clone(), || Ok(self.zk_binding))?;

        // Allocate private witnesses — `new_witness` variables are kept secret.
        let dvrf_exp  = FpVar::new_witness(cs.clone(), || Ok(self.dvrf_exporter_fe))?;
        let ht_hash   = FpVar::new_witness(cs.clone(), || Ok(self.ht_hash_fe))?;

        // Compute MiMC7_sponge in-circuit and constrain output == zk_binding.
        let inputs = [session_id, rand, dvrf_exp, cert_hash, ht_hash];
        let computed = mimc7_sponge_gadget(cs, &inputs, &constants)?;
        computed.enforce_equal(&binding)?;

        Ok(())
    }
}

// ── BindingCircuit ──────────────────────────────────────────────────────────────

/// Extended circuit that proves the full `TranscriptBinding` chain.
///
/// Public inputs:
///   - `session_id_fe`, `rand_fe`, `hsp_commitment_fe`, `qp_transcript_fe`
///   - `binding_digest` (the `TranscriptBinding::binding_digest` public output)
///
/// Private witnesses:
///   - `dvrf_exporter_fe`, `ht_hash_fe`, `statement_digest_fe`
///
/// The circuit constrains:
///   MiMC7(session_id, rand, hsp_commitment, qp_transcript, statement_digest)
///     == binding_digest
///
/// This is a simpler shape — the prover reveals HSP and QP commitments (which
/// are already on-chain) but keeps the statement digest private.
#[derive(Clone)]
pub struct BindingCircuit {
    // Public
    pub session_id_fe:    Fr,
    pub rand_fe:          Fr,
    pub hsp_commitment_fe: Fr,
    pub qp_transcript_fe: Fr,
    pub binding_digest:   Fr,

    // Private
    pub pgp_commitment_fe: Fr,
}

impl ConstraintSynthesizer<Fr> for BindingCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        let constants = mimc_constants::<Fr>();

        let session_id    = FpVar::new_input(cs.clone(), || Ok(self.session_id_fe))?;
        let rand          = FpVar::new_input(cs.clone(), || Ok(self.rand_fe))?;
        let hsp_commit    = FpVar::new_input(cs.clone(), || Ok(self.hsp_commitment_fe))?;
        let qp_transcript = FpVar::new_input(cs.clone(), || Ok(self.qp_transcript_fe))?;
        let binding       = FpVar::new_input(cs.clone(), || Ok(self.binding_digest))?;

        let pgp_commit    = FpVar::new_witness(cs.clone(), || Ok(self.pgp_commitment_fe))?;

        let inputs = [session_id, rand, hsp_commit, qp_transcript, pgp_commit];
        let computed = mimc7_sponge_gadget(cs, &inputs, &constants)?;
        computed.enforce_equal(&binding)?;

        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use crate::mimc::{bytes31_to_fe, bytes16_to_fe, mimc7_sponge};

    fn make_hsp_circuit(dvrf: &[u8; 32]) -> (HspCircuit, Fr) {
        let constants = mimc_constants::<Fr>();
        let sid    = bytes16_to_fe(&[1u8; 16]);
        let rand   = bytes31_to_fe(&[2u8; 32]);
        let cert   = bytes31_to_fe(&[3u8; 32]);
        let dvrf_fe: Fr = bytes31_to_fe(dvrf);
        let ht     = bytes31_to_fe(&[5u8; 32]);
        let binding = mimc7_sponge(&[sid, rand, dvrf_fe, cert, ht], &constants);
        let circuit = HspCircuit {
            session_id_fe:    sid,
            rand_fe:          rand,
            cert_hash_fe:     cert,
            zk_binding:       binding,
            dvrf_exporter_fe: dvrf_fe,
            ht_hash_fe:       ht,
        };
        (circuit, binding)
    }

    #[test]
    fn hsp_circuit_satisfiable() {
        let (circuit, _) = make_hsp_circuit(&[42u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "circuit should be satisfiable");
    }

    #[test]
    fn hsp_circuit_wrong_exporter_unsatisfiable() {
        let (mut circuit, binding) = make_hsp_circuit(&[42u8; 32]);
        // Swap in a different dvrf_exporter — should break the constraint.
        circuit.dvrf_exporter_fe = bytes31_to_fe(&[99u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "wrong exporter must be unsatisfiable");
        let _ = binding;
    }

    #[test]
    fn hsp_circuit_constraint_count() {
        let (circuit, _) = make_hsp_circuit(&[7u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        let n = cs.num_constraints();
        // 5 inputs × 91 rounds × 4 mults = 1820; allow some slack for sponge overhead.
        assert!(n > 0 && n < 15_000, "unexpected constraint count: {n}");
    }
}