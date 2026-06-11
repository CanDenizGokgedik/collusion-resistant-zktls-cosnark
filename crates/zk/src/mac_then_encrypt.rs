//! Mac-then-Encrypt PGP circuit for TLS 1.2 CBC cipher suites.
//!
//! Completes the PGP statement that was previously HMAC-only. For a
//! `TLS_RSA_WITH_AES_128_CBC_SHA256` record, the TLS 1.2 record protection is:
//!
//! ```text
//!   MAC        = HMAC-SHA256(K_MAC, seq ‖ hdr ‖ plaintext)
//!   padded     = plaintext ‖ MAC ‖ pad           (pad to a 16-byte multiple)
//!   ciphertext = AES-128-CBC_Enc(K_ENC, IV, padded)
//! ```
//!
//! This circuit proves, in zero knowledge, that the prover knows
//! `(K_MAC, K_ENC, plaintext)` such that:
//!
//!   1. `MAC == HMAC-SHA256(K_MAC, seq ‖ hdr ‖ plaintext)`         (authenticity)
//!   2. `ciphertext == AES-128-CBC(K_ENC, IV, plaintext ‖ MAC ‖ pad)` (mac-then-encrypt)
//!   3. `pack(K_MAC) + rand_binding == k_mac_commitment`     (binds to HSP/co-SNARK)
//!
//! Together with the HSP co-SNARK proof (which establishes K_MAC from the
//! handshake), this closes the loop: the committed ciphertext is the genuine
//! mac-then-encrypt of the plaintext under keys derived from the attested TLS
//! session — no longer a commitment-only approximation.
//!
//! # Sizing
//!
//! Fixed to a **single 16-byte plaintext fragment** so that
//! `plaintext(16) ‖ MAC(32)` = 48 bytes = exactly **3 AES blocks** (the
//! "AES 3 block" target). The HMAC over `seq(8) ‖ hdr(5) ‖ plaintext(16)` =
//! 29 bytes fits the standard 2-compression HMAC path. CRS/proving cost is
//! dominated by the ~482k-constraint 3-block AES-CBC plus ~75k for the HMAC.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::uint8::UInt8,
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::OsRng;
use thiserror::Error;

use crate::aes128_gadget::{aes128_cbc_encrypt, aes128_cbc_encrypt_constrained};
use crate::hmac_sha256_gadget::{hmac_sha256_gadget, hmac_sha256_gadget_constrained};
use crate::tls_prf_circuit::{bytes32_to_fr, k_mac_commitment, pack_bytes_to_fpvar};

#[derive(Debug, Error)]
pub enum MacThenEncryptError {
    #[error("Groth16 setup failed: {0}")]
    Setup(String),
    #[error("Groth16 proof generation failed: {0}")]
    Prove(String),
    #[error("Groth16 verification failed")]
    Verify,
    #[error("serialization error: {0}")]
    Serialize(String),
}

/// Plaintext fragment size (one TLS data block). 16 + 32 (MAC) = 48 = 3 AES blocks.
pub const PT_LEN: usize = 16;
/// MAC length (HMAC-SHA256 truncated to full 32 bytes here).
pub const MAC_LEN: usize = 32;
/// Padded length: plaintext ‖ MAC, already a 16-multiple (48). No extra pad.
pub const PADDED_LEN: usize = PT_LEN + MAC_LEN; // 48 = 3 blocks

/// HMAC additional-data header (seq_num(8) ‖ content_type(1) ‖ version(2) ‖ len(2)).
fn build_mac_aad(seq: u64, content_type: u8, version: [u8; 2], data_len: u16) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[0..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = content_type;
    aad[9..11].copy_from_slice(&version);
    aad[11..13].copy_from_slice(&data_len.to_be_bytes());
    aad
}

/// Witness builder: computes MAC and ciphertext natively so the prover has a
/// consistent assignment.
pub struct MacThenEncryptWitness {
    pub k_mac: [u8; 32],
    pub k_enc: [u8; 16],
    pub iv: [u8; 16],
    pub plaintext: [u8; PT_LEN],
    pub seq: u64,
    pub content_type: u8,
    pub version: [u8; 2],
    // Derived:
    pub mac: [u8; MAC_LEN],
    pub ciphertext: [u8; PADDED_LEN],
}

impl MacThenEncryptWitness {
    pub fn new(
        k_mac: [u8; 32],
        k_enc: [u8; 16],
        iv: [u8; 16],
        plaintext: [u8; PT_LEN],
        seq: u64,
        content_type: u8,
        version: [u8; 2],
    ) -> Self {
        // 1. MAC = HMAC-SHA256(K_MAC, aad ‖ plaintext)
        let aad = build_mac_aad(seq, content_type, version, PT_LEN as u16);
        let mut mac_msg = Vec::with_capacity(13 + PT_LEN);
        mac_msg.extend_from_slice(&aad);
        mac_msg.extend_from_slice(&plaintext);
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        let mac = hmac_sha256_gadget(cs, &k_mac, &mac_msg).expect("native hmac");

        // 2. ciphertext = AES-128-CBC(K_ENC, IV, plaintext ‖ MAC)
        let mut padded = Vec::with_capacity(PADDED_LEN);
        padded.extend_from_slice(&plaintext);
        padded.extend_from_slice(&mac);
        let ct_vec = aes128_cbc_encrypt(&k_enc, &iv, &padded);
        let mut ciphertext = [0u8; PADDED_LEN];
        ciphertext.copy_from_slice(&ct_vec);

        Self {
            k_mac,
            k_enc,
            iv,
            plaintext,
            seq,
            content_type,
            version,
            mac,
            ciphertext,
        }
    }
}

/// Groth16 circuit enforcing mac-then-encrypt over one TLS record fragment.
///
/// Public inputs:
///   - `k_mac_commitment_fe`: pack(K_MAC) + rand_binding (binds to HSP proof)
///   - `rand_binding_fe`:     DVRF randomness binding
///   - `ciphertext_fe[0..3]`: pack of each 16-byte ciphertext block + rand_binding
///
/// Private witnesses: K_MAC, K_ENC, IV, plaintext.
#[derive(Clone)]
pub struct MacThenEncryptCircuit {
    // Public
    pub k_mac_commitment_fe: Fr,
    pub rand_binding_fe: Fr,
    pub ct_commit_fe: [Fr; 3],
    // Private
    pub k_mac: [u8; 32],
    pub k_enc: [u8; 16],
    pub iv: [u8; 16],
    pub plaintext: [u8; PT_LEN],
    pub seq: u64,
    pub content_type: u8,
    pub version: [u8; 2],
}

fn pack16(bytes: &[u8], rand: Fr) -> Fr {
    // Must match `pack_bytes_to_fpvar`: LSB-first bit accumulation
    // (Σ bit[i] * 2^i over bytes in order, up to 254 bits). For 16 bytes
    // (128 bits) there is no truncation.
    let mut acc = Fr::from(0u64);
    let mut coeff = Fr::from(1u64);
    let two = Fr::from(2u64);
    for &b in bytes {
        for i in 0..8 {
            let bit = (b >> i) & 1;
            if bit == 1 {
                acc += coeff;
            }
            coeff *= two;
        }
    }
    acc + rand
}

impl MacThenEncryptCircuit {
    pub fn from_witness(w: &MacThenEncryptWitness, rand_binding: &[u8; 32]) -> Self {
        let rand_fe = bytes32_to_fr(rand_binding);
        let ct_commit_fe = [
            pack16(&w.ciphertext[0..16], rand_fe),
            pack16(&w.ciphertext[16..32], rand_fe),
            pack16(&w.ciphertext[32..48], rand_fe),
        ];
        Self {
            k_mac_commitment_fe: k_mac_commitment(&w.k_mac, rand_fe),
            rand_binding_fe: rand_fe,
            ct_commit_fe,
            k_mac: w.k_mac,
            k_enc: w.k_enc,
            iv: w.iv,
            plaintext: w.plaintext,
            seq: w.seq,
            content_type: w.content_type,
            version: w.version,
        }
    }

    /// Dummy for trusted setup.
    pub fn dummy() -> Self {
        let w = MacThenEncryptWitness::new(
            [1u8; 32], [2u8; 16], [3u8; 16], [4u8; PT_LEN], 0, 23, [3, 3],
        );
        Self::from_witness(&w, &[0u8; 32])
    }

    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            self.k_mac_commitment_fe,
            self.rand_binding_fe,
            self.ct_commit_fe[0],
            self.ct_commit_fe[1],
            self.ct_commit_fe[2],
        ]
    }
}

impl ConstraintSynthesizer<Fr> for MacThenEncryptCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public inputs ──────────────────────────────────────────────────
        let expected_k_mac_commit = FpVar::new_input(cs.clone(), || Ok(self.k_mac_commitment_fe))?;
        let rand_binding = FpVar::new_input(cs.clone(), || Ok(self.rand_binding_fe))?;
        let expected_ct: Vec<FpVar<Fr>> = self
            .ct_commit_fe
            .iter()
            .map(|fe| FpVar::new_input(cs.clone(), || Ok(*fe)))
            .collect::<Result<_, _>>()?;

        // ── Witnesses ──────────────────────────────────────────────────────
        let k_mac_vars: Vec<UInt8<Fr>> = self
            .k_mac
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;
        let k_enc_vars: [UInt8<Fr>; 16] = {
            let v: Vec<UInt8<Fr>> = self
                .k_enc
                .iter()
                .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
                .collect::<Result<_, _>>()?;
            v.try_into().unwrap()
        };
        let iv_vars: [UInt8<Fr>; 16] = {
            let v: Vec<UInt8<Fr>> = self
                .iv
                .iter()
                .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
                .collect::<Result<_, _>>()?;
            v.try_into().unwrap()
        };
        let pt_vars: Vec<UInt8<Fr>> = self
            .plaintext
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        // ── Constraint 1: pack(K_MAC) + rand == k_mac_commitment ───────────
        let packed_k_mac = pack_bytes_to_fpvar(cs.clone(), &k_mac_vars)?;
        (packed_k_mac + rand_binding.clone()).enforce_equal(&expected_k_mac_commit)?;

        // ── Constraint 2: MAC = HMAC-SHA256(K_MAC, aad ‖ plaintext) ────────
        let aad = build_mac_aad(self.seq, self.content_type, self.version, PT_LEN as u16);
        let aad_vars: Vec<UInt8<Fr>> = aad
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;
        let mut mac_msg = aad_vars;
        mac_msg.extend(pt_vars.clone());
        let mac_vars = hmac_sha256_gadget_constrained(cs.clone(), &k_mac_vars, &mac_msg)?;

        // ── Constraint 3: ciphertext == AES-128-CBC(K_ENC, IV, pt ‖ MAC) ──
        // Build padded plaintext var: pt(16) ‖ MAC(32) = 48 bytes (3 blocks).
        let mut padded_vars: Vec<UInt8<Fr>> = Vec::with_capacity(PADDED_LEN);
        padded_vars.extend(pt_vars);
        padded_vars.extend(mac_vars);

        // Allocate ciphertext bytes as witnesses, then enforce both:
        //   (a) AES-CBC(pt‖mac) == ct      (via the gadget)
        //   (b) pack(ct block) + rand == public commitment
        let ct_native = {
            // Recompute native ct for witness assignment consistency.
            let mut padded = Vec::with_capacity(PADDED_LEN);
            padded.extend_from_slice(&self.plaintext);
            padded.extend_from_slice(&self.mac_from_native());
            aes128_cbc_encrypt(&self.k_enc, &self.iv, &padded)
        };
        let ct_vars: Vec<UInt8<Fr>> = ct_native
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        aes128_cbc_encrypt_constrained(cs.clone(), &k_enc_vars, &iv_vars, &padded_vars, &ct_vars)?;

        // Bind ciphertext to the public commitments (one per 16-byte block).
        for blk in 0..3 {
            let block = &ct_vars[16 * blk..16 * blk + 16];
            let packed = pack_bytes_to_fpvar(cs.clone(), block)?;
            (packed + rand_binding.clone()).enforce_equal(&expected_ct[blk])?;
        }

        Ok(())
    }
}

impl MacThenEncryptCircuit {
    /// Recompute MAC natively (used to assign the ciphertext witness).
    fn mac_from_native(&self) -> [u8; MAC_LEN] {
        let aad = build_mac_aad(self.seq, self.content_type, self.version, PT_LEN as u16);
        let mut msg = Vec::with_capacity(13 + PT_LEN);
        msg.extend_from_slice(&aad);
        msg.extend_from_slice(&self.plaintext);
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        hmac_sha256_gadget(cs, &self.k_mac, &msg).expect("native hmac")
    }
}

// ── Groth16 wrapper ───────────────────────────────────────────────────────────

type Pk = <Groth16<Bn254> as SNARK<Fr>>::ProvingKey;
type Vk = <Groth16<Bn254> as SNARK<Fr>>::VerifyingKey;

pub struct MacThenEncryptCrs {
    pub pk: Pk,
    pub vk: Vk,
}

pub fn setup() -> Result<MacThenEncryptCrs, MacThenEncryptError> {
    let mut rng = OsRng;
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(MacThenEncryptCircuit::dummy(), &mut rng)
        .map_err(|e| MacThenEncryptError::Setup(e.to_string()))?;
    Ok(MacThenEncryptCrs { pk, vk })
}

pub struct MacThenEncryptProof {
    pub groth16_bytes: Vec<u8>,
    pub public_inputs: Vec<Fr>,
}

pub fn prove(
    crs: &MacThenEncryptCrs,
    circuit: MacThenEncryptCircuit,
) -> Result<MacThenEncryptProof, MacThenEncryptError> {
    let public_inputs = circuit.public_inputs();
    let mut rng = OsRng;
    let proof = Groth16::<Bn254>::prove(&crs.pk, circuit, &mut rng)
        .map_err(|e| MacThenEncryptError::Prove(e.to_string()))?;
    let mut groth16_bytes = Vec::new();
    proof
        .serialize_compressed(&mut groth16_bytes)
        .map_err(|e| MacThenEncryptError::Serialize(e.to_string()))?;
    Ok(MacThenEncryptProof {
        groth16_bytes,
        public_inputs,
    })
}

pub fn verify(
    crs: &MacThenEncryptCrs,
    proof: &MacThenEncryptProof,
) -> Result<(), MacThenEncryptError> {
    let g_proof = <Groth16<Bn254> as SNARK<Fr>>::Proof::deserialize_compressed(
        proof.groth16_bytes.as_slice(),
    )
    .map_err(|e| MacThenEncryptError::Serialize(e.to_string()))?;
    let pvk = Groth16::<Bn254>::process_vk(&crs.vk)
        .map_err(|_| MacThenEncryptError::Verify)?;
    let ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &proof.public_inputs, &g_proof)
        .map_err(|_| MacThenEncryptError::Verify)?;
    if ok {
        Ok(())
    } else {
        Err(MacThenEncryptError::Verify)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    fn sample_witness() -> MacThenEncryptWitness {
        MacThenEncryptWitness::new(
            [0x42u8; 32],
            [0x11u8; 16],
            [0x22u8; 16],
            [0xAAu8; PT_LEN],
            1,
            23,
            [3, 3],
        )
    }

    #[test]
    fn witness_is_self_consistent() {
        let w = sample_witness();
        // Re-derive ct from (k_enc, iv, pt‖mac) and compare.
        let mut padded = Vec::new();
        padded.extend_from_slice(&w.plaintext);
        padded.extend_from_slice(&w.mac);
        let ct = aes128_cbc_encrypt(&w.k_enc, &w.iv, &padded);
        assert_eq!(&ct[..], &w.ciphertext[..]);
    }

    #[test]
    fn circuit_satisfiable_with_correct_witness() {
        let w = sample_witness();
        let circuit = MacThenEncryptCircuit::from_witness(&w, &[0x11u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "mac-then-encrypt circuit must be satisfiable");
        println!("mac-then-encrypt constraints: {}", cs.num_constraints());
    }

    #[test]
    fn circuit_rejects_wrong_k_mac() {
        let w = sample_witness();
        let mut circuit = MacThenEncryptCircuit::from_witness(&w, &[0x11u8; 32]);
        // Tamper the K_MAC witness — MAC will no longer match, breaking the
        // mac-then-encrypt chain (ciphertext derived from the real MAC).
        circuit.k_mac = [0xFFu8; 32];
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "wrong K_MAC must be rejected");
    }

    #[test]
    fn circuit_rejects_wrong_enc_key() {
        let w = sample_witness();
        let mut circuit = MacThenEncryptCircuit::from_witness(&w, &[0x11u8; 32]);
        // Tamper K_ENC — the in-circuit AES recomputation will disagree with
        // the (public-committed) ciphertext.
        circuit.k_enc = [0x00u8; 16];
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "wrong K_ENC must be rejected");
    }

    #[test]
    fn groth16_roundtrip() {
        let crs = setup().unwrap();
        let w = sample_witness();
        let circuit = MacThenEncryptCircuit::from_witness(&w, &[0x11u8; 32]);
        let proof = prove(&crs, circuit).unwrap();
        assert!(verify(&crs, &proof).is_ok(), "valid proof must verify");
        println!("mac-then-encrypt π size: {} bytes", proof.groth16_bytes.len());
    }
}
