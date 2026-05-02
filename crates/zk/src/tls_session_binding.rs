//! TLS Session Binding circuit — θs (session secret) in-circuit binding.
//!
//! # Paper reference — §V PGP Proof
//!
//! The PGP proof requires the prover to demonstrate that the query Q and
//! response R were genuinely exchanged over the TLS session authenticated by
//! the session secret θs = K_MAC:
//!
//! ```text
//! π_θs = ZKP.Prove(
//!   x = (k_mac_commitment, rand_binding, mac_commitment_q, mac_commitment_r),
//!   w = (K_MAC, tls_header_q, tls_header_r, SHA256(Q), SHA256(R), mac_q, mac_r)
//! )
//! ```
//!
//! # What this circuit proves
//!
//! 1. The prover knows a K_MAC whose commitment matches the public input:
//!    `pack(K_MAC) + rand_binding == k_mac_commitment_fe`
//!
//! 2. The prover knows TLS record headers and data hashes such that:
//!    `HMAC(K_MAC, tls_header_q || SHA256(Q)) == mac_q`
//!    `HMAC(K_MAC, tls_header_r || SHA256(R)) == mac_r`
//!
//! 3. The MACs match the committed values:
//!    `pack(mac_q) + rand_binding == mac_commitment_q_fe`
//!    `pack(mac_r) + rand_binding == mac_commitment_r_fe`
//!
//! Together, these constraints ensure that the prover holds K_MAC (the TLS
//! session secret) and that this key was used to authenticate exactly the
//! query and response bound in the PGP transcript commitment.
//!
//! # HMAC data format
//!
//! For each TLS record, the HMAC covers:
//! ```text
//! HMAC(K_MAC, seq_num[8] || content_type[1] || version[2] || data_len[2] || SHA256(data)[32])
//!                           ↑ 13-byte TLS record header            ↑ 32-byte pre-hashed data
//! ```
//!
//! The 45-byte fixed HMAC input fits in one SHA256 block (inner: 109 bytes →
//! 2 blocks; outer: 96 bytes → 2 blocks) — ~4 SHA256 compressions per record.
//!
//! # Constraint cost
//! - K_MAC commitment:        ~8 constraints
//! - Query HMAC:    4 SHA256 blocks × 37,416 = ~149,664
//! - Response HMAC: 4 SHA256 blocks × 37,416 = ~149,664
//! - MAC commitments:         ~16 constraints
//! Total:                     ~300K constraints

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{uint8::UInt8, ToBitsGadget},
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::OsRng;
use thiserror::Error;

use crate::hmac_sha256_gadget::hmac_sha256_gadget_constrained;
use crate::sha256_gadget::sha256_from_byte_vars;
use crate::tls_prf_circuit::{bytes32_to_fr, k_mac_commitment, pack_bytes_to_fpvar};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SessionBindingError {
    #[error("Groth16 setup failed: {0}")]
    Setup(String),
    #[error("Groth16 proof generation failed: {0}")]
    Prove(String),
    #[error("Groth16 verification failed")]
    Verify,
    #[error("Serialization error: {0}")]
    Serialize(String),
}

// ── TLS record header ──────────────────────────────────────────────────────────

/// TLS 1.2 record header (13 bytes) used as HMAC prefix.
///
/// TLS MAC covers: `seq_num(8) || content_type(1) || version(2) || data_len(2)`
/// This is the standard TLS 1.2 MAC "additional data" header (RFC 5246 §6.2.3.1).
#[derive(Clone, Copy, Debug)]
pub struct TlsRecordHeader {
    /// 8-byte big-endian TLS sequence number.
    pub seq_num: u64,
    /// TLS content type (20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=AppData).
    pub content_type: u8,
    /// TLS version bytes: [3, 3] for TLS 1.2.
    pub version: [u8; 2],
    /// Length of the plaintext data (before MAC/padding).
    pub data_len: u16,
}

impl TlsRecordHeader {
    /// Serialize to 13 bytes in TLS wire format.
    pub fn to_bytes(&self) -> [u8; 13] {
        let mut buf = [0u8; 13];
        buf[0..8].copy_from_slice(&self.seq_num.to_be_bytes());
        buf[8] = self.content_type;
        buf[9..11].copy_from_slice(&self.version);
        buf[11..13].copy_from_slice(&self.data_len.to_be_bytes());
        buf
    }
}

// ── Circuit ───────────────────────────────────────────────────────────────────

/// Groth16 R1CS circuit proving θs (K_MAC) authenticated the TLS query + response.
///
/// Public inputs  (x):  k_mac_commitment_fe, rand_binding_fe,
///                       mac_commitment_q_fe, mac_commitment_r_fe
/// Private witnesses (w): k_mac, header_q, header_r,
///                         query_data_hash, response_data_hash,
///                         mac_q, mac_r
#[derive(Clone)]
pub struct TlsSessionBindingCircuit {
    // ── Public inputs ──────────────────────────────────────────────────────
    /// pack(K_MAC) + rand_binding (matches HSP proof commitment).
    pub k_mac_commitment_fe: Fr,
    /// DVRF randomness binding (same rand_binding as HSP proof).
    pub rand_binding_fe: Fr,
    /// pack(mac_q) + rand_binding.
    pub mac_commitment_q_fe: Fr,
    /// pack(mac_r) + rand_binding.
    pub mac_commitment_r_fe: Fr,

    // ── Private witnesses ──────────────────────────────────────────────────
    /// TLS session secret K_MAC (θs) — 32 bytes.
    pub k_mac: [u8; 32],
    /// TLS record header for the query record.
    pub header_q: TlsRecordHeader,
    /// TLS record header for the response record.
    pub header_r: TlsRecordHeader,
    /// SHA256(query plaintext) — pre-hashed for fixed circuit size.
    pub query_data_hash: [u8; 32],
    /// SHA256(response plaintext) — pre-hashed for fixed circuit size.
    pub response_data_hash: [u8; 32],
    /// Expected TLS record MAC for the query.
    pub mac_q: [u8; 32],
    /// Expected TLS record MAC for the response.
    pub mac_r: [u8; 32],
}

impl TlsSessionBindingCircuit {
    /// Compute all public input field elements from native values.
    pub fn new(
        k_mac: [u8; 32],
        rand_binding: &[u8; 32],
        header_q: TlsRecordHeader,
        header_r: TlsRecordHeader,
        query_data_hash: [u8; 32],
        response_data_hash: [u8; 32],
        mac_q: [u8; 32],
        mac_r: [u8; 32],
    ) -> Self {
        let rand_binding_fe = bytes32_to_fr(rand_binding);
        Self {
            k_mac_commitment_fe: k_mac_commitment(&k_mac, rand_binding_fe),
            rand_binding_fe,
            mac_commitment_q_fe: bytes32_to_fr(&mac_q) + rand_binding_fe,
            mac_commitment_r_fe: bytes32_to_fr(&mac_r) + rand_binding_fe,
            k_mac,
            header_q,
            header_r,
            query_data_hash,
            response_data_hash,
            mac_q,
            mac_r,
        }
    }

    /// Dummy circuit for Groth16 trusted setup.
    pub fn dummy() -> Self {
        let dummy_header = TlsRecordHeader {
            seq_num: 0,
            content_type: 23,
            version: [3, 3],
            data_len: 32,
        };
        // Use consistent dummy MAC: HMAC([1u8;32], [0u8;13] || [0u8;32])
        let dummy_mac = {
            use crate::hmac_sha256_gadget::hmac_sha256_gadget;
            let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
            let header = dummy_header.to_bytes();
            let mut data = [0u8; 45];
            data[..13].copy_from_slice(&header);
            hmac_sha256_gadget(cs, &[1u8; 32], &data)
                .unwrap_or([0u8; 32])
        };
        Self::new(
            [1u8; 32],
            &[0u8; 32],
            dummy_header,
            dummy_header,
            [0u8; 32],
            [0u8; 32],
            dummy_mac,
            dummy_mac,
        )
    }

    /// Build the 45-byte HMAC input for one TLS record:
    /// `header(13) || data_hash(32)`
    fn hmac_input(header: &TlsRecordHeader, data_hash: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(45);
        v.extend_from_slice(&header.to_bytes());
        v.extend_from_slice(data_hash);
        v
    }
}

impl ConstraintSynthesizer<Fr> for TlsSessionBindingCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public inputs ──────────────────────────────────────────────────
        let expected_k_mac_commit =
            FpVar::new_input(cs.clone(), || Ok(self.k_mac_commitment_fe))?;
        let rand_binding = FpVar::new_input(cs.clone(), || Ok(self.rand_binding_fe))?;
        let expected_mac_commit_q =
            FpVar::new_input(cs.clone(), || Ok(self.mac_commitment_q_fe))?;
        let expected_mac_commit_r =
            FpVar::new_input(cs.clone(), || Ok(self.mac_commitment_r_fe))?;

        // ── Private witnesses: K_MAC ───────────────────────────────────────
        let k_mac_vars: Vec<UInt8<Fr>> = self
            .k_mac
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        // ── Constraint 1: pack(K_MAC) + rand_binding == k_mac_commitment ──
        let packed_k_mac = pack_bytes_to_fpvar(cs.clone(), &k_mac_vars)?;
        let computed_k_mac_commit = packed_k_mac + rand_binding.clone();
        computed_k_mac_commit.enforce_equal(&expected_k_mac_commit)?;

        // ── Private witnesses: TLS headers (constant, not secret) ─────────
        let hdr_q_bytes = self.header_q.to_bytes();
        let hdr_r_bytes = self.header_r.to_bytes();

        let hdr_q_vars: Vec<UInt8<Fr>> = hdr_q_bytes
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        let hdr_r_vars: Vec<UInt8<Fr>> = hdr_r_bytes
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        // ── Private witnesses: data hashes ────────────────────────────────
        let qdh_vars: Vec<UInt8<Fr>> = self
            .query_data_hash
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        let rdh_vars: Vec<UInt8<Fr>> = self
            .response_data_hash
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        // ── Constraint 2: HMAC(K_MAC, hdr_q || query_data_hash) == mac_q ─
        let mut hmac_input_q = hdr_q_vars;
        hmac_input_q.extend(qdh_vars);
        let computed_mac_q = hmac_sha256_gadget_constrained(
            cs.clone(),
            &k_mac_vars,
            &hmac_input_q,
        )?;
        let packed_mac_q = pack_bytes_to_fpvar(cs.clone(), &computed_mac_q)?;
        let mac_commit_q = packed_mac_q + rand_binding.clone();
        mac_commit_q.enforce_equal(&expected_mac_commit_q)?;

        // ── Constraint 3: HMAC(K_MAC, hdr_r || response_data_hash) == mac_r
        let mut hmac_input_r = hdr_r_vars;
        hmac_input_r.extend(rdh_vars);
        let computed_mac_r = hmac_sha256_gadget_constrained(
            cs.clone(),
            &k_mac_vars,
            &hmac_input_r,
        )?;
        let packed_mac_r = pack_bytes_to_fpvar(cs.clone(), &computed_mac_r)?;
        let mac_commit_r = packed_mac_r + rand_binding;
        mac_commit_r.enforce_equal(&expected_mac_commit_r)?;

        Ok(())
    }
}

// ── CRS ───────────────────────────────────────────────────────────────────────

type Pk  = <Groth16<Bn254> as SNARK<Fr>>::ProvingKey;
type Pvk = <Groth16<Bn254> as SNARK<Fr>>::ProcessedVerifyingKey;
type Pf  = <Groth16<Bn254> as SNARK<Fr>>::Proof;

pub struct SessionBindingCrs {
    pub(crate) pk:  Pk,
    pub(crate) pvk: Pvk,
}

impl SessionBindingCrs {
    /// Run Groth16 trusted setup for the TlsSessionBindingCircuit.
    ///
    /// # Security
    /// Uses `OsRng` — same τ caveats as `CoSnarkCrs::setup()`.
    /// For production, replace with an MPC ceremony.
    pub fn setup() -> Result<Self, SessionBindingError> {
        let mut rng = OsRng;
        let circuit = TlsSessionBindingCircuit::dummy();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| SessionBindingError::Setup(e.to_string()))?;
        let pvk = Groth16::<Bn254>::process_vk(&vk)
            .map_err(|e| SessionBindingError::Setup(e.to_string()))?;
        Ok(Self { pk, pvk })
    }

    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.pvk
            .serialize_compressed(&mut buf)
            .expect("pvk serialization must succeed");
        buf
    }
}

// ── Proof struct ──────────────────────────────────────────────────────────────

/// π_θs — proof that K_MAC authenticated the TLS query and response.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SessionBindingProof {
    pub groth16_bytes: Vec<u8>,
    pub k_mac_commitment_bytes: Vec<u8>,
    pub rand_binding_bytes: Vec<u8>,
    pub mac_commitment_q_bytes: Vec<u8>,
    pub mac_commitment_r_bytes: Vec<u8>,
}

// ── Execute ───────────────────────────────────────────────────────────────────

/// Prove that K_MAC authenticated the TLS query + response records.
///
/// # Arguments
/// - `crs`:                Proving key from `SessionBindingCrs::setup()`
/// - `k_mac`:              TLS session MAC key (θs) — private witness
/// - `rand_binding`:       DVRF randomness (same as HSP proof)
/// - `header_q/r`:         TLS record headers
/// - `query_data_hash`:    SHA256(query plaintext)
/// - `response_data_hash`: SHA256(response plaintext)
/// - `mac_q/r`:            Expected TLS record MACs
pub fn session_binding_prove(
    crs: &SessionBindingCrs,
    k_mac: [u8; 32],
    rand_binding: &[u8; 32],
    header_q: TlsRecordHeader,
    header_r: TlsRecordHeader,
    query_data_hash: [u8; 32],
    response_data_hash: [u8; 32],
    mac_q: [u8; 32],
    mac_r: [u8; 32],
) -> Result<SessionBindingProof, SessionBindingError> {
    let circuit = TlsSessionBindingCircuit::new(
        k_mac, rand_binding,
        header_q, header_r,
        query_data_hash, response_data_hash,
        mac_q, mac_r,
    );

    let k_mac_commit_fe   = circuit.k_mac_commitment_fe;
    let rand_fe            = circuit.rand_binding_fe;
    let mac_commit_q_fe   = circuit.mac_commitment_q_fe;
    let mac_commit_r_fe   = circuit.mac_commitment_r_fe;

    let mut rng = OsRng;
    let proof = Groth16::<Bn254>::prove(&crs.pk, circuit, &mut rng)
        .map_err(|e| SessionBindingError::Prove(e.to_string()))?;

    let mut groth16_bytes = Vec::new();
    proof.serialize_compressed(&mut groth16_bytes)
        .map_err(|e| SessionBindingError::Serialize(e.to_string()))?;

    let mut k_mac_commitment_bytes = Vec::new();
    k_mac_commit_fe.serialize_compressed(&mut k_mac_commitment_bytes)
        .map_err(|e| SessionBindingError::Serialize(e.to_string()))?;

    let mut rand_binding_bytes = Vec::new();
    rand_fe.serialize_compressed(&mut rand_binding_bytes)
        .map_err(|e| SessionBindingError::Serialize(e.to_string()))?;

    let mut mac_commitment_q_bytes = Vec::new();
    mac_commit_q_fe.serialize_compressed(&mut mac_commitment_q_bytes)
        .map_err(|e| SessionBindingError::Serialize(e.to_string()))?;

    let mut mac_commitment_r_bytes = Vec::new();
    mac_commit_r_fe.serialize_compressed(&mut mac_commitment_r_bytes)
        .map_err(|e| SessionBindingError::Serialize(e.to_string()))?;

    Ok(SessionBindingProof {
        groth16_bytes,
        k_mac_commitment_bytes,
        rand_binding_bytes,
        mac_commitment_q_bytes,
        mac_commitment_r_bytes,
    })
}

// ── Verify ────────────────────────────────────────────────────────────────────

/// Verify π_θs — confirm K_MAC authenticated the TLS query + response.
///
/// Checks:
/// 1. Groth16 proof is valid for the public inputs.
/// 2. `k_mac_commitment` in the proof matches `expected_k_mac_commitment`
///    (the commitment published by the HSP phase).
pub fn session_binding_verify(
    pvk: &Pvk,
    proof: &SessionBindingProof,
    expected_k_mac_commitment_bytes: &[u8],
) -> Result<(), SessionBindingError> {
    let groth16_proof = Pf::deserialize_compressed(proof.groth16_bytes.as_slice())
        .map_err(|e| SessionBindingError::Serialize(format!("proof deserialize: {e}")))?;

    let k_mac_commit_fe = Fr::deserialize_compressed(proof.k_mac_commitment_bytes.as_slice())
        .map_err(|e| SessionBindingError::Serialize(format!("k_mac_commitment deserialize: {e}")))?;

    let rand_fe = Fr::deserialize_compressed(proof.rand_binding_bytes.as_slice())
        .map_err(|e| SessionBindingError::Serialize(format!("rand_binding deserialize: {e}")))?;

    let mac_q_fe = Fr::deserialize_compressed(proof.mac_commitment_q_bytes.as_slice())
        .map_err(|e| SessionBindingError::Serialize(format!("mac_q deserialize: {e}")))?;

    let mac_r_fe = Fr::deserialize_compressed(proof.mac_commitment_r_bytes.as_slice())
        .map_err(|e| SessionBindingError::Serialize(format!("mac_r deserialize: {e}")))?;

    let public_inputs = vec![k_mac_commit_fe, rand_fe, mac_q_fe, mac_r_fe];

    let valid = Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &groth16_proof)
        .map_err(|e| SessionBindingError::Prove(e.to_string()))?;

    if !valid {
        return Err(SessionBindingError::Verify);
    }

    // Check that the K_MAC commitment in the proof matches the HSP proof's commitment.
    // This binds θs to the TLS session established by the HSP phase.
    if !expected_k_mac_commitment_bytes.is_empty() {
        let expected_fe =
            Fr::deserialize_compressed(expected_k_mac_commitment_bytes)
                .map_err(|e| SessionBindingError::Serialize(format!(
                    "expected_k_mac_commitment deserialize: {e}"
                )))?;
        if k_mac_commit_fe != expected_fe {
            return Err(SessionBindingError::Verify);
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
    use crate::hmac_sha256_gadget::hmac_sha256_gadget;
    use sha2::{Digest, Sha256};

    fn make_mac(k_mac: &[u8; 32], header: &TlsRecordHeader, data_hash: &[u8; 32]) -> [u8; 32] {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut input = header.to_bytes().to_vec();
        input.extend_from_slice(data_hash);
        hmac_sha256_gadget(cs, k_mac, &input).unwrap()
    }

    fn sample_header(seq: u64) -> TlsRecordHeader {
        TlsRecordHeader {
            seq_num: seq,
            content_type: 23, // ApplicationData
            version: [3, 3],
            data_len: 64,
        }
    }

    #[test]
    fn session_binding_circuit_is_satisfiable() {
        let k_mac: [u8; 32] = [0x42u8; 32];
        let rand_binding: [u8; 32] = [0x11u8; 32];
        let hdr_q = sample_header(0);
        let hdr_r = sample_header(1);

        let query_data_hash: [u8; 32] = Sha256::digest(b"GET /secret HTTP/1.1").into();
        let response_data_hash: [u8; 32] = Sha256::digest(b"HTTP/1.1 200 OK\r\n...").into();

        let mac_q = make_mac(&k_mac, &hdr_q, &query_data_hash);
        let mac_r = make_mac(&k_mac, &hdr_r, &response_data_hash);

        let circuit = TlsSessionBindingCircuit::new(
            k_mac, &rand_binding,
            hdr_q, hdr_r,
            query_data_hash, response_data_hash,
            mac_q, mac_r,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("constraints must synthesize");

        println!("TlsSessionBindingCircuit constraints: {}", cs.num_constraints());
        assert!(
            cs.is_satisfied().expect("satisfiability check"),
            "circuit must be satisfiable with consistent witnesses"
        );
    }

    /// Full Groth16 round-trip: prove θs binding, verify K_MAC commitment matches.
    #[test]
    fn session_binding_groth16_round_trip() {
        let k_mac: [u8; 32] = [0x77u8; 32];
        let rand_binding: [u8; 32] = [0xABu8; 32];
        let hdr_q = sample_header(10);
        let hdr_r = sample_header(11);

        let query_data_hash: [u8; 32] = Sha256::digest(b"GET /api/balance").into();
        let response_data_hash: [u8; 32] = Sha256::digest(b"HTTP/1.1 200 balance=42").into();

        let mac_q = make_mac(&k_mac, &hdr_q, &query_data_hash);
        let mac_r = make_mac(&k_mac, &hdr_r, &response_data_hash);

        let crs = SessionBindingCrs::setup().expect("setup must succeed");

        let proof = session_binding_prove(
            &crs,
            k_mac,
            &rand_binding,
            hdr_q, hdr_r,
            query_data_hash, response_data_hash,
            mac_q, mac_r,
        )
        .expect("prove must succeed");

        // Verify with correct K_MAC commitment.
        session_binding_verify(&crs.pvk, &proof, &proof.k_mac_commitment_bytes.clone())
            .expect("verify must succeed with correct commitment");

        // Verify with wrong K_MAC commitment must fail.
        let wrong_k_mac_commit = {
            use ark_serialize::CanonicalSerialize;
            let rand_fe = bytes32_to_fr(&rand_binding);
            let wrong_fe = bytes32_to_fr(&[0xFFu8; 32]) + rand_fe;
            let mut buf = Vec::new();
            wrong_fe.serialize_compressed(&mut buf).unwrap();
            buf
        };
        assert!(
            session_binding_verify(&crs.pvk, &proof, &wrong_k_mac_commit).is_err(),
            "verify must fail with wrong K_MAC commitment"
        );

        println!("π_θs proof size: {} bytes", proof.groth16_bytes.len());
    }

    #[test]
    fn session_binding_wrong_k_mac_unsatisfiable() {
        let k_mac: [u8; 32] = [0x42u8; 32];
        let wrong_k_mac: [u8; 32] = [0xFFu8; 32];
        let rand_binding: [u8; 32] = [0x11u8; 32];
        let hdr_q = sample_header(0);
        let hdr_r = sample_header(1);

        let query_data_hash: [u8; 32] = Sha256::digest(b"query").into();
        let response_data_hash: [u8; 32] = Sha256::digest(b"response").into();

        // MACs computed with k_mac but circuit uses wrong_k_mac as witness.
        let mac_q = make_mac(&k_mac, &hdr_q, &query_data_hash);
        let mac_r = make_mac(&k_mac, &hdr_r, &response_data_hash);

        let mut circuit = TlsSessionBindingCircuit::new(
            k_mac, &rand_binding,
            hdr_q, hdr_r,
            query_data_hash, response_data_hash,
            mac_q, mac_r,
        );
        // Tamper: swap k_mac witness to wrong value.
        circuit.k_mac = wrong_k_mac;

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("synthesis ok");

        assert!(
            !cs.is_satisfied().unwrap_or(false),
            "circuit must be unsatisfiable with wrong K_MAC"
        );
    }
}