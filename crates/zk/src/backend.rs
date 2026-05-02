//! `GrothZkBackend` — real ZK backend implementing `ZkTlsBackend`.
//!
//! # What changes vs `CommitmentBackend`
//!
//! | Field in `HSPProof`   | CommitmentBackend    | GrothZkBackend                   |
//! |-----------------------|----------------------|----------------------------------|
//! | `dvrf_exporter`       | plaintext            | zeroed (hidden from verifier)    |
//! | `zk_proof`            | `None`               | `Some(Groth16 π bytes)`          |
//! | `zk_binding`          | `None`               | `Some(MiMC7 sponge output bytes)`|
//!
//! # Trusted setup
//!
//! `GrothZkBackend::setup()` runs a local Groth16 trusted setup using
//! `HspCircuit` as the constraint system.  In production this should be
//! replaced with a multi-party ceremony.
//!
//! # Proof verification
//!
//! `verify_session_params` skips the conventional SHA-256 re-derivation of
//! `dvrf_exporter` (which would fail because the field is zeroed) and instead
//! verifies the Groth16 proof against the four public inputs.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

use tls_attestation_attestation::dctls::{
    DctlsError, HSPProof, PGPProof, QueryRecord, SessionParamsPublic, SessionParamsSecret,
    Statement,
};
use tls_attestation_attestation::zk_backend::ZkTlsBackend;
use tls_attestation_core::{hash::DigestBytes, ids::SessionId};

use crate::circuit::HspCircuit;
use crate::mimc::{bytes16_to_fe, bytes31_to_fe, mimc7_sponge, mimc_constants};

// Type aliases for the Groth16 associated types on BN254.
type Pk = <Groth16<Bn254> as SNARK<Fr>>::ProvingKey;
type Pvk = <Groth16<Bn254> as SNARK<Fr>>::ProcessedVerifyingKey;
type Pf = <Groth16<Bn254> as SNARK<Fr>>::Proof;

// ── GrothZkBackend ─────────────────────────────────────────────────────────────

/// Groth16 zero-knowledge backend for dx-DCTLS.
///
/// Hides `dvrf_exporter` from all verifiers while still allowing them to check
/// the binding digest through the succinct Groth16 proof.
pub struct GrothZkBackend {
    pk:  Pk,
    pvk: Pvk,
}

impl GrothZkBackend {
    /// Run a Groth16 trusted setup keyed to the `HspCircuit` shape.
    ///
    /// Uses a **deterministic** RNG — suitable for tests and development.
    /// Production deployments should use a proper MPC ceremony and load
    /// the resulting keys instead of calling this function.
    pub fn setup() -> Result<Self, ZkError> {
        let mut rng = StdRng::seed_from_u64(0x746c735f61747465_u64);
        let circuit = dummy_hsp_circuit();

        let (pk, vk) =
            <Groth16<Bn254> as SNARK<Fr>>::circuit_specific_setup(circuit, &mut rng)
                .map_err(|e| ZkError::Setup(e.to_string()))?;

        let pvk = <Groth16<Bn254> as SNARK<Fr>>::process_vk(&vk)
            .map_err(|e| ZkError::Setup(e.to_string()))?;

        Ok(Self { pk, pvk })
    }

    /// Serialize the processed verifying key for distribution.
    pub fn export_pvk(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.pvk.serialize_compressed(&mut buf).unwrap_or_default();
        buf
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    fn prove_hsp_internal(
        &self,
        session_id:       &SessionId,
        rand_value:       &DigestBytes,
        dvrf_exporter:    &DigestBytes,
        server_cert_hash: &DigestBytes,
        ht_hash:          &DigestBytes,
    ) -> Result<(DigestBytes, Vec<u8>), ZkError> {
        let constants = mimc_constants::<Fr>();

        let sid_fe:  Fr = bytes16_to_fe(session_id.as_bytes());
        let rand_fe: Fr = bytes31_to_fe(rand_value.as_bytes());
        let cert_fe: Fr = bytes31_to_fe(server_cert_hash.as_bytes());
        let dvrf_fe: Fr = bytes31_to_fe(dvrf_exporter.as_bytes());
        let ht_fe:   Fr = bytes31_to_fe(ht_hash.as_bytes());

        let zk_binding =
            mimc7_sponge(&[sid_fe, rand_fe, dvrf_fe, cert_fe, ht_fe], &constants);

        let circuit = HspCircuit {
            session_id_fe:    sid_fe,
            rand_fe,
            cert_hash_fe:     cert_fe,
            zk_binding,
            dvrf_exporter_fe: dvrf_fe,
            ht_hash_fe:       ht_fe,
        };

        let mut rng = StdRng::from_entropy();
        let proof: Pf =
            <Groth16<Bn254> as SNARK<Fr>>::prove(&self.pk, circuit, &mut rng)
                .map_err(|e| ZkError::Prove(e.to_string()))?;

        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| ZkError::Serialize(e.to_string()))?;

        let binding_le = zk_binding.into_bigint().to_bytes_le();
        let mut binding_bytes = [0u8; 32];
        binding_bytes[..binding_le.len().min(32)]
            .copy_from_slice(&binding_le[..binding_le.len().min(32)]);

        Ok((DigestBytes::from_bytes(binding_bytes), proof_bytes))
    }

    fn verify_hsp_zk(
        &self,
        session_id:       &SessionId,
        rand_value:       &DigestBytes,
        server_cert_hash: &DigestBytes,
        zk_binding:       &DigestBytes,
        proof_bytes:      &[u8],
    ) -> Result<(), ZkError> {
        let sid_fe:     Fr = bytes16_to_fe(session_id.as_bytes());
        let rand_fe:    Fr = bytes31_to_fe(rand_value.as_bytes());
        let cert_fe:    Fr = bytes31_to_fe(server_cert_hash.as_bytes());
        let binding_fe: Fr = Fr::from_le_bytes_mod_order(zk_binding.as_bytes());

        // Public inputs must match the order in `HspCircuit::generate_constraints`.
        let public_inputs = vec![sid_fe, rand_fe, cert_fe, binding_fe];

        let proof = Pf::deserialize_compressed(proof_bytes)
            .map_err(|_| ZkError::BadProof("deserialization failed".into()))?;

        let ok =
            <Groth16<Bn254> as SNARK<Fr>>::verify_with_processed_vk(
                &self.pvk,
                &public_inputs,
                &proof,
            )
            .map_err(|e| ZkError::BadProof(e.to_string()))?;

        if ok {
            Ok(())
        } else {
            Err(ZkError::BadProof("Groth16 verification rejected".into()))
        }
    }
}

// ── ZkTlsBackend impl ──────────────────────────────────────────────────────────

impl ZkTlsBackend for GrothZkBackend {
    fn prove_session_params(
        &self,
        session_id: &SessionId,
        rand_value: &DigestBytes,
        sps:        &SessionParamsSecret,
        spp:        &SessionParamsPublic,
    ) -> Result<HSPProof, DctlsError> {
        let ht_hash = HSPProof::compute_handshake_transcript_hash(
            &spp.server_cert_hash,
            spp.tls_version,
            &spp.server_name,
            spp.established_at,
        );
        let commitment = HSPProof::compute_commitment(
            session_id,
            rand_value,
            &sps.dvrf_exporter,
            &spp.server_cert_hash,
            &ht_hash,
        );

        let (zk_binding, proof_bytes) = self
            .prove_hsp_internal(
                session_id,
                rand_value,
                &sps.dvrf_exporter,
                &spp.server_cert_hash,
                &ht_hash,
            )
            .map_err(|e| DctlsError::ZkProofFailed(e.to_string()))?;

        Ok(HSPProof {
            session_id:               session_id.clone(),
            rand_value:               rand_value.clone(),
            // Zero out the exporter — the verifier must not see it.
            dvrf_exporter:            DigestBytes::from_bytes([0u8; 32]),
            commitment,
            server_cert_hash:         spp.server_cert_hash.clone(),
            handshake_transcript_hash: ht_hash,
            tls_version:              spp.tls_version,
            server_name:              spp.server_name.clone(),
            established_at:           spp.established_at,
            engine_tag:               "dx-dctls/groth16-mimc7-v1".into(),
            zk_proof:                 Some(proof_bytes),
            zk_binding:               Some(zk_binding),
        })
    }

    fn verify_session_params(
        &self,
        proof:            &HSPProof,
        rand_value:       &DigestBytes,
        server_cert_hash: &DigestBytes,
    ) -> Result<(), DctlsError> {
        if &proof.rand_value != rand_value {
            return Err(DctlsError::RandMismatch);
        }
        if &proof.server_cert_hash != server_cert_hash {
            return Err(DctlsError::CertHashMismatch);
        }

        let (zk_binding, proof_bytes) = match (&proof.zk_binding, &proof.zk_proof) {
            (Some(b), Some(p)) => (b, p.as_slice()),
            _ => return Err(DctlsError::ZkProofFailed("missing ZK proof fields".into())),
        };

        self.verify_hsp_zk(
            &proof.session_id,
            rand_value,
            server_cert_hash,
            zk_binding,
            proof_bytes,
        )
        .map_err(|e| DctlsError::ZkProofFailed(e.to_string()))
    }

    // QP and PGP: the commitment construction contains no sensitive data.
    fn prove_query_response(
        &self,
        session_id: &SessionId,
        rand_value: &DigestBytes,
        query:      &[u8],
        response:   &[u8],
    ) -> Result<QueryRecord, DctlsError> {
        Ok(QueryRecord::build(session_id, rand_value, query, response))
    }

    fn verify_query_response(
        &self,
        record:   &QueryRecord,
        query:    &[u8],
        response: &[u8],
    ) -> Result<(), DctlsError> {
        tls_attestation_attestation::dctls::verify_query_record(record, query, response)
    }

    fn prove_pgp(
        &self,
        _session_id: &SessionId,
        _rand_value: &DigestBytes,
        qr:          &QueryRecord,
        statement:   Statement,
        hsp:         &HSPProof,
    ) -> Result<PGPProof, DctlsError> {
        Ok(PGPProof::generate(&qr.session_id, &qr.rand_value, qr, statement, hsp))
    }

    fn verify_pgp(
        &self,
        proof:      &PGPProof,
        rand_value: &DigestBytes,
        hsp:        &HSPProof,
    ) -> Result<(), DctlsError> {
        tls_attestation_attestation::dctls::verify_pgp_proof(proof, rand_value, hsp)
    }

    fn backend_tag(&self) -> &'static str {
        "groth16/mimc7-bn254-v1"
    }
}

// ── ZkError ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    #[error("trusted setup failed: {0}")]
    Setup(String),
    #[error("proof generation failed: {0}")]
    Prove(String),
    #[error("serialization failed: {0}")]
    Serialize(String),
    #[error("invalid proof: {0}")]
    BadProof(String),
}

// ── helpers ────────────────────────────────────────────────────────────────────

fn dummy_hsp_circuit() -> HspCircuit {
    HspCircuit {
        session_id_fe:    Fr::from(0u64),
        rand_fe:          Fr::from(0u64),
        cert_hash_fe:     Fr::from(0u64),
        zk_binding:       Fr::from(0u64),
        dvrf_exporter_fe: Fr::from(0u64),
        ht_hash_fe:       Fr::from(0u64),
    }
}

// ── tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_attestation::dctls::{SessionParamsPublic, SessionParamsSecret};
    use tls_attestation_core::hash::{CanonicalHasher, DigestBytes};
    use tls_attestation_core::ids::SessionId;

    fn sid()      -> SessionId   { SessionId::from_bytes([0xAAu8; 16]) }
    fn rand_val() -> DigestBytes { DigestBytes::from_bytes([0xBBu8; 32]) }
    fn cert()     -> DigestBytes { DigestBytes::from_bytes([0xCCu8; 32]) }

    fn make_sps(sid: &SessionId, rand: &DigestBytes) -> SessionParamsSecret {
        let mut h = CanonicalHasher::new("test/exporter");
        h.update_fixed(sid.as_bytes());
        h.update_digest(rand);
        SessionParamsSecret {
            dvrf_exporter: h.finalize(),
            session_nonce: DigestBytes::from_bytes([0xDDu8; 32]),
        }
    }

    fn make_spp(cert: DigestBytes) -> SessionParamsPublic {
        SessionParamsPublic {
            server_cert_hash: cert,
            tls_version:      0x0304,
            server_name:      "example.com".into(),
            established_at:   1_700_000_000,
        }
    }

    #[test]
    fn setup_succeeds() {
        GrothZkBackend::setup().expect("trusted setup should succeed");
    }

    #[test]
    fn prove_verify_roundtrip() {
        let backend = GrothZkBackend::setup().unwrap();
        let sid  = sid();
        let rand = rand_val();
        let sps  = make_sps(&sid, &rand);
        let spp  = make_spp(cert());

        let proof = backend.prove_session_params(&sid, &rand, &sps, &spp).unwrap();

        assert_eq!(proof.dvrf_exporter.as_bytes(), &[0u8; 32], "exporter must be zeroed");
        assert!(proof.zk_proof.is_some(),   "ZK proof must be present");
        assert!(proof.zk_binding.is_some(), "ZK binding must be present");

        backend.verify_session_params(&proof, &rand, &cert())
               .expect("Groth16 proof must verify");
    }

    #[test]
    fn tampered_cert_rejected() {
        let backend = GrothZkBackend::setup().unwrap();
        let sid  = sid();
        let rand = rand_val();
        let sps  = make_sps(&sid, &rand);
        let spp  = make_spp(cert());

        let mut proof = backend.prove_session_params(&sid, &rand, &sps, &spp).unwrap();
        let bad_cert  = DigestBytes::from_bytes([0xFFu8; 32]);
        proof.server_cert_hash = bad_cert.clone();

        let result = backend.verify_session_params(&proof, &rand, &bad_cert);
        assert!(result.is_err(), "tampered cert must be rejected by Groth16");
    }

    #[test]
    fn dvrf_exporter_not_revealed() {
        let backend = GrothZkBackend::setup().unwrap();
        let sid  = sid();
        let rand = rand_val();
        let sps  = make_sps(&sid, &rand);
        let spp  = make_spp(cert());

        let proof = backend.prove_session_params(&sid, &rand, &sps, &spp).unwrap();

        // The dvrf_exporter in the proof must not equal the original secret.
        assert_ne!(
            proof.dvrf_exporter.as_bytes(),
            sps.dvrf_exporter.as_bytes(),
            "dvrf_exporter secret must not appear in the proof"
        );
    }
}