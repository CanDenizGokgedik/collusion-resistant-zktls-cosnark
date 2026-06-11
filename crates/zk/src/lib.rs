//! `tls-attestation-zk` — Groth16 zero-knowledge backend for dx-DCTLS.
//!
//! Implements the `ZkTlsBackend` trait from `tls-attestation-attestation` using
//! a MiMC-7 hash circuit proved under Groth16 on the BN254 curve.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use tls_attestation_zk::GrothZkBackend;
//! use tls_attestation_attestation::zk_backend::ZkTlsBackend;
//!
//! // One-time trusted setup (≈ 2–5 s).
//! let backend = GrothZkBackend::setup().expect("setup failed");
//!
//! // Pass to AttestationEngine or use directly via ZkTlsBackend methods.
//! ```

pub mod circuit;
pub mod mimc;
pub mod backend;

/// TLS 1.2 HMAC-SHA256 PRF and 2PC MAC key split (paper §VIII.C).
pub mod tls12_hmac;

/// Groth16 R1CS circuit for TLS-PRF and 2PC K_MAC split verification.
pub mod tls_prf_circuit;

/// SHA256 R1CS gadget — ~37,416 constraints/block (paper §IX, reference [19]).
pub mod sha256_gadget;

pub mod aes128_gadget;

pub mod mac_then_encrypt;

/// HMAC-SHA256 + TLS-PRF R1CS gadgets (~74,832 constraints/HMAC call).
pub mod hmac_sha256_gadget;

/// Collaborative zk-SNARK (co-SNARK) — π_HSP proof (paper equation 2).
pub mod co_snark;

/// Verifying key exporter: arkworks BN254 → Solidity DctlsVerifier format (paper §IX).
pub mod vk_export;

/// TLS session secret (θs) in-circuit binding — paper §V PGP Proof.
///
/// Proves K_MAC authenticated the TLS query + response records via constrained
/// HMAC-SHA256 verification, binding the session secret to the transcript.
pub mod tls_session_binding;

/// Distributed co-SNARK with DH-masked witness exchange (security upgrade).
/// Coordinator never sees K^P_MAC or K^V_MAC in plaintext.
pub mod co_snark_split;

/// Subprocess-based distributed co-SNARK client (Ozdemir & Boneh 2022, paper ref [32]).
///
/// Spawns the `co-snark-prover` binary (ark 0.2 + mpc-algebra) via JSON IPC,
/// bypassing the ark 0.4 / ark 0.2 version conflict entirely.
///
/// # Build the prover binary first
///
/// ```bash
/// cd crates/co-snark-prover
/// cargo build --release
/// ```
pub mod co_snark_distributed;

pub use backend::{GrothZkBackend, ZkError};
pub use co_snark::{CoSnarkBackend, CoSnarkCrs, CoSnarkError, HspProof, co_snark_execute, co_snark_verify};
pub use tls12_hmac::{
    tls_prf_sha256, tls12_key_expansion,
    ProverMacKeyShare, VerifierMacKeyShare, MacKey, PreMasterSecret,
    split_mac_key, combine_mac_key_shares, derive_k_mac_from_pms,
};
pub use tls_prf_circuit::{
    TlsPrfCircuit, PgpBindingCircuit,
    k_mac_commitment, pgp_transcript_commitment, pms_hash, bytes32_to_fr,
};