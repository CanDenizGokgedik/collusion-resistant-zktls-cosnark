//! Attestation session model, envelope format, and auxiliary verifier logic.
//!
//! This crate contains all protocol logic. It has no I/O or async code.
//! Everything here is deterministic given its inputs.

pub mod dctls;
/// RC Phase — Π_coll-min Randomness Creation (DKG + PartialEval + Combine).
#[cfg(feature = "secp256k1")]
pub mod rc_phase;

/// DECO-based dx-DCTLS — full HSP + QP + PGP protocol (paper §VIII.C, Fig. 8).
pub mod deco_dx_dctls;

/// Distefano-based dx-DCTLS — TLS 1.3 variant using v2PC (paper §VIII.C, eq. 3).
pub mod distefano_dx_dctls;

/// secp256k1 FROST on-chain attestation (EVM SC.Verify, paper §IX Table I).
pub mod onchain_secp256k1;

/// Real TLS 1.2 session capture for DECO HSP (rustls + RFC 5705 exporter).
pub mod tls12_session;

pub mod tls_2pc;
#[cfg(feature = "tls")]
pub mod tls_engine;
pub mod engine;
pub mod envelope;
pub mod error;
pub mod onchain;
pub mod session;
pub mod statement;
pub mod verify;
pub mod zk_backend;

pub use dctls::{
    DctlsError, DctlsEvidence, HSPProof, PGPProof, QueryRecord, Statement,
    SessionParamsPublic, SessionParamsSecret, SessionParamsVerifier,
    TranscriptBinding,
    verify_hsp_proof, verify_pgp_proof, verify_query_record,
    verify_transcript_consistency,
    DCTLS_ENGINE_TAG,
};
pub use zk_backend::{ZkTlsBackend, CommitmentBackend};
pub use tls_2pc::{TlsSessionParams, compute_2pc_binding_input, derive_2pc_dvrf_exporter};
pub use engine::{AttestationEngine, AttestationPackage, CoordinatorEvidence, ExportableEvidence, PrototypeAttestationEngine};
#[cfg(feature = "tls")]
pub use tls_engine::TlsAttestationEngine;
pub use envelope::{AttestationEnvelope, RandomnessBinding};
pub use error::AttestationError;
pub use onchain::{
    OnChainAttestation, OnChainError,
    derive_onchain_statement_digest,
};
#[cfg(feature = "frost")]
pub use onchain::extract_on_chain_attestation;
pub use session::{SessionContext, SessionState};
pub use statement::{StatementPayload, derive_statement_digest};
pub use verify::{AuxiliaryVerifier, VerificationPolicy, VerificationResult};

#[cfg(feature = "secp256k1")]
pub use rc_phase::{
    RcPhaseParams,
    RcPhaseOutput,
    RcPhaseOrchestrator,
    rc_phase_verify,
};

pub use onchain_secp256k1::{
    OnChainAttestationSecp256k1,
    Secp256k1OnChainError,
};
#[cfg(feature = "secp256k1")]
pub use onchain_secp256k1::extract_secp256k1_attestation;

pub use distefano_dx_dctls::{
    Tls13SecretParams,
    ProverTrafficShare, VerifierTrafficShare,
    V2pcProof, V2pcExecutor, CommitmentV2pcExecutor,
    DistefanoHspProof, DistefanoQueryRecord, DistefanoDxDctlsProof,
    DistefanoAttestationSession, DistefanoError,
    verify_distefano_dx_dctls,
};

pub use tls12_session::{Tls12SessionCapture, mock_tls12_session};
#[cfg(feature = "tls")]
pub use tls12_session::Tls12Connector;
