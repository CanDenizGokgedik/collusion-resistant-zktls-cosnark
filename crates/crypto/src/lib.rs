//! Cryptographic abstractions and prototype implementations.
//!
//! # Production readiness
//!
//! All items in this crate labelled `Prototype` are NOT production-safe.
//! They provide correct structure for development and testing but make
//! simplifying assumptions that compromise security under adversarial conditions.
//! See `docs/THREAT_MODEL.md` for details.
//!
//! # Trait-based design
//!
//! All cryptographic operations are accessed through traits:
//! - [`RandomnessEngine`] — distributed verifiable random function
//! - [`ThresholdSigner`] — threshold signature scheme (single-round, prototype)
//!
//! For real FROST threshold signing (two-round), enable the `frost` feature and
//! use [`frost_adapter`] directly. FROST requires a separate coordinator-driven
//! two-round protocol — see `docs/FROST_INTEGRATION.md`.
//!
//! Swap implementations by changing which concrete type implements the trait.
//! No protocol code should depend directly on `Prototype*` types.

pub mod error;
pub mod participant_registry;
pub mod randomness;
pub mod threshold;
pub mod transcript;

/// Real FROST (RFC 9591) threshold signing adapter.
///
/// Only available when compiled with `--features frost`.
/// The prototype single-round signer in [`threshold`] remains available
/// regardless of this feature.
#[cfg(feature = "frost")]
pub mod frost_adapter;

/// Pedersen DKG adapter: distributed key generation without a trusted dealer.
///
/// Only available when compiled with `--features frost`.
/// Use `frost_trusted_dealer_keygen` (in `frost_adapter`) for tests and
/// controlled bootstrap scenarios; use this module for production key ceremonies.
#[cfg(feature = "frost")]
pub mod dkg;

/// DKG Round-2 wire confidentiality (RFC 9591 §5.3).
///
/// Provides `encrypt_round2_package` / `decrypt_round2_package` using
/// static-static X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305.
/// The coordinator routing `EncryptedDkgRound2Package` sees routing metadata
/// but cannot read plaintext package contents.
///
/// Only available when compiled with `--features frost`.
#[cfg(feature = "frost")]
pub mod dkg_encrypt;

/// Authenticated DKG encryption key distribution.
///
/// Removes coordinator key-substitution risk: each participant signs their
/// `DkgEncryptionPublicKey` with their long-term ed25519 identity key before
/// distribution. Peers verify announcements against a pre-distributed
/// `DkgParticipantRegistry` before accepting any key for use in round-2 routing.
///
/// Only available when compiled with `--features frost`.
#[cfg(feature = "frost")]
pub mod dkg_announce;

/// FROST-based Distributed Verifiable Random Function (DVRF).
///
/// Replaces `PrototypeDvrf` with a real threshold VRF using deterministic
/// FROST Schnorr signatures.
#[cfg(feature = "frost")]
pub mod dvrf;

/// secp256k1 FROST adapter — EVM-compatible production path (paper §IX).
///
/// Provides `Secp256k1FrostParticipant`, `Secp256k1GroupKey`, and coordinator
/// helpers (`secp256k1_build_signing_package`, `secp256k1_aggregate_signature_shares`).
///
/// Only available when compiled with `--features secp256k1`.
#[cfg(feature = "secp256k1")]
pub mod frost_secp256k1_adapter;

/// DDH-based DVRF on secp256k1 (paper §III.B, references [25][26][27]).
///
/// Provides the RC Phase: DKG + PartialEval + Combine + Verify on secp256k1.
/// Required for Π_coll-min deployments; the resulting `rand` value is used
/// in the dx-DCTLS attestation phase.
///
/// Only available when compiled with `--features secp256k1`.
#[cfg(feature = "secp256k1")]
pub mod dvrf_secp256k1;

/// Pedersen DKG for secp256k1 — production key generation without a trusted dealer.
///
/// Provides `run_secp256k1_dkg` for in-process ceremonies and
/// `secp256k1_dkg_part1/2/3` for distributed ceremonies.
///
/// Only available when compiled with `--features secp256k1`.
#[cfg(feature = "secp256k1")]
pub mod dkg_secp256k1;

pub use error::CryptoError;
pub use participant_registry::{
    ParticipantRegistry, ParticipantStatus, RegisteredParticipant, RegistryEpoch, RegistryError,
};
pub use randomness::{
    PartialRandomness, PrototypeDvrf, RandomnessEngine, RandomnessOutput,
};
#[cfg(feature = "secp256k1")]
pub use randomness::Secp256k1DvrfEngine;
pub use threshold::{
    PartialSignature, PrototypeThresholdSigner, ThresholdApproval, ThresholdSigner,
    VerifierKeyPair,
};
pub use transcript::{TranscriptCommitment, TranscriptCommitments};

#[cfg(feature = "frost")]
pub use dvrf::{DvRFError, DvRFInput, DvRFOutput, DvRFProof, FrostDvRF};

#[cfg(feature = "secp256k1")]
pub use frost_secp256k1_adapter::{
    secp256k1_trusted_dealer_keygen,
    secp256k1_build_signing_package,
    secp256k1_aggregate_signature_shares,
    secp256k1_verify_approval,
    Secp256k1FrostParticipant,
    Secp256k1GroupKey,
    Secp256k1KeygenOutput,
    Secp256k1SigningNonces,
    Secp256k1Commitment,
    Secp256k1SignatureShare,
    Secp256k1SigningPackage,
    Secp256k1ThresholdApproval,
};

#[cfg(feature = "secp256k1")]
pub use dvrf_secp256k1::{
    Secp256k1Dvrf,
    Secp256k1DvrfOutput,
    Secp256k1DvrfProof,
    Secp256k1DvrfInput,
    Secp256k1PartialEval,
};

#[cfg(feature = "secp256k1")]
pub use dkg_secp256k1::{
    run_secp256k1_dkg,
    secp256k1_dkg_part1,
    secp256k1_dkg_part2,
    secp256k1_dkg_part3,
    Secp256k1DkgRound1State,
    Secp256k1DkgRound2State,
    Secp256k1DkgRound1Package,
    Secp256k1DkgRound2Package,
    Secp256k1DkgParticipantOutput,
};
