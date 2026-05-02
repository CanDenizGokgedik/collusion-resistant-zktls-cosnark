//! Pedersen DKG adapter for FROST(Ed25519, SHA-512).
//!
//! Wraps `frost_ed25519::keys::dkg::{part1, part2, part3}` to produce the
//! same runtime types as `frost_trusted_dealer_keygen` — without any single
//! party holding the full group secret key.
//!
//! # Protocol summary (RFC 9591 / FROST paper §6)
//!
//! ```text
//! Part 1 — each participant independently:
//!   • Generates a random secret polynomial and a zero-knowledge proof.
//!   • Returns a Round-1 secret state (in memory, never transmitted) and
//!     a Round-1 broadcast package (sent to ALL other participants).
//!
//! Part 2 — each participant, after receiving all Round-1 packages:
//!   • Verifies every received Round-1 package (proof of knowledge check).
//!   • Produces one Round-2 package per OTHER participant (unicast).
//!   • Returns a Round-2 secret state (in memory, never transmitted).
//!
//!   ⚠ Round-2 packages MUST travel on confidential + authenticated channels.
//!
//! Part 3 — each participant, after receiving its Round-2 packages:
//!   • Derives its own long-term key share (KeyPackage).
//!   • Derives the shared group public key (PublicKeyPackage — identical for all).
//!   • The full group secret key is NEVER assembled anywhere.
//! ```
//!
//! # Output compatibility
//!
//! `dkg_part3` returns `DkgParticipantOutput` containing a `FrostParticipant`
//! and `FrostGroupKey` that are structurally identical to those produced by
//! `frost_trusted_dealer_keygen`. All existing signing/runtime infrastructure
//! (`FrostAuxiliaryNode`, `attest_frost_distributed`, approval verification)
//! accepts them unchanged.
//!
//! # Identifier assignment
//!
//! The ceremony coordinator assigns FROST identifiers before Part 1.
//! The rule — identical to `frost_trusted_dealer_keygen` — is:
//!
//! ```text
//! participant at position i in all_participant_ids → Identifier(i + 1)
//! ```
//!
//! All participants in the ceremony MUST agree on the same ordered list.
//!
//! # Round-2 confidentiality
//!
//! **RFC 9591 / Pedersen DKG requires that `round2::Package` is sent on a
//! confidential + authenticated channel.** `DkgRound2Package` documents this
//! requirement. In the in-process test harness it is trivially satisfied.
//! Before adding real network transport, callers MUST encrypt each Round-2
//! package to the recipient's long-term public key.

use crate::error::CryptoError;
use crate::frost_adapter::{FrostGroupKey, FrostParticipant};
use frost_ed25519 as frost;
use std::collections::{BTreeMap, HashMap};
use tls_attestation_core::ids::VerifierId;

// Re-export Identifier so the node crate does not need a direct frost-ed25519 dep.
pub use frost::Identifier;

use frost::keys::dkg as frost_dkg;

// ── Secret state wrappers ─────────────────────────────────────────────────────
//
// These are intentionally !Clone to prevent accidental duplication of
// secret polynomial material.

/// Secret state held between `dkg_part1` and `dkg_part2`.
///
/// # Safety invariants
///
/// - MUST NOT be transmitted to any other party.
/// - MUST NOT be persisted to untrusted storage.
/// - Consumed (moved) by `dkg_part2` regardless of outcome — if `dkg_part2`
///   returns an error, this state is gone and the ceremony must restart.
pub struct DkgRound1State(frost_dkg::round1::SecretPackage);

/// Secret state held between `dkg_part2` and `dkg_part3`.
///
/// # Safety invariants
///
/// - MUST NOT be transmitted to any other party.
/// - MUST NOT be persisted to untrusted storage.
/// - **Borrowed** (not consumed) by `dkg_part3`, so Part 3 can be retried
///   if a Round-2 package was missing or temporarily unavailable.
pub struct DkgRound2State(frost_dkg::round2::SecretPackage);

// ── Wire package wrappers ─────────────────────────────────────────────────────

/// Round-1 broadcast package.
///
/// The same copy is sent to every other participant.
/// Public — safe to route through an untrusted coordinator.
///
/// Serializable via `to_bytes` / `from_bytes` (serde_json internally, matching
/// the pattern established for signing wire types).
#[derive(Clone, Debug)]
pub struct DkgRound1Package(pub(crate) frost_dkg::round1::Package);

impl DkgRound1Package {
    /// Serialize for wire transmission (opaque bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0)
            .expect("DkgRound1Package serialization must not fail — library invariant")
    }

    /// Deserialize from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        serde_json::from_slice(bytes).map(DkgRound1Package).map_err(|e| {
            CryptoError::InvalidKeyMaterial(format!(
                "DkgRound1Package deserialization failed: {e}"
            ))
        })
    }
}

/// Round-2 unicast package.
///
/// Addressed to ONE specific recipient. Each participant sends a distinct
/// `DkgRound2Package` to every other participant.
///
/// # ⚠ CONFIDENTIALITY REQUIREMENT (RFC 9591)
///
/// **This package MUST be routed on a confidential + authenticated channel.**
///
/// The coordinator or any intermediate router MUST NOT be able to read its
/// contents. An adversary who intercepts a Round-2 package directed at
/// participant P learns partial information about P's secret share.
///
/// In the in-process test harness this requirement is satisfied by
/// construction (in-memory transfer, no network). Before adding real
/// network transport, callers MUST encrypt this package to the
/// recipient's long-term public key (e.g., via NaCl box / ECIES) before
/// handing it to any routing layer.
#[derive(Clone, Debug)]
pub struct DkgRound2Package(pub(crate) frost_dkg::round2::Package);

impl DkgRound2Package {
    /// Serialize to **plaintext** bytes for **in-process or already-encrypted** use.
    ///
    /// # ⚠ Do NOT send these bytes over a network without encryption.
    ///
    /// For network transmission, use `crate::dkg_encrypt::encrypt_round2_package()`
    /// to wrap this package in an authenticated X25519+XChaCha20-Poly1305 envelope
    /// before handing it to any routing layer.  Sending plaintext Round-2 packages
    /// over the network leaks partial information about participants' secret shares
    /// (RFC 9591 §5.3).
    ///
    /// This method is intentionally named `to_plaintext_bytes` (not `to_bytes`) to
    /// make the unencrypted nature visible at every call site.
    pub fn to_plaintext_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0)
            .expect("DkgRound2Package serialization must not fail — library invariant")
    }

    /// Deserialize from plaintext bytes (in-process or post-decryption).
    ///
    /// Call this only after decrypting via `crate::dkg_encrypt::decrypt_round2_package()`.
    pub fn from_plaintext_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        serde_json::from_slice(bytes).map(DkgRound2Package).map_err(|e| {
            CryptoError::InvalidKeyMaterial(format!(
                "DkgRound2Package deserialization failed: {e}"
            ))
        })
    }
}

// ── Output ────────────────────────────────────────────────────────────────────

/// Output of a completed Pedersen DKG ceremony for one participant.
///
/// The `FrostParticipant` and `FrostGroupKey` are structurally identical to
/// those produced by `frost_trusted_dealer_keygen` and work unchanged with all
/// existing signing/runtime infrastructure.
///
/// # Security property
///
/// Unlike trusted-dealer key generation, the full group secret key was NEVER
/// assembled in any process. Each participant's key share was derived solely
/// from their own polynomial and the shares received from other participants.
pub struct DkgParticipantOutput {
    /// This participant's secret key share. Treat as a private key.
    pub participant: FrostParticipant,
    /// Group public key and participant identity mapping. Safe to share widely.
    pub group_key: FrostGroupKey,
}

// ── Part 1 ────────────────────────────────────────────────────────────────────

/// Execute DKG Part 1 for one participant.
///
/// Generates a secret polynomial and a Schnorr zero-knowledge proof of
/// knowledge. Returns:
/// - `DkgRound1State` — held in memory until `dkg_part2`; never transmitted.
/// - `DkgRound1Package` — broadcast to ALL other participants.
///
/// `identifier` must be unique within the ceremony and assigned consistently
/// by the ceremony coordinator. The standard rule:
/// `all_participant_ids[i]` → `Identifier::try_from(i + 1)`.
pub fn dkg_part1(
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
) -> Result<(DkgRound1State, DkgRound1Package), CryptoError> {
    use rand::rngs::OsRng;

    let (secret_pkg, round1_pkg) =
        frost_dkg::part1(identifier, max_signers, min_signers, OsRng)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("DKG part1 failed: {e}")))?;

    Ok((DkgRound1State(secret_pkg), DkgRound1Package(round1_pkg)))
}

// ── Part 2 ────────────────────────────────────────────────────────────────────

/// Execute DKG Part 2 for one participant.
///
/// Processes Round-1 broadcast packages from all other participants.
/// The `DkgRound1State` is **consumed** (moved) regardless of outcome — if
/// this function returns an error, the ceremony must restart from Part 1.
///
/// `round1_packages` must contain exactly one entry per OTHER participant
/// (not including this participant's own package), keyed by FROST identifier.
///
/// Returns:
/// - `DkgRound2State` — held in memory until `dkg_part3`; never transmitted.
/// - `BTreeMap<Identifier, DkgRound2Package>` — one package per other participant.
///   **Each package MUST be routed to its recipient on a confidential + authenticated
///   channel** — see `DkgRound2Package` documentation.
pub fn dkg_part2(
    round1_state: DkgRound1State,
    round1_packages: &BTreeMap<Identifier, DkgRound1Package>,
) -> Result<(DkgRound2State, BTreeMap<Identifier, DkgRound2Package>), CryptoError> {
    let inner_r1: BTreeMap<Identifier, frost_dkg::round1::Package> =
        round1_packages.iter().map(|(id, pkg)| (*id, pkg.0.clone())).collect();

    // round1_state.0 is consumed here.
    let (round2_secret, outbound) =
        frost_dkg::part2(round1_state.0, &inner_r1)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("DKG part2 failed: {e}")))?;

    let wrapped = outbound.into_iter().map(|(id, pkg)| (id, DkgRound2Package(pkg))).collect();

    Ok((DkgRound2State(round2_secret), wrapped))
}

// ── Part 3 ────────────────────────────────────────────────────────────────────

/// Execute DKG Part 3 (final) for one participant.
///
/// Derives this participant's long-term key share and the shared group public
/// key from the collected packages.
///
/// The `DkgRound2State` is **borrowed** (not consumed) — if this function
/// fails (e.g., a Round-2 package is missing), the caller can retry once the
/// missing input is available.
///
/// `round2_packages` must contain one entry per OTHER participant (those
/// addressed TO this participant), keyed by the sender's FROST identifier.
///
/// `all_verifier_ids_in_order` determines the `VerifierId → Identifier`
/// mapping in the output `FrostGroupKey`. The rule:
/// `all_verifier_ids_in_order[i]` → `Identifier(i + 1)` — identical to
/// `frost_trusted_dealer_keygen`. All participants must use the same list.
///
/// # Output compatibility
///
/// The returned `DkgParticipantOutput` is a drop-in replacement for the
/// per-participant view of `TrustedDealerKeygenOutput`. No changes to
/// `FrostAuxiliaryNode`, `attest_frost_distributed`, or any signing code
/// are required.
pub fn dkg_part3(
    my_verifier_id: &VerifierId,
    my_identifier: Identifier,
    round2_state: &DkgRound2State,
    round1_packages: &BTreeMap<Identifier, DkgRound1Package>,
    round2_packages: &BTreeMap<Identifier, DkgRound2Package>,
    all_verifier_ids_in_order: &[VerifierId],
) -> Result<DkgParticipantOutput, CryptoError> {
    let inner_r1: BTreeMap<Identifier, frost_dkg::round1::Package> =
        round1_packages.iter().map(|(id, pkg)| (*id, pkg.0.clone())).collect();

    let inner_r2: BTreeMap<Identifier, frost_dkg::round2::Package> =
        round2_packages.iter().map(|(id, pkg)| (*id, pkg.0.clone())).collect();

    let (key_package, pub_key_package) =
        frost_dkg::part3(&round2_state.0, &inner_r1, &inner_r2)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("DKG part3 failed: {e}")))?;

    // Build the VerifierId → Identifier map using the same deterministic rule
    // as frost_trusted_dealer_keygen: all_verifier_ids_in_order[i] → Identifier(i+1).
    let mut verifier_to_id = HashMap::with_capacity(all_verifier_ids_in_order.len());
    for (idx, vid) in all_verifier_ids_in_order.iter().enumerate() {
        let frost_id = Identifier::try_from((idx + 1) as u16).map_err(|e| {
            CryptoError::InvalidKeyMaterial(format!(
                "DKG identifier assignment at index {idx}: {e}"
            ))
        })?;
        verifier_to_id.insert(vid.clone(), frost_id);
    }

    Ok(DkgParticipantOutput {
        participant: FrostParticipant::new_from_key_package(
            key_package,
            my_identifier,
            my_verifier_id.clone(),
        ),
        group_key: FrostGroupKey::new_from_parts(pub_key_package, verifier_to_id),
    })
}
