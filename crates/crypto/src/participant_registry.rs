//! Versioned participant registry with epoch binding, revocation, and key rotation.
//!
//! This is the authoritative source of truth for participant authorization in DKG
//! ceremonies and FROST signing sessions. It closes the implicit trust gap left by
//! the flat `DkgParticipantRegistry` (no epoch, no status, no revocation) and the
//! raw `Vec<(VerifierId, VerifyingKey)>` in `CoordinatorConfig`.
//!
//! # Mental model
//!
//! A `ParticipantRegistry` is an **immutable snapshot** of authorized participants
//! at a specific `RegistryEpoch`. Every ceremony or signing session **must bind**
//! to a specific epoch; using a stale or mismatched snapshot is an explicit error.
//!
//! # Epoch binding
//!
//! `RegistryEpoch` is a monotonically increasing version counter. Every time the
//! participant set changes (admission, revocation, key rotation), the epoch MUST
//! increase. Mutation methods (`with_revocation`, `with_key_rotation`) return a
//! **new** registry at a strictly higher epoch — the old snapshot is unaffected.
//!
//! # Revocation
//!
//! A revoked participant's `status` changes from `Active` to `Revoked`. All
//! admission checks (`check_ceremony_admission`, `get_active`) return
//! `RegistryError::RevokedParticipant` for such entries. Old signed announcements
//! remain cryptographically verifiable but will fail admission because:
//! - `check_ceremony_admission` requires the ceremony to bind to the current epoch.
//! - The new epoch's `to_dkg_registry()` only includes `Active` participants.
//!
//! # Key rotation
//!
//! `with_key_rotation` updates a participant's `signing_key` and returns a new
//! registry at a strictly higher epoch. Old signed announcements (using the old key)
//! are invalid under the new epoch because the DKG registry derived from the new
//! snapshot contains the new key, not the old one.
//!
//! # Trust model
//!
//! The `ParticipantRegistry` must be distributed through a channel that is
//! **independent of the ceremony coordinator**. If the coordinator can modify
//! registry contents, all downstream admission guarantees are void.
//!
//! ## What this module prevents (given a trusted registry source)
//!
//! - Stale registry use: epoch check rejects old snapshots.
//! - Revoked participant admission: status check blocks them at every entry point.
//! - Key substitution: `to_dkg_registry()` exposes current active keys only.
//! - Mixed-epoch confusion: epoch check is transitive through admission gates.
//!
//! ## What is NOT prevented by this module alone
//!
//! - Registry poisoning: if an adversary can modify the registry itself, all
//!   guarantees are void. The registry distribution channel must be trusted.
//! - DoS via registry withholding: an adversary that prevents registry distribution
//!   can block ceremony startup (liveness threat, not confidentiality threat).

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;
use tls_attestation_core::ids::VerifierId;

#[cfg(feature = "frost")]
use crate::dkg_announce::DkgParticipantRegistry;

// ── Registry epoch ────────────────────────────────────────────────────────────

/// Monotonically increasing registry version counter.
///
/// Every mutation of the participant set (addition, revocation, key rotation)
/// MUST produce a new `RegistryEpoch` that is strictly greater than the previous
/// one. Ceremonies bind to a specific epoch and reject any registry snapshot
/// whose epoch does not match.
///
/// # Relationship to `tls_attestation_core::types::Epoch`
///
/// `Epoch` (in `core`) is the session-level key material epoch, used by the
/// coordinator to scope randomness and verifier keys. `RegistryEpoch` is
/// the participant-registry version. In a well-operated deployment these two
/// counters should advance in lockstep, but they are kept separate to avoid
/// conflating session-level concerns with participant admission control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RegistryEpoch(pub u64);

impl RegistryEpoch {
    /// The initial epoch for a freshly bootstrapped registry.
    pub const GENESIS: Self = Self(0);

    /// Return the immediately following epoch.
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for RegistryEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "registry-epoch:{}", self.0)
    }
}

// ── Participant status ────────────────────────────────────────────────────────

/// Authorization status of a registered participant.
///
/// Only `Active` participants are admitted to new DKG ceremonies or FROST
/// signing sessions. `Revoked` and `Retired` participants fail all admission
/// checks — the distinction is semantic only:
/// - `Revoked` = involuntary removal (misbehaviour, key compromise).
/// - `Retired` = voluntary withdrawal (graceful shutdown, decommission).
///
/// Status transitions:
/// ```text
/// Active  ──revoke──►  Revoked   (permanent within this epoch; new epoch can re-admit)
/// Active  ──retire──►  Retired   (same enforcement as Revoked)
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParticipantStatus {
    /// Participant is eligible for new ceremonies and signing sessions.
    Active,
    /// Participant has been involuntarily removed. All admission checks fail.
    ///
    /// To re-admit a revoked participant, create a new registry snapshot at
    /// a higher epoch with the participant listed as `Active`.
    Revoked,
    /// Participant has voluntarily retired. All admission checks fail.
    Retired,
}

impl ParticipantStatus {
    /// True if and only if the status is `Active`.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl fmt::Display for ParticipantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Revoked => write!(f, "revoked"),
            Self::Retired => write!(f, "retired"),
        }
    }
}

// ── Registry entry ────────────────────────────────────────────────────────────

/// A single participant entry in the `ParticipantRegistry`.
///
/// # Key self-authentication
///
/// `verifier_id` is `SHA-256(signing_key.to_bytes())`, so the
/// `VerifierId → VerifyingKey` binding is structurally guaranteed.
/// A caller who constructs a `RegisteredParticipant` with a mismatched pair
/// (e.g. using `VerifierId::from_bytes` with arbitrary bytes) is responsible
/// for that inconsistency — `ParticipantRegistry::new` does not re-derive
/// or cross-check the hash.
#[derive(Clone, Debug)]
pub struct RegisteredParticipant {
    /// Participant identity.
    pub verifier_id: VerifierId,
    /// Long-term ed25519 signing public key.
    pub signing_key: VerifyingKey,
    /// Authorization status.
    pub status: ParticipantStatus,
    /// Registry epoch when this entry was added or last modified.
    pub added_at_epoch: RegistryEpoch,
}

impl RegisteredParticipant {
    /// Construct a new active participant entry from explicit fields.
    ///
    /// **Does not validate** that `verifier_id` is derived from `signing_key`.
    /// Prefer `from_signing_key` when constructing from raw key material to
    /// guarantee consistency.  Use this constructor only when you already hold
    /// a pre-validated `(VerifierId, VerifyingKey)` pair (e.g., from a signed
    /// operator manifest that you trust to be consistent).
    pub fn active(
        verifier_id: VerifierId,
        signing_key: VerifyingKey,
        epoch: RegistryEpoch,
    ) -> Self {
        Self {
            verifier_id,
            signing_key,
            status: ParticipantStatus::Active,
            added_at_epoch: epoch,
        }
    }

    /// Construct a new active participant entry by **deriving** `VerifierId`
    /// from the signing key.
    ///
    /// `VerifierId` is computed as `SHA-256(signing_key.to_bytes())` — the
    /// same derivation used by `VerifierKeyPair::from_seed` and
    /// `VerifierId::from_public_key`. This guarantees structural consistency
    /// between the identity and the key stored in this entry.
    ///
    /// Prefer this constructor over `active()` when building entries from raw
    /// key material.
    pub fn from_signing_key(signing_key: VerifyingKey, epoch: RegistryEpoch) -> Self {
        let verifier_id = VerifierId::from_public_key(signing_key.as_bytes());
        Self::active(verifier_id, signing_key, epoch)
    }

    /// Validate that `self.verifier_id` is structurally consistent with
    /// `self.signing_key`.
    ///
    /// A mismatch can only arise if the entry was constructed via `active()`
    /// with a manually specified `VerifierId` that does not equal
    /// `SHA-256(signing_key.to_bytes())`.
    ///
    /// # Errors
    ///
    /// Returns `RegistryError::VerifierIdMismatch` if the IDs differ.
    pub fn validate_key_consistency(&self) -> Result<(), RegistryError> {
        let derived = VerifierId::from_public_key(self.signing_key.as_bytes());
        if derived != self.verifier_id {
            return Err(RegistryError::VerifierIdMismatch {
                claimed: self.verifier_id.clone(),
                derived,
            });
        }
        Ok(())
    }

    /// True only if the participant is currently `Active`.
    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }
}

// ── Registry errors ───────────────────────────────────────────────────────────

/// Errors from participant registry operations and admission checks.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Participant is not in the registry at all.
    #[error("participant {0} is not in the registry")]
    UnknownParticipant(VerifierId),

    /// Participant exists but has been involuntarily revoked.
    #[error("participant {0} has been revoked and is not eligible for new ceremonies")]
    RevokedParticipant(VerifierId),

    /// Participant exists but has voluntarily retired.
    #[error("participant {0} has retired and is not eligible for new ceremonies")]
    RetiredParticipant(VerifierId),

    /// The ceremony or session tried to bind to an epoch that does not match
    /// the registry snapshot's epoch.
    #[error("registry epoch mismatch: expected {expected}, got {actual}")]
    EpochMismatch {
        expected: RegistryEpoch,
        actual: RegistryEpoch,
    },

    /// A participant appeared more than once in the registry construction input.
    #[error("participant {0} appears more than once — registry entries must be unique")]
    DuplicateParticipant(VerifierId),

    /// The registry was constructed with zero participants.
    #[error("registry must contain at least one participant")]
    EmptyRegistry,

    /// A mutation was attempted with a new epoch that is not strictly greater
    /// than the current epoch.
    #[error(
        "epoch {new} is not strictly greater than the current registry epoch {current} — \
         registry epochs must advance monotonically"
    )]
    StaleRotationEpoch {
        current: RegistryEpoch,
        new: RegistryEpoch,
    },

    /// Revocation was requested for a participant not in the registry.
    #[error("cannot revoke participant {0}: not in registry")]
    RevocationTargetUnknown(VerifierId),

    /// The participant is already in the `Revoked` state.
    #[error("participant {0} is already revoked")]
    AlreadyRevoked(VerifierId),

    /// Key rotation was requested for a participant not in the registry.
    #[error("cannot rotate key for participant {0}: not in registry")]
    RotationTargetUnknown(VerifierId),

    /// `VerifierId` and `VerifyingKey` are structurally inconsistent.
    ///
    /// A consistent entry requires `claimed == SHA-256(signing_key.to_bytes())`.
    /// This error is returned by `RegisteredParticipant::validate_key_consistency`
    /// and `ParticipantRegistry::new_validated`.
    #[error(
        "VerifierId/VerifyingKey mismatch: claimed {claimed}, \
         derived SHA-256(signing_key) = {derived}"
    )]
    VerifierIdMismatch {
        /// The `VerifierId` stored in the entry.
        claimed: VerifierId,
        /// The `VerifierId` derived from the signing key by SHA-256.
        derived: VerifierId,
    },
}

// ── Participant registry ──────────────────────────────────────────────────────

/// A versioned, immutable snapshot of participant authorization.
///
/// The registry is the out-of-band trust anchor for:
/// - DKG key announcement verification (`to_dkg_registry()`)
/// - DKG ceremony participant admission (`check_ceremony_admission`)
/// - FROST signing participant admission (`active_verifier_keys`)
///
/// # Immutability and mutation
///
/// The registry is logically immutable once created. Mutation methods
/// (`with_revocation`, `with_key_rotation`) return a **new** registry at a
/// strictly higher epoch — the original snapshot is unchanged. This prevents
/// retroactive modification of the trust anchor that ceremonies have already
/// bound to.
///
/// # Construction
///
/// ```rust,ignore
/// let registry = ParticipantRegistry::new(
///     RegistryEpoch::GENESIS,
///     vec![
///         RegisteredParticipant::active(vid_a, vk_a, RegistryEpoch::GENESIS),
///         RegisteredParticipant::active(vid_b, vk_b, RegistryEpoch::GENESIS),
///     ],
/// )?;
/// ```
#[derive(Clone, Debug)]
pub struct ParticipantRegistry {
    epoch: RegistryEpoch,
    participants: HashMap<VerifierId, RegisteredParticipant>,
}

impl ParticipantRegistry {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Construct from an explicit list of entries at the given epoch.
    ///
    /// # Errors
    ///
    /// - `DuplicateParticipant` if the same `VerifierId` appears more than once.
    /// - `EmptyRegistry` if `entries` is empty.
    pub fn new(
        epoch: RegistryEpoch,
        entries: impl IntoIterator<Item = RegisteredParticipant>,
    ) -> Result<Self, RegistryError> {
        let mut participants: HashMap<VerifierId, RegisteredParticipant> = HashMap::new();
        for entry in entries {
            if participants.contains_key(&entry.verifier_id) {
                return Err(RegistryError::DuplicateParticipant(entry.verifier_id));
            }
            participants.insert(entry.verifier_id.clone(), entry);
        }
        if participants.is_empty() {
            return Err(RegistryError::EmptyRegistry);
        }
        Ok(Self { epoch, participants })
    }

    /// Like `new`, but also validates `VerifierId ↔ VerifyingKey` consistency
    /// for every entry by calling `RegisteredParticipant::validate_key_consistency`.
    ///
    /// Use this as the safe default when constructing a registry from externally
    /// supplied `(VerifierId, VerifyingKey)` pairs — it enforces that each
    /// `VerifierId` is exactly `SHA-256(signing_key.to_bytes())`.
    ///
    /// # Errors
    ///
    /// All errors from `new`, plus `RegistryError::VerifierIdMismatch` if any
    /// entry has an inconsistent `VerifierId`/`VerifyingKey` pair.
    pub fn new_validated(
        epoch: RegistryEpoch,
        entries: impl IntoIterator<Item = RegisteredParticipant>,
    ) -> Result<Self, RegistryError> {
        let entries_vec: Vec<RegisteredParticipant> = entries.into_iter().collect();
        for entry in &entries_vec {
            entry.validate_key_consistency()?;
        }
        Self::new(epoch, entries_vec)
    }

    /// Convenience constructor: build an all-`Active` registry from `VerifierKeyPair`s.
    ///
    /// All entries are created with `status = Active` and `added_at_epoch = epoch`.
    /// Use in tests and single-operator bootstraps where key pairs are available
    /// out-of-band. In production, use `new` with pre-validated verifying keys.
    pub fn from_key_pairs<'a>(
        epoch: RegistryEpoch,
        key_pairs: impl IntoIterator<Item = &'a crate::threshold::VerifierKeyPair>,
    ) -> Result<Self, RegistryError> {
        let entries = key_pairs.into_iter().map(|kp| RegisteredParticipant {
            verifier_id: kp.verifier_id.clone(),
            signing_key: kp.verifying_key(),
            status: ParticipantStatus::Active,
            added_at_epoch: epoch,
        });
        Self::new(epoch, entries)
    }

    // ── Getters ───────────────────────────────────────────────────────────────

    /// The epoch this registry snapshot is bound to.
    pub fn epoch(&self) -> RegistryEpoch {
        self.epoch
    }

    /// Total number of participants (including revoked and retired).
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Number of currently `Active` participants.
    pub fn active_count(&self) -> usize {
        self.participants.values().filter(|p| p.is_active()).count()
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Look up any participant (including revoked and retired).
    ///
    /// Returns `None` if the participant is not in the registry at all.
    pub fn get(&self, id: &VerifierId) -> Option<&RegisteredParticipant> {
        self.participants.get(id)
    }

    /// Look up an **`Active`** participant.
    ///
    /// Fails if the participant is unknown, `Revoked`, or `Retired`.
    /// Use this for any operation that requires the participant to be currently authorized.
    ///
    /// # Errors
    ///
    /// - `UnknownParticipant` if the `VerifierId` is not in the registry.
    /// - `RevokedParticipant` if the participant has been revoked.
    /// - `RetiredParticipant` if the participant has retired.
    pub fn get_active(&self, id: &VerifierId) -> Result<&RegisteredParticipant, RegistryError> {
        match self.participants.get(id) {
            None => Err(RegistryError::UnknownParticipant(id.clone())),
            Some(p) => match &p.status {
                ParticipantStatus::Active => Ok(p),
                ParticipantStatus::Revoked => Err(RegistryError::RevokedParticipant(id.clone())),
                ParticipantStatus::Retired => Err(RegistryError::RetiredParticipant(id.clone())),
            },
        }
    }

    /// Return the `VerifierId`s of all currently `Active` participants.
    ///
    /// Order is unspecified (HashMap iteration order). For stable ordering —
    /// needed when constructing participant lists for DKG ceremonies — sort
    /// the result.
    pub fn active_participant_ids(&self) -> Vec<VerifierId> {
        self.participants
            .values()
            .filter(|p| p.is_active())
            .map(|p| p.verifier_id.clone())
            .collect()
    }

    // ── Admission checks ─────────────────────────────────────────────────────

    /// Verify that a ceremony or signing session can proceed using this registry.
    ///
    /// Enforces:
    /// 1. `expected_epoch == self.epoch` — no stale snapshots.
    /// 2. Every `VerifierId` in `ceremony_participants` is `Active` — no revoked
    ///    or unknown participants.
    ///
    /// # When to call
    ///
    /// Call this before:
    /// - Starting a DKG ceremony (before key announcement verification).
    /// - Assembling the signer set for a FROST signing session.
    ///
    /// # Errors
    ///
    /// - `EpochMismatch` if `expected_epoch != self.epoch`.
    /// - `UnknownParticipant`, `RevokedParticipant`, or `RetiredParticipant`
    ///   for the first participant that fails the `Active` check.
    pub fn check_ceremony_admission(
        &self,
        expected_epoch: RegistryEpoch,
        ceremony_participants: &[VerifierId],
    ) -> Result<(), RegistryError> {
        if expected_epoch != self.epoch {
            return Err(RegistryError::EpochMismatch {
                expected: expected_epoch,
                actual: self.epoch,
            });
        }
        for id in ceremony_participants {
            self.get_active(id)?;
        }
        Ok(())
    }

    // ── Bridge methods ────────────────────────────────────────────────────────

    /// Build a `DkgParticipantRegistry` containing only the `Active` participants.
    ///
    /// This is the bridge between the versioned `ParticipantRegistry` and the
    /// DKG announcement-verification path. Revoked and retired participants are
    /// excluded: their signed announcements will fail the registry lookup in
    /// `verify_announcement` and return an error.
    ///
    /// Only available with the `frost` feature (which enables `DkgParticipantRegistry`).
    #[cfg(feature = "frost")]
    pub fn to_dkg_registry(&self) -> DkgParticipantRegistry {
        DkgParticipantRegistry::new(
            self.participants
                .values()
                .filter(|p| p.is_active())
                .map(|p| (p.verifier_id.clone(), p.signing_key)),
        )
    }

    /// Return `(VerifierId, VerifyingKey)` pairs for all **`Active`** participants.
    ///
    /// Use this to construct `CoordinatorConfig::verifier_public_keys` from a
    /// registry snapshot rather than a raw key list. This ensures that only
    /// currently authorized participants contribute to approval verification.
    pub fn active_verifier_keys(&self) -> Vec<(VerifierId, VerifyingKey)> {
        self.participants
            .values()
            .filter(|p| p.is_active())
            .map(|p| (p.verifier_id.clone(), p.signing_key))
            .collect()
    }

    // ── Mutation — returns new registry ───────────────────────────────────────

    /// Revoke a participant. Returns a new registry at `new_epoch` with the
    /// target participant's status set to `Revoked`.
    ///
    /// `new_epoch` must be strictly greater than `self.epoch`.
    ///
    /// # Effect on downstream users
    ///
    /// - Any ceremony or signing session that calls `check_ceremony_admission`
    ///   with the new epoch will reject the revoked participant.
    /// - A `DkgParticipantRegistry` derived from `to_dkg_registry()` on the new
    ///   snapshot will not include the revoked participant's key, so their signed
    ///   announcements will fail lookup.
    ///
    /// # Errors
    ///
    /// - `StaleRotationEpoch` if `new_epoch <= self.epoch`.
    /// - `RevocationTargetUnknown` if the participant is not in the registry.
    /// - `AlreadyRevoked` if the participant is already `Revoked`.
    pub fn with_revocation(
        &self,
        target: &VerifierId,
        new_epoch: RegistryEpoch,
    ) -> Result<ParticipantRegistry, RegistryError> {
        if new_epoch <= self.epoch {
            return Err(RegistryError::StaleRotationEpoch {
                current: self.epoch,
                new: new_epoch,
            });
        }
        let entry = self
            .participants
            .get(target)
            .ok_or_else(|| RegistryError::RevocationTargetUnknown(target.clone()))?;
        if entry.status == ParticipantStatus::Revoked {
            return Err(RegistryError::AlreadyRevoked(target.clone()));
        }
        let mut new_participants = self.participants.clone();
        let e = new_participants.get_mut(target).unwrap();
        e.status = ParticipantStatus::Revoked;
        e.added_at_epoch = new_epoch;
        Ok(ParticipantRegistry {
            epoch: new_epoch,
            participants: new_participants,
        })
    }

    /// Mark a participant as retired. Returns a new registry at `new_epoch`.
    ///
    /// Semantically identical to `with_revocation` in terms of admission
    /// enforcement; differs only in the recorded `ParticipantStatus`.
    ///
    /// # Errors
    ///
    /// - `StaleRotationEpoch` if `new_epoch <= self.epoch`.
    /// - `RevocationTargetUnknown` if the participant is not in the registry.
    pub fn with_retirement(
        &self,
        target: &VerifierId,
        new_epoch: RegistryEpoch,
    ) -> Result<ParticipantRegistry, RegistryError> {
        if new_epoch <= self.epoch {
            return Err(RegistryError::StaleRotationEpoch {
                current: self.epoch,
                new: new_epoch,
            });
        }
        if !self.participants.contains_key(target) {
            return Err(RegistryError::RevocationTargetUnknown(target.clone()));
        }
        let mut new_participants = self.participants.clone();
        let e = new_participants.get_mut(target).unwrap();
        e.status = ParticipantStatus::Retired;
        e.added_at_epoch = new_epoch;
        Ok(ParticipantRegistry {
            epoch: new_epoch,
            participants: new_participants,
        })
    }

    /// Rotate a participant's signing key. Returns a new registry at `new_epoch`
    /// with the updated key and status reset to `Active`.
    ///
    /// `new_epoch` must be strictly greater than `self.epoch`.
    ///
    /// # Effect on signed announcements from the previous epoch
    ///
    /// Old signed DKG key announcements (signed with the participant's old key)
    /// are invalid under the new epoch because:
    /// 1. `check_ceremony_admission` rejects any ceremony bound to the old epoch.
    /// 2. `to_dkg_registry()` on the new snapshot contains the **new** key; the
    ///    old announcement's signature fails verification against the new key.
    ///
    /// This ensures key rotation is a clean boundary: old announcements cannot
    /// survive into the new epoch.
    ///
    /// # Errors
    ///
    /// - `StaleRotationEpoch` if `new_epoch <= self.epoch`.
    /// - `RotationTargetUnknown` if the participant is not in the registry.
    pub fn with_key_rotation(
        &self,
        target: &VerifierId,
        new_signing_key: VerifyingKey,
        new_epoch: RegistryEpoch,
    ) -> Result<ParticipantRegistry, RegistryError> {
        if new_epoch <= self.epoch {
            return Err(RegistryError::StaleRotationEpoch {
                current: self.epoch,
                new: new_epoch,
            });
        }
        if !self.participants.contains_key(target) {
            return Err(RegistryError::RotationTargetUnknown(target.clone()));
        }
        let mut new_participants = self.participants.clone();
        let e = new_participants.get_mut(target).unwrap();
        e.signing_key = new_signing_key;
        e.status = ParticipantStatus::Active;
        e.added_at_epoch = new_epoch;
        Ok(ParticipantRegistry {
            epoch: new_epoch,
            participants: new_participants,
        })
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::VerifierKeyPair;

    fn make_kp(seed: u8) -> VerifierKeyPair {
        VerifierKeyPair::from_seed([seed; 32])
    }

    fn make_registry(n: usize) -> ParticipantRegistry {
        let kps: Vec<VerifierKeyPair> = (1u8..=(n as u8)).map(make_kp).collect();
        ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap()
    }

    // ── Construction ─────────────────────────────────────────────────────────

    #[test]
    fn new_registry_valid() {
        let r = make_registry(3);
        assert_eq!(r.epoch(), RegistryEpoch::GENESIS);
        assert_eq!(r.participant_count(), 3);
        assert_eq!(r.active_count(), 3);
    }

    #[test]
    fn new_registry_rejects_empty() {
        let result = ParticipantRegistry::new(RegistryEpoch::GENESIS, vec![]);
        assert!(matches!(result, Err(RegistryError::EmptyRegistry)));
    }

    #[test]
    fn new_registry_rejects_duplicates() {
        let kp = make_kp(1);
        let e1 = RegisteredParticipant::active(
            kp.verifier_id.clone(),
            kp.verifying_key(),
            RegistryEpoch::GENESIS,
        );
        let e2 = RegisteredParticipant::active(
            kp.verifier_id.clone(),
            kp.verifying_key(),
            RegistryEpoch::GENESIS,
        );
        let result = ParticipantRegistry::new(RegistryEpoch::GENESIS, vec![e1, e2]);
        assert!(matches!(result, Err(RegistryError::DuplicateParticipant(_))));
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    #[test]
    fn get_active_returns_active_participant() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let p = r.get_active(&kps[0].verifier_id).unwrap();
        assert!(p.is_active());
    }

    #[test]
    fn get_active_rejects_unknown() {
        let r = make_registry(3);
        let unknown_kp = make_kp(99);
        let result = r.get_active(&unknown_kp.verifier_id);
        assert!(matches!(result, Err(RegistryError::UnknownParticipant(_))));
    }

    // ── Admission ─────────────────────────────────────────────────────────────

    #[test]
    fn check_ceremony_admission_correct_epoch_all_active() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let ids: Vec<VerifierId> = kps.iter().map(|k| k.verifier_id.clone()).collect();
        assert!(r
            .check_ceremony_admission(RegistryEpoch::GENESIS, &ids)
            .is_ok());
    }

    #[test]
    fn check_ceremony_admission_wrong_epoch_rejected() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let ids: Vec<VerifierId> = kps.iter().map(|k| k.verifier_id.clone()).collect();
        let result = r.check_ceremony_admission(RegistryEpoch(1), &ids);
        assert!(matches!(result, Err(RegistryError::EpochMismatch { .. })));
    }

    #[test]
    fn check_ceremony_admission_unknown_participant_rejected() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let mut ids: Vec<VerifierId> = kps.iter().map(|k| k.verifier_id.clone()).collect();
        ids.push(make_kp(99).verifier_id); // outsider
        let result = r.check_ceremony_admission(RegistryEpoch::GENESIS, &ids);
        assert!(matches!(result, Err(RegistryError::UnknownParticipant(_))));
    }

    // ── Revocation ────────────────────────────────────────────────────────────

    #[test]
    fn revocation_produces_new_epoch() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r0 = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let r1 = r0.with_revocation(&kps[0].verifier_id, RegistryEpoch(1)).unwrap();
        assert_eq!(r1.epoch(), RegistryEpoch(1));
        // original unchanged
        assert_eq!(r0.epoch(), RegistryEpoch::GENESIS);
        assert!(r0.get_active(&kps[0].verifier_id).is_ok());
    }

    #[test]
    fn revocation_blocks_admission() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r0 = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let r1 = r0.with_revocation(&kps[0].verifier_id, RegistryEpoch(1)).unwrap();
        let result = r1.get_active(&kps[0].verifier_id);
        assert!(matches!(result, Err(RegistryError::RevokedParticipant(_))));
    }

    #[test]
    fn revocation_stale_epoch_rejected() {
        let r = make_registry(3);
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        // new_epoch == current → rejected
        let result = r.with_revocation(&kps[0].verifier_id, RegistryEpoch::GENESIS);
        assert!(matches!(result, Err(RegistryError::StaleRotationEpoch { .. })));
    }

    #[test]
    fn revocation_unknown_participant_rejected() {
        let r = make_registry(3);
        let result = r.with_revocation(&make_kp(99).verifier_id, RegistryEpoch(1));
        assert!(matches!(result, Err(RegistryError::RevocationTargetUnknown(_))));
    }

    #[test]
    fn double_revocation_rejected() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r0 = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let r1 = r0.with_revocation(&kps[0].verifier_id, RegistryEpoch(1)).unwrap();
        let result = r1.with_revocation(&kps[0].verifier_id, RegistryEpoch(2));
        assert!(matches!(result, Err(RegistryError::AlreadyRevoked(_))));
    }

    // ── Key rotation ──────────────────────────────────────────────────────────

    #[test]
    fn key_rotation_produces_new_epoch_with_new_key() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r0 = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let new_kp = make_kp(100);
        let r1 = r0
            .with_key_rotation(&kps[0].verifier_id, new_kp.verifying_key(), RegistryEpoch(1))
            .unwrap();
        assert_eq!(r1.epoch(), RegistryEpoch(1));
        // new key is active
        let p = r1.get_active(&kps[0].verifier_id).unwrap();
        assert_eq!(p.signing_key.to_bytes(), new_kp.verifying_key().to_bytes());
        // original snapshot still has old key
        let p_old = r0.get_active(&kps[0].verifier_id).unwrap();
        assert_eq!(p_old.signing_key.to_bytes(), kps[0].verifying_key().to_bytes());
    }

    #[test]
    fn key_rotation_stale_epoch_rejected() {
        let r = make_registry(3);
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let new_kp = make_kp(100);
        let result =
            r.with_key_rotation(&kps[0].verifier_id, new_kp.verifying_key(), RegistryEpoch::GENESIS);
        assert!(matches!(result, Err(RegistryError::StaleRotationEpoch { .. })));
    }

    #[test]
    fn key_rotation_unknown_participant_rejected() {
        let r = make_registry(3);
        let new_kp = make_kp(100);
        let result = r.with_key_rotation(
            &make_kp(99).verifier_id,
            new_kp.verifying_key(),
            RegistryEpoch(1),
        );
        assert!(matches!(result, Err(RegistryError::RotationTargetUnknown(_))));
    }

    // ── Bridge ────────────────────────────────────────────────────────────────

    #[test]
    fn active_verifier_keys_excludes_revoked() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r0 = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let r1 = r0.with_revocation(&kps[0].verifier_id, RegistryEpoch(1)).unwrap();
        let keys = r1.active_verifier_keys();
        assert_eq!(keys.len(), 2);
        assert!(!keys.iter().any(|(vid, _)| vid == &kps[0].verifier_id));
    }

    #[test]
    fn active_participant_ids_excludes_retired() {
        let kps: Vec<VerifierKeyPair> = (1..=3).map(make_kp).collect();
        let r0 = ParticipantRegistry::from_key_pairs(RegistryEpoch::GENESIS, &kps).unwrap();
        let r1 = r0.with_retirement(&kps[2].verifier_id, RegistryEpoch(1)).unwrap();
        let ids = r1.active_participant_ids();
        assert_eq!(ids.len(), 2);
        assert!(!ids.contains(&kps[2].verifier_id));
    }
}
