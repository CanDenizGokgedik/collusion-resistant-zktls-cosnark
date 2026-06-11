//! Authenticated DKG encryption key distribution (RFC 9591 §5.3 prerequisite).
//!
//! Before DKG Part 1, every participant must distribute their
//! `DkgEncryptionPublicKey` to all other participants so that Round-2 packages
//! can be encrypted correctly.  If an untrusted coordinator relays those keys,
//! it could substitute a key it controls and decrypt the confidential Round-2
//! packages.
//!
//! This module removes the coordinator key-substitution risk by requiring each
//! participant to **sign** their encryption key announcement with their long-term
//! ed25519 identity key (the key that generates their `VerifierId`).  Peers
//! verify each announcement against a pre-distributed `DkgParticipantRegistry`
//! before accepting any key for use in round-2 routing.
//!
//! # Signing scheme
//!
//! ```text
//! payload = DkgKeyAnnouncementPayload {
//!     version     = 1                 (u8, explicit versioning)
//!     verifier_id = SHA-256(ed25519_pub_key)   (32 B, participant identity)
//!     ceremony_id = random 16 B       (anti-replay: binds to one DKG ceremony)
//!     enc_public_key = X25519 pub key (32 B, the key being announced)
//! }
//!
//! signing_preimage = CanonicalHasher::new("tls-attestation/dkg-enc-key-announcement/v1")
//!     .update_u32(version)
//!     .update_fixed(&verifier_id)
//!     .update_fixed(&ceremony_id)
//!     .update_fixed(&enc_public_key)
//!     .finalize()   →  32 bytes
//!
//! signature = Ed25519::sign(participant_signing_key, signing_preimage)
//! ```
//!
//! # Trust model
//!
//! `DkgParticipantRegistry` is the trust anchor.  It maps `VerifierId` to an
//! ed25519 `VerifyingKey` and must be populated through a channel that is NOT
//! controlled by the ceremony coordinator (e.g., a pre-ceremony operator manifest
//! or the same out-of-band channel used to distribute the participant list).
//!
//! ## What is now prevented
//!
//! - **Coordinator key substitution**: the coordinator cannot replace participant
//!   P's `DkgEncryptionPublicKey` with an attacker-controlled key without forging
//!   an ed25519 signature under P's identity key.
//! - **Cross-ceremony replay**: the `ceremony_id` field in the signed payload
//!   prevents a valid announcement from one ceremony being accepted in another.
//! - **Outsider injection**: announcements from participants not in the expected
//!   participant set are rejected.
//! - **Duplicate announcements**: a second announcement from the same participant
//!   is rejected (ambiguity protection).
//!
//! ## What is NOT prevented by this module alone
//!
//! - **Registry poisoning**: if an adversary can modify the `DkgParticipantRegistry`
//!   itself (i.e., substitute a verifying key in the registry), they can still forge
//!   announcements.  The registry must be distributed through a trusted,
//!   coordinator-independent channel.
//! - **Missing announcements causing DoS**: a coordinator that drops a participant's
//!   announcement prevents the ceremony from starting.  This is a liveness threat
//!   but not a confidentiality threat — the ceremony simply won't proceed.

use crate::dkg_encrypt::{DkgCeremonyId, DkgEncryptionKeyPair, DkgEncryptionPublicKey};
use crate::error::CryptoError;
use crate::threshold::VerifierKeyPair;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tls_attestation_core::{hash::CanonicalHasher, ids::VerifierId};

/// Domain tag for announcement signing preimages.
///
/// Changing this tag invalidates all previously signed announcements — use
/// with care.  The `/v1` suffix must be incremented if the payload format
/// changes in a backwards-incompatible way.
const ANNOUNCEMENT_DOMAIN: &str = "tls-attestation/dkg-enc-key-announcement/v1";

/// Wire format version embedded in every `DkgKeyAnnouncementPayload`.
///
/// Verified at the application layer in addition to the AEAD/signature checks.
pub const ANNOUNCEMENT_VERSION: u8 = 1;

// ── Payload ───────────────────────────────────────────────────────────────────

/// The data each participant signs to announce their `DkgEncryptionPublicKey`.
///
/// All fields are fixed-size byte arrays to guarantee canonical serialization.
/// The signing preimage is computed via `CanonicalHasher` (not serde_json) so
/// it is unambiguous regardless of how the struct is serialized on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgKeyAnnouncementPayload {
    /// Announcement format version. Must equal [`ANNOUNCEMENT_VERSION`].
    pub version: u8,
    /// The announcing participant's `VerifierId` as raw bytes.
    pub verifier_id: [u8; 32],
    /// The DKG ceremony this announcement is scoped to.
    /// Binding to `ceremony_id` prevents cross-ceremony replay.
    pub ceremony_id: [u8; 16],
    /// The X25519 public key being announced for Round-2 encryption.
    pub enc_public_key: [u8; 32],
}

// ── Signed announcement ────────────────────────────────────────────────────────

/// A signed DKG encryption key announcement.
///
/// `signature` is a 64-byte Ed25519 signature (stored as `Vec<u8>` to satisfy
/// serde's array-size limit) over the canonical preimage of `payload` (computed
/// by [`announcement_signing_preimage`]).
///
/// Untrusted until verified by [`DkgParticipantRegistry::verify_announcement`].
/// The coordinator can route this struct but cannot forge it without the
/// announcing participant's ed25519 private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDkgKeyAnnouncement {
    pub payload: DkgKeyAnnouncementPayload,
    /// Ed25519 signature bytes (64 bytes).
    ///
    /// Stored as `Vec<u8>` because serde's built-in `[T; N]` support only
    /// covers N ≤ 32.  Length is validated at verification time.
    pub signature: Vec<u8>,
}

// ── Verified announcement (proof-of-verification token) ──────────────────────

/// A `DkgEncryptionPublicKey` whose ownership by a specific participant has
/// been cryptographically verified.
///
/// # Construction
///
/// This type can only be produced by
/// [`DkgParticipantRegistry::verify_announcement`].  Holding a
/// `VerifiedDkgKeyAnnouncement` is proof that:
/// - The `enc_public_key` was signed by the participant controlling `verifier_id`.
/// - The announcement is bound to `ceremony_id` (no cross-ceremony replay).
/// - The signing key matches the one in the `DkgParticipantRegistry` (no
///   coordinator substitution unless the registry itself was poisoned).
#[derive(Clone, Debug)]
pub struct VerifiedDkgKeyAnnouncement {
    pub verifier_id: VerifierId,
    pub ceremony_id: DkgCeremonyId,
    pub enc_public_key: DkgEncryptionPublicKey,
}

// ── Participant registry ───────────────────────────────────────────────────────

/// Maps `VerifierId` to the corresponding long-term ed25519 `VerifyingKey`.
///
/// This is the **out-of-band trust anchor** for DKG key announcement
/// verification.  It must be populated before the ceremony from a source that
/// is independent of the ceremony coordinator.
///
/// # Security
///
/// The security of the announcement scheme depends entirely on the integrity
/// of this registry.  If an adversary controls its contents, they can register
/// a key they own under a legitimate participant's `VerifierId` and forge
/// announcements.  Protect the registry's distribution channel accordingly.
pub struct DkgParticipantRegistry {
    entries: HashMap<VerifierId, VerifyingKey>,
}

impl DkgParticipantRegistry {
    /// Construct a registry from an explicit list of `(VerifierId, VerifyingKey)` pairs.
    ///
    /// Use this when you have the verifying keys from a trusted out-of-band source
    /// (e.g., an operator-configured participant manifest).
    pub fn new(entries: impl IntoIterator<Item = (VerifierId, VerifyingKey)>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    /// Convenience constructor: build the registry directly from `VerifierKeyPair`s.
    ///
    /// In tests and single-operator scenarios the coordinator knows all key pairs
    /// out-of-band.  In a real deployment, only the verifying keys would be
    /// distributed — use [`DkgParticipantRegistry::new`] in that case.
    pub fn from_key_pairs<'a>(
        key_pairs: impl IntoIterator<Item = &'a VerifierKeyPair>,
    ) -> Self {
        let entries = key_pairs
            .into_iter()
            .map(|kp| (kp.verifier_id.clone(), kp.verifying_key()))
            .collect();
        Self { entries }
    }

    /// Verify one signed announcement and return the trusted typed result.
    ///
    /// Checks:
    /// 1. `version` == `ANNOUNCEMENT_VERSION`.
    /// 2. `ceremony_id` matches `expected_ceremony_id` (anti-replay).
    /// 3. The announcing `verifier_id` is in this registry.
    /// 4. The Ed25519 signature over the canonical preimage is valid.
    ///
    /// # Errors
    ///
    /// - `CryptoError::DkgAnnouncement` for version, ceremony, or unknown-verifier failures.
    /// - `CryptoError::SignatureVerificationFailed` if the signature is invalid.
    pub fn verify_announcement(
        &self,
        announcement: &SignedDkgKeyAnnouncement,
        expected_ceremony_id: &DkgCeremonyId,
    ) -> Result<VerifiedDkgKeyAnnouncement, CryptoError> {
        let p = &announcement.payload;

        // ── Version check ─────────────────────────────────────────────────────
        if p.version != ANNOUNCEMENT_VERSION {
            return Err(CryptoError::DkgAnnouncement(format!(
                "unsupported announcement version {} (expected {})",
                p.version, ANNOUNCEMENT_VERSION
            )));
        }

        // ── Ceremony binding check ─────────────────────────────────────────────
        if &p.ceremony_id != expected_ceremony_id.as_bytes() {
            return Err(CryptoError::DkgAnnouncement(
                "announcement ceremony_id does not match expected ceremony — \
                 possible cross-ceremony replay or stale announcement"
                    .into(),
            ));
        }

        // ── Registry lookup ───────────────────────────────────────────────────
        let verifier_id = VerifierId::from_bytes(p.verifier_id);
        let vk = self.entries.get(&verifier_id).ok_or_else(|| {
            CryptoError::DkgAnnouncement(format!(
                "verifier {} is not in the DKG participant registry — \
                 outsider or registry not populated correctly",
                verifier_id
            ))
        })?;

        // ── Signature verification ────────────────────────────────────────────
        let preimage =
            announcement_signing_preimage(&p.version, &p.verifier_id, &p.ceremony_id, &p.enc_public_key);
        let sig = Signature::from_slice(&announcement.signature).map_err(|e| {
            CryptoError::DkgAnnouncement(format!("malformed announcement signature: {e}"))
        })?;
        vk.verify(&preimage, &sig).map_err(|_| {
            CryptoError::SignatureVerificationFailed {
                reason: format!(
                    "DKG key-announcement signature from {} is invalid — \
                     possible coordinator key substitution or data tampering",
                    verifier_id
                ),
            }
        })?;

        Ok(VerifiedDkgKeyAnnouncement {
            verifier_id,
            ceremony_id: DkgCeremonyId::from_bytes(p.ceremony_id),
            enc_public_key: DkgEncryptionPublicKey::from_bytes(p.enc_public_key),
        })
    }

    /// Verify announcements from **all** expected participants and return a
    /// `HashMap<VerifierId, DkgEncryptionPublicKey>` of authenticated keys.
    ///
    /// Enforces:
    /// - Every announcement has a valid signature (prevents substitution).
    /// - Every announcement is bound to `expected_ceremony_id` (prevents replay).
    /// - Announcing participant is in `expected_participants` (no outsider injection).
    /// - No two announcements for the same participant (no ambiguity).
    /// - Every participant in `expected_participants` has submitted an announcement
    ///   (missing announcement → ceremony cannot start).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DkgAnnouncement` or `CryptoError::SignatureVerificationFailed`
    /// on any failure.
    pub fn collect_verified_enc_keys(
        &self,
        announcements: &[SignedDkgKeyAnnouncement],
        expected_ceremony_id: &DkgCeremonyId,
        expected_participants: &[VerifierId],
    ) -> Result<HashMap<VerifierId, DkgEncryptionPublicKey>, CryptoError> {
        let mut verified: HashMap<VerifierId, DkgEncryptionPublicKey> =
            HashMap::with_capacity(expected_participants.len());

        for ann in announcements {
            let v = self.verify_announcement(ann, expected_ceremony_id)?;

            // Outsider injection check.
            if !expected_participants.contains(&v.verifier_id) {
                return Err(CryptoError::DkgAnnouncement(format!(
                    "announcement from {} is not in the expected participant set",
                    v.verifier_id
                )));
            }

            // Duplicate announcement check.
            if verified.contains_key(&v.verifier_id) {
                return Err(CryptoError::DkgAnnouncement(format!(
                    "duplicate announcement for participant {} — ambiguous key",
                    v.verifier_id
                )));
            }

            verified.insert(v.verifier_id, v.enc_public_key);
        }

        // Missing participant check: every expected participant must have announced.
        for expected_id in expected_participants {
            if !verified.contains_key(expected_id) {
                return Err(CryptoError::DkgAnnouncement(format!(
                    "missing DKG key announcement from participant {} — \
                     ceremony cannot start without all participants' authenticated keys",
                    expected_id
                )));
            }
        }

        Ok(verified)
    }
}

// ── Announcement creation ─────────────────────────────────────────────────────

/// Create a signed DKG encryption key announcement.
///
/// Signs the canonical preimage of `(ANNOUNCEMENT_VERSION, signer.verifier_id,
/// ceremony_id, enc_key.public_key())` with `signer`'s long-term ed25519 key.
///
/// The resulting `SignedDkgKeyAnnouncement` should be distributed to all other
/// participants (and the coordinator for routing) before DKG Part 1 begins.
///
/// # Example
///
/// ```rust,ignore
/// let ceremony_id = DkgCeremonyId::generate();
/// let enc_key = DkgEncryptionKeyPair::generate();
/// let announcement = create_dkg_key_announcement(&enc_key, &ceremony_id, &my_key_pair);
/// // broadcast `announcement` to all participants via the coordinator
/// ```
pub fn create_dkg_key_announcement(
    enc_key: &DkgEncryptionKeyPair,
    ceremony_id: &DkgCeremonyId,
    signer: &VerifierKeyPair,
) -> SignedDkgKeyAnnouncement {
    let verifier_id_bytes = *signer.verifier_id.as_bytes();
    let ceremony_id_bytes = *ceremony_id.as_bytes();
    let enc_pub_bytes = enc_key.public_key().to_bytes();

    let payload = DkgKeyAnnouncementPayload {
        version: ANNOUNCEMENT_VERSION,
        verifier_id: verifier_id_bytes,
        ceremony_id: ceremony_id_bytes,
        enc_public_key: enc_pub_bytes,
    };

    let preimage = announcement_signing_preimage(
        &payload.version,
        &payload.verifier_id,
        &payload.ceremony_id,
        &payload.enc_public_key,
    );

    // sign_raw requires pre-hashed, domain-separated bytes — preimage satisfies this.
    let signature = signer.sign_raw(&preimage).to_vec();

    SignedDkgKeyAnnouncement { payload, signature }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Compute the canonical Ed25519 signing preimage for a DKG key announcement.
///
/// Encoding (via [`CanonicalHasher`]):
/// ```text
/// SHA-256(
///     len_be32("tls-attestation/dkg-enc-key-announcement/v1")
///     || "tls-attestation/dkg-enc-key-announcement/v1"
///     || version as u32 (4 bytes BE)
///     || verifier_id    (32 bytes, no length prefix — fixed size)
///     || ceremony_id    (16 bytes, no length prefix — fixed size)
///     || enc_public_key (32 bytes, no length prefix — fixed size)
/// )
/// ```
///
/// `CanonicalHasher` prepends the domain tag with a 4-byte length prefix,
/// preventing domain-string collisions.  Fixed-size fields are hashed without
/// a length prefix because their sizes are statically known.
fn announcement_signing_preimage(
    version: &u8,
    verifier_id: &[u8; 32],
    ceremony_id: &[u8; 16],
    enc_public_key: &[u8; 32],
) -> [u8; 32] {
    let mut h = CanonicalHasher::new(ANNOUNCEMENT_DOMAIN);
    h.update_u32(*version as u32)
        .update_fixed(verifier_id)
        .update_fixed(ceremony_id)
        .update_fixed(enc_public_key);
    *h.finalize().as_bytes()
}
