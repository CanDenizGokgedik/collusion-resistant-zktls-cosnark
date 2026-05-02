//! Real FROST (RFC 9591) threshold signing adapter.
//!
//! This module provides a production-ready FROST signing path using the
//! `frost-ed25519` crate (ZF FROST implementation). It is only compiled when
//! the `frost` feature is enabled.
//!
//! # What FROST provides
//!
//! FROST is a **two-round** threshold Schnorr signature scheme:
//!
//! - Round 1: each participant generates a nonce and broadcasts commitments.
//! - Round 2: the coordinator assembles a `SigningPackage` from all commitments
//!   and the message; each participant signs and returns a share.
//! - Aggregation: the coordinator combines `t` valid shares into a single
//!   64-byte Schnorr signature verifiable against the group public key.
//!
//! Unlike the prototype (`PrototypeThresholdSigner`), the aggregate signature:
//! - Does NOT reveal which participants signed.
//! - Is indistinguishable from a standard Ed25519 signature.
//! - Provides true (t,n)-threshold security: an adversary who compromises
//!   fewer than `t` signers learns nothing about the group key.
//!
//! # FROST protocol constraints (RFC 9591 §B.1)
//!
//! - `threshold (min_signers) >= 2`: FROST cannot model 1-of-n. For
//!   single-key use cases, use a regular Ed25519 key.
//! - `n (max_signers) >= 2`: Only meaningful with at least two participants.
//!
//! # Nonce safety
//!
//! **Critical**: nonces from `FrostParticipant::round1` MUST NOT be reused.
//! Nonce reuse in Schnorr threshold signing leaks the participant's secret share.
//!
//! This module enforces single-use through Rust move semantics:
//! - `FrostSigningNonces` is `!Clone` (the inner `frost_ed25519::round1::SigningNonces` is `!Clone`).
//! - `FrostParticipant::round2` takes nonces by value — they are consumed and
//!   cannot be used again.
//!
//! # Key generation warning
//!
//! `frost_trusted_dealer_keygen` uses a **trusted dealer**: one party generates
//! all key shares and knows the group secret key. This violates the
//! collusion-minimized threat model and is **NOT safe for production**.
//! Use it only for in-process tests and single-machine demos.
//!
//! Production deployments must use a Pedersen DKG (see `keys::dkg` module in
//! `frost-ed25519`) where no party ever sees the full group secret.
//!
//! # Signing preimage
//!
//! All FROST approvals sign the output of
//! `tls_attestation_crypto::threshold::approval_signed_digest(envelope_digest)`:
//!
//! ```text
//! signed_msg = SHA256(
//!     len_be32("tls-attestation/threshold-approval/v1")
//!     || "tls-attestation/threshold-approval/v1"
//!     || envelope_digest[32 bytes]
//! )
//! ```
//!
//! This ensures domain separation and binds the approval to the specific
//! attestation envelope. Callers MUST pass the output of
//! `approval_signed_digest` — not raw `envelope_digest` bytes.

use crate::error::CryptoError;
use frost_ed25519 as frost;
use std::collections::{BTreeMap, HashMap, HashSet};
use tls_attestation_core::{hash::DigestBytes, ids::VerifierId, types::QuorumSpec};

// ── Type imports ──────────────────────────────────────────────────────────────

use frost::keys::{KeyPackage, PublicKeyPackage, SecretShare};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};

// ── Nonce wrapper ─────────────────────────────────────────────────────────────

/// Nonces produced in Round 1 for exactly one signing session.
///
/// # Nonce reuse prevention
///
/// `FrostSigningNonces` is `!Clone` because the inner
/// `frost_ed25519::round1::SigningNonces` is `!Clone`. Rust's move semantics
/// ensure that once you pass a `FrostSigningNonces` to `FrostParticipant::round2`,
/// the value is consumed and cannot be reused — preventing the catastrophic
/// key-share leakage that nonce reuse causes in Schnorr signatures.
pub struct FrostSigningNonces(SigningNonces);

// Compiler-enforced: NOT Clone, NOT Copy.

// ── Commitment ────────────────────────────────────────────────────────────────

/// Round-1 output broadcast by a participant to the coordinator.
///
/// The coordinator collects one commitment per participant, assembles them into
/// a `FrostSigningPackage`, then distributes that package to trigger Round 2.
#[derive(Clone)]
pub struct FrostCommitment {
    pub(crate) identifier: Identifier,
    pub(crate) inner: SigningCommitments,
}

// ── Signature share ───────────────────────────────────────────────────────────

/// Round-2 output: one participant's partial signature.
///
/// The coordinator aggregates `t` valid shares into a single Schnorr signature.
#[derive(Clone)]
pub struct FrostSignatureShare {
    pub(crate) identifier: Identifier,
    pub(crate) inner: SignatureShare,
}

// ── Signing package ───────────────────────────────────────────────────────────

/// The message and commitment set distributed to participants to trigger Round 2.
///
/// Assembled by the coordinator from all Round-1 commitments.
/// Contains the message (the signed_digest bytes) that each participant must sign.
pub struct FrostSigningPackage {
    pub(crate) inner: SigningPackage,
}

// ── Group key ─────────────────────────────────────────────────────────────────

/// The FROST group public key and participant-identity mapping.
///
/// Public data — contains no secret material. Shared among all participants,
/// the coordinator, and any external verifier.
///
/// The `verifier_to_id` map translates between the protocol's `VerifierId`
/// (a 32-byte identity derived from a participant's signing key) and the
/// FROST `Identifier` (a 1-indexed u16 used internally by frost-ed25519).
#[derive(Clone)]
pub struct FrostGroupKey {
    pub_key_package: PublicKeyPackage,
    /// Protocol VerifierId → FROST Identifier (1-indexed u16).
    ///
    /// Order is fixed at key-generation time and must not change.
    /// Uses `HashMap` because `VerifierId` implements `Hash + Eq` but not `Ord`.
    verifier_to_id: HashMap<VerifierId, Identifier>,
}

impl FrostGroupKey {
    /// Look up the FROST identifier for a given protocol verifier.
    pub fn verifier_to_identifier(&self, vid: &VerifierId) -> Option<&Identifier> {
        self.verifier_to_id.get(vid)
    }

    /// The 32-byte compressed Ed25519 group verifying key.
    ///
    /// External verifiers use this to verify `FrostThresholdApproval`s.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.pub_key_package.verifying_key().serialize()
    }

    /// Construct from already-validated parts.
    ///
    /// Used by the Pedersen DKG adapter (`crates/crypto/src/dkg.rs`) to build
    /// a `FrostGroupKey` from `PublicKeyPackage` output of `keys::dkg::part3`.
    /// Not exposed outside this crate — callers must go through `frost_trusted_dealer_keygen`
    /// or the DKG functions.
    pub(crate) fn new_from_parts(
        pub_key_package: PublicKeyPackage,
        verifier_to_id: HashMap<VerifierId, Identifier>,
    ) -> Self {
        Self { pub_key_package, verifier_to_id }
    }

    /// Serialize the group public key to JSON bytes for disk / wire.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        #[derive(serde::Serialize)]
        struct GroupKeyExport<'a> {
            pub_key_package: &'a PublicKeyPackage,
            verifier_map: Vec<(String, String)>, // (verifier_id_hex, identifier_hex)
        }
        let verifier_map: Vec<(String, String)> = self
            .verifier_to_id
            .iter()
            .map(|(vid, id)| {
                (hex::encode(vid.as_bytes()), hex::encode(id.serialize()))
            })
            .collect();
        let export = GroupKeyExport { pub_key_package: &self.pub_key_package, verifier_map };
        serde_json::to_vec_pretty(&export)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("serialize group key: {e}")))
    }

    /// Reconstruct a `FrostGroupKey` from JSON bytes produced by [`to_json_bytes`].
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        #[derive(serde::Deserialize)]
        struct GroupKeyExport {
            pub_key_package: PublicKeyPackage,
            verifier_map: Vec<(String, String)>,
        }
        let export: GroupKeyExport = serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("deserialize group key: {e}")))?;
        let mut verifier_to_id = HashMap::new();
        for (vid_hex, id_hex) in export.verifier_map {
            let vid_bytes = hex::decode(&vid_hex)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("decode vid hex: {e}")))?;
            let vid_arr: [u8; 32] = vid_bytes.try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial("verifier_id must be 32 bytes".into()))?;
            let id_bytes = hex::decode(&id_hex)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("decode id hex: {e}")))?;
            let id_arr: [u8; 32] = id_bytes.try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial("identifier must be 32 bytes".into()))?;
            let id = Identifier::deserialize(&id_arr)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("deserialize identifier: {e}")))?;
            verifier_to_id.insert(VerifierId::from_bytes(vid_arr), id);
        }
        Ok(Self { pub_key_package: export.pub_key_package, verifier_to_id })
    }

    }

// ── Participant ───────────────────────────────────────────────────────────────

/// A FROST participant: holds a key share and executes both protocol rounds.
///
/// One `FrostParticipant` per auxiliary verifier. Contains secret key material.
///
/// # Security
///
/// Treat `FrostParticipant` like a private key. Never log, serialize to
/// untrusted storage, or transmit it over an unauthenticated channel.
pub struct FrostParticipant {
    key_package: KeyPackage,
    identifier: Identifier,
    /// This participant's protocol-level identity.
    pub verifier_id: VerifierId,
}

impl FrostParticipant {
    /// Round 1: generate fresh nonces and public commitments.
    ///
    /// Call this once per signing session. The returned `FrostSigningNonces`
    /// are consumed by `round2` and cannot be reused (enforced by the type
    /// system). The `FrostCommitment` is broadcast to the coordinator.
    ///
    /// The nonces are generated from the OS CSPRNG — do not replace with a
    /// deterministic RNG in production.
    pub fn round1<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (FrostSigningNonces, FrostCommitment) {
        let (nonces, commitments) = frost::round1::commit(self.key_package.signing_share(), rng);
        (
            FrostSigningNonces(nonces),
            FrostCommitment {
                identifier: self.identifier,
                inner: commitments,
            },
        )
    }

    /// Deterministic round-1 nonce generation for DVRF evaluation.
    ///
    /// Unlike `round1` (which uses a random nonce), this method derives the
    /// nonce deterministically from `H("dvrf-nonce-seed/v1" || key_package_bytes || alpha)`.
    pub fn round1_dvrf(&self, alpha: &[u8]) -> (FrostSigningNonces, FrostCommitment) {
        use rand::SeedableRng;
        let seed = self.dvrf_nonce_seed(alpha);
        let mut seeded_rng = rand::rngs::StdRng::from_seed(seed);
        self.round1(&mut seeded_rng)
    }

    /// Derive a deterministic nonce seed from the key package and α.
    fn dvrf_nonce_seed(&self, alpha: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let key_bytes = serde_json::to_vec(&self.key_package)
            .expect("KeyPackage is always JSON-serializable");
        let mut h = sha2::Sha256::new();
        h.update(b"tls-attestation/dvrf-nonce-seed/v1\x00");
        h.update((key_bytes.len() as u64).to_be_bytes());
        h.update(&key_bytes);
        h.update((alpha.len() as u64).to_be_bytes());
        h.update(alpha);
        h.finalize().into()
    }

    /// Round 2: produce a partial signature.
    ///
    /// `nonces` must be the ones produced by *this* participant's `round1`
    /// call for *this* session. The nonces are consumed (moved into this call)
    /// — after `round2` returns, they are gone and cannot be reused.
    ///
    /// The `signing_package` must be the one assembled by the coordinator from
    /// all Round-1 commitments. Using a signing package from a different session
    /// is detected and rejected by the FROST library.
    pub fn round2(
        &self,
        signing_package: &FrostSigningPackage,
        nonces: FrostSigningNonces,
    ) -> Result<FrostSignatureShare, CryptoError> {
        // `nonces.0` is moved here; the FrostSigningNonces wrapper is consumed.
        frost::round2::sign(&signing_package.inner, &nonces.0, &self.key_package)
            .map(|share| FrostSignatureShare {
                identifier: self.identifier,
                inner: share,
            })
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))
    }

    pub fn verifier_id(&self) -> &VerifierId {
        &self.verifier_id
    }

    /// Construct from already-validated key material.
    ///
    /// Used by the Pedersen DKG adapter (`crates/crypto/src/dkg.rs`) to build
    /// a `FrostParticipant` from `KeyPackage` output of `keys::dkg::part3`.
    /// Not exposed outside this crate — callers must go through `frost_trusted_dealer_keygen`
    /// or the DKG functions.
    pub(crate) fn new_from_key_package(
        key_package: KeyPackage,
        identifier: Identifier,
        verifier_id: VerifierId,
    ) -> Self {
        Self { key_package, identifier, verifier_id }
    }

    // ── Key persistence ────────────────────────────────────────────────────

    /// Serialize this participant's key material to JSON bytes for disk storage.
    ///
    /// # Security
    /// The output contains the secret signing share. Encrypt before writing to
    /// disk. Never transmit over an unauthenticated channel.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        #[derive(serde::Serialize)]
        struct ParticipantExport<'a> {
            key_package: &'a KeyPackage,
            identifier_hex: String,
            verifier_id_hex: String,
        }
        let id_bytes = self.identifier.serialize();
        let export = ParticipantExport {
            key_package: &self.key_package,
            identifier_hex: hex::encode(id_bytes),
            verifier_id_hex: hex::encode(self.verifier_id.as_bytes()),
        };
        serde_json::to_vec_pretty(&export)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("serialize participant: {e}")))
    }

    /// Reconstruct a `FrostParticipant` from JSON bytes previously produced by
    /// [`to_json_bytes`].
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        #[derive(serde::Deserialize)]
        struct ParticipantExport {
            key_package: KeyPackage,
            identifier_hex: String,
            verifier_id_hex: String,
        }
        let export: ParticipantExport = serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("deserialize participant: {e}")))?;

        let id_bytes = hex::decode(&export.identifier_hex)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("decode identifier hex: {e}")))?;
        let id_arr: [u8; 32] = id_bytes.try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial("identifier must be 32 bytes".into()))?;
        let identifier = Identifier::deserialize(&id_arr)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("deserialize identifier: {e}")))?;

        let vid_bytes = hex::decode(&export.verifier_id_hex)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("decode verifier_id hex: {e}")))?;
        let vid_arr: [u8; 32] = vid_bytes.try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial("verifier_id must be 32 bytes".into()))?;
        let verifier_id = VerifierId::from_bytes(vid_arr);

        Ok(Self::new_from_key_package(export.key_package, identifier, verifier_id))
    }
}

// ── Trusted-dealer key generation ─────────────────────────────────────────────

/// Output of the trusted-dealer key generation ceremony.
///
/// # WARNING: NOT PRODUCTION-SAFE
///
/// `frost_trusted_dealer_keygen` uses a **trusted dealer**: one process
/// generates all key shares, meaning it temporarily holds the full group
/// secret key. This violates the collusion-minimized threat model.
///
/// This is appropriate only for:
/// - In-process tests
/// - Single-machine demos
/// - Benchmarks
///
/// Production deployments MUST use a Pedersen DKG where no single party
/// ever reconstructs the full group secret key.
pub struct TrustedDealerKeygenOutput {
    /// One participant per entry in the original `verifier_ids` slice.
    pub participants: Vec<FrostParticipant>,
    /// Group public key and identity mapping for this quorum.
    pub group_key: FrostGroupKey,
}

/// Trusted-dealer key generation for FROST(Ed25519, SHA-512).
///
/// Assigns FROST identifiers `1..=n` to participants in the order given.
/// The mapping is deterministic: participant `verifier_ids[i]` always gets
/// FROST identifier `i+1`.
///
/// # Constraints
///
/// - `threshold >= 2`: FROST requires at least 2 signers (RFC 9591 §B.1).
///   Use a regular Ed25519 key for single-signer scenarios.
/// - `verifier_ids.len() >= 2`: at least two participants.
/// - `threshold <= verifier_ids.len()`: threshold cannot exceed the quorum.
///
/// # WARNING
///
/// See `TrustedDealerKeygenOutput` — this is NOT safe for production.
pub fn frost_trusted_dealer_keygen(
    verifier_ids: &[VerifierId],
    threshold: usize,
) -> Result<TrustedDealerKeygenOutput, CryptoError> {
    use rand::rngs::OsRng;

    let n = verifier_ids.len();

    if n < 2 {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "FROST requires at least 2 participants (got {n})"
        )));
    }
    if threshold < 2 {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "FROST requires threshold >= 2 (got {threshold})"
        )));
    }
    if threshold > n {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "threshold {threshold} exceeds participant count {n}"
        )));
    }
    if verifier_ids.len() != verifier_ids.iter().collect::<HashSet<_>>().len() {
        return Err(CryptoError::InvalidKeyMaterial(
            "verifier_ids must not contain duplicates".into(),
        ));
    }

    // Build identifiers 1..=n. The frost-core library enforces u16 range and
    // non-zero values — both are satisfied since n <= u16::MAX and we start at 1.
    let identifiers: Vec<Identifier> = (1u16..=(n as u16))
        .map(|i| Identifier::try_from(i).expect("1..=n is a valid non-zero u16"))
        .collect();

    let id_list = frost::keys::IdentifierList::Custom(identifiers.as_slice());

    let (shares, pub_key_package) = frost::keys::generate_with_dealer(
        n as u16,
        threshold as u16,
        id_list,
        &mut OsRng,
    )
    .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;

    // Convert shares to key packages and build the VerifierId mapping.
    let mut verifier_to_id: HashMap<VerifierId, Identifier> = HashMap::new();
    let mut participants: Vec<FrostParticipant> = Vec::new();

    for (idx, verifier_id) in verifier_ids.iter().enumerate() {
        let frost_id = identifiers[idx];

        let secret_share: SecretShare = shares
            .get(&frost_id)
            .ok_or_else(|| {
                CryptoError::InvalidKeyMaterial(format!(
                    "missing share for FROST identifier {idx}"
                ))
            })?
            .clone();

        let key_package = KeyPackage::try_from(secret_share)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;

        verifier_to_id.insert(verifier_id.clone(), frost_id);
        participants.push(FrostParticipant {
            key_package,
            identifier: frost_id,
            verifier_id: verifier_id.clone(),
        });
    }

    let group_key = FrostGroupKey {
        pub_key_package,
        verifier_to_id,
    };

    Ok(TrustedDealerKeygenOutput { participants, group_key })
}

// ── FROST threshold approval ──────────────────────────────────────────────────

/// A threshold approval produced by the FROST signing protocol.
///
/// Contains a single 64-byte aggregate Schnorr signature verifiable against
/// the group verifying key — indistinguishable from a regular Ed25519 signature.
///
/// # Replay protection
///
/// `signed_digest` binds this approval to a specific attestation envelope via:
/// ```text
/// signed_digest = SHA256(domain_tag || envelope_digest)
/// ```
/// A valid approval for envelope A cannot be replayed for envelope B.
///
/// # Verification
///
/// 1. Verify `group_verifying_key_bytes` matches the expected group key for
///    the quorum (from configuration — do NOT accept an unknown key).
/// 2. Call `verify_signature()` to check the aggregate signature.
/// 3. Optionally verify that `signed_digest` matches
///    `approval_signed_digest(expected_envelope_digest)`.
#[derive(Clone, Debug)]
pub struct FrostThresholdApproval {
    /// The exact bytes that were signed:
    /// `approval_signed_digest(envelope_digest)`.
    pub signed_digest: DigestBytes,
    /// The 64-byte aggregate Schnorr signature over `signed_digest`.
    pub aggregate_signature_bytes: [u8; 64],
    /// The 32-byte compressed Ed25519 group verifying key.
    ///
    /// IMPORTANT: consumers MUST verify this matches the expected group key
    /// from their quorum configuration before accepting this approval.
    pub group_verifying_key_bytes: [u8; 32],
}

impl serde::Serialize for FrostThresholdApproval {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("FrostThresholdApproval", 3)?;
        st.serialize_field("signed_digest", &self.signed_digest)?;
        st.serialize_field("aggregate_signature_hex", &hex::encode(self.aggregate_signature_bytes))?;
        st.serialize_field("group_verifying_key_hex", &hex::encode(self.group_verifying_key_bytes))?;
        st.end()
    }
}

impl<'de> serde::Deserialize<'de> for FrostThresholdApproval {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Raw {
            signed_digest: DigestBytes,
            aggregate_signature_hex: String,
            group_verifying_key_hex: String,
        }
        let raw = Raw::deserialize(d)?;
        let sig_bytes = hex::decode(&raw.aggregate_signature_hex)
            .map_err(serde::de::Error::custom)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into()
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))?;
        let key_bytes = hex::decode(&raw.group_verifying_key_hex)
            .map_err(serde::de::Error::custom)?;
        let key_arr: [u8; 32] = key_bytes.try_into()
            .map_err(|_| serde::de::Error::custom("verifying key must be 32 bytes"))?;
        Ok(Self {
            signed_digest: raw.signed_digest,
            aggregate_signature_bytes: sig_arr,
            group_verifying_key_bytes: key_arr,
        })
    }
}

impl FrostThresholdApproval {
    /// Verify the aggregate signature over `signed_digest` using the embedded
    /// group verifying key.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the aggregate Schnorr signature is cryptographically valid.
    /// `Err(_)` if the key bytes are malformed or the signature is invalid.
    ///
    /// # Security note
    ///
    /// This check alone is NOT sufficient for acceptance. The caller MUST
    /// independently verify that `group_verifying_key_bytes` matches the
    /// expected group key for the quorum. An attacker who controls the approval
    /// could substitute a different key and produce a valid signature under it.
    pub fn verify_signature(&self) -> Result<(), CryptoError> {
        let vk = frost::VerifyingKey::deserialize(self.group_verifying_key_bytes)
            .map_err(|e| CryptoError::SignatureVerificationFailed {
                reason: format!("invalid group verifying key: {e}"),
            })?;

        let sig = frost::Signature::deserialize(self.aggregate_signature_bytes)
            .map_err(|e| CryptoError::SignatureVerificationFailed {
                reason: format!("malformed aggregate signature: {e}"),
            })?;

        vk.verify(self.signed_digest.as_bytes(), &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed {
                reason: "FROST aggregate signature is invalid".into(),
            })
    }

    /// Verify that `signed_digest` is the canonical preimage for the given
    /// `envelope_digest`.
    ///
    /// This binds the approval to a specific attestation envelope.
    pub fn verify_binding(
        &self,
        envelope_digest: &DigestBytes,
    ) -> Result<(), CryptoError> {
        use crate::threshold::approval_signed_digest;
        let expected = approval_signed_digest(envelope_digest);
        if self.signed_digest != expected {
            return Err(CryptoError::SignatureVerificationFailed {
                reason: "FrostThresholdApproval: signed_digest does not match envelope_digest"
                    .into(),
            });
        }
        Ok(())
    }

    /// Return the 64-byte aggregate Schnorr signature bytes.
    pub fn signature_bytes(&self) -> [u8; 64] {
        self.aggregate_signature_bytes
    }
}

// ── Wire serialization for distributed FROST ─────────────────────────────────
//
// These methods serialize FROST round artifacts to/from opaque byte vectors for
// transmission across the network layer. The bytes are only interpreted inside
// this module — callers outside `frost_adapter` treat them as opaque.
//
// We use serde_json here because it is already a workspace dependency, and the
// wire format correctness matters more than compactness at this stage. A future
// implementation may switch to postcard or bincode for space efficiency.
//
// # Security note
//
// Serialization failure is treated as a hard error (`expect`/`map_err`). If a
// local frost type cannot be serialized, something is fundamentally wrong with
// the library or our usage — there is no sensible recovery.

impl FrostCommitment {
    /// Serialize the commitment for wire transmission.
    ///
    /// The bytes are opaque to all layers outside `frost_adapter`.
    /// Use `FrostCommitment::from_bytes` to reconstruct on the receiving side.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if serde_json serialization fails (e.g. after
    /// a library update that changes the type's `Serialize` impl).
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        serde_json::to_vec(&self.inner).map_err(|e| {
            CryptoError::AggregationFailed(format!(
                "SigningCommitments serialization failed: {e}"
            ))
        })
    }

    /// Deserialize a commitment from wire bytes, associating it with the given
    /// verifier's FROST identifier looked up via `group_key`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::UnknownVerifier` if `verifier_id` is not in `group_key`.
    /// - `CryptoError::AggregationFailed` if deserialization fails (malformed bytes).
    pub fn from_bytes(
        bytes: &[u8],
        verifier_id: &VerifierId,
        group_key: &FrostGroupKey,
    ) -> Result<Self, CryptoError> {
        let identifier = *group_key
            .verifier_to_identifier(verifier_id)
            .ok_or_else(|| CryptoError::UnknownVerifier(verifier_id.to_string()))?;

        let inner: SigningCommitments = serde_json::from_slice(bytes).map_err(|e| {
            CryptoError::AggregationFailed(format!("commitment deserialization failed: {e}"))
        })?;

        Ok(FrostCommitment { identifier, inner })
    }
}

impl FrostSignatureShare {
    /// Serialize the signature share for wire transmission.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if serde_json serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        serde_json::to_vec(&self.inner).map_err(|e| {
            CryptoError::AggregationFailed(format!(
                "SignatureShare serialization failed: {e}"
            ))
        })
    }

    /// Deserialize a signature share, associating it with the given verifier's
    /// FROST identifier looked up via `group_key`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::UnknownVerifier` if `verifier_id` is not in `group_key`.
    /// - `CryptoError::AggregationFailed` if deserialization fails.
    pub fn from_bytes(
        bytes: &[u8],
        verifier_id: &VerifierId,
        group_key: &FrostGroupKey,
    ) -> Result<Self, CryptoError> {
        let identifier = *group_key
            .verifier_to_identifier(verifier_id)
            .ok_or_else(|| CryptoError::UnknownVerifier(verifier_id.to_string()))?;

        let inner: SignatureShare = serde_json::from_slice(bytes).map_err(|e| {
            CryptoError::AggregationFailed(format!("signature share deserialization failed: {e}"))
        })?;

        Ok(FrostSignatureShare { identifier, inner })
    }
}

impl FrostSigningPackage {
    /// Serialize the signing package for wire transmission.
    ///
    /// The coordinator sends this to every Round-2 participant.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if serde_json serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        serde_json::to_vec(&self.inner).map_err(|e| {
            CryptoError::AggregationFailed(format!(
                "SigningPackage serialization failed: {e}"
            ))
        })
    }

    /// Deserialize a signing package from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let inner: SigningPackage = serde_json::from_slice(bytes).map_err(|e| {
            CryptoError::AggregationFailed(format!("signing package deserialization failed: {e}"))
        })?;
        Ok(FrostSigningPackage { inner })
    }

    /// Return the message bytes embedded in this signing package.
    ///
    /// Round-2 participants use this to verify that the message being signed
    /// is the `signed_digest` they committed to in Round 1 — not a different
    /// payload injected by a compromised coordinator.
    pub fn message_bytes(&self) -> &[u8] {
        self.inner.message()
    }
}

// ── Coordinator-side distributed round helpers ────────────────────────────────

/// Assemble a `FrostSigningPackage` from Round-1 commitments.
///
/// Called by the coordinator after receiving all Round-1 responses.
/// `collected` maps each participating verifier's identity to their serialized
/// commitment bytes (from `FrostCommitment::to_bytes()`).
///
/// Returns `(signing_package, package_bytes)` where `package_bytes` is
/// ready for wire transmission in `FrostRound2Request`.
///
/// # Errors
///
/// - `CryptoError::UnknownVerifier` if any verifier is not in `group_key`.
/// - `CryptoError::AggregationFailed` if any commitment cannot be deserialized.
pub fn build_signing_package(
    collected: &[(VerifierId, Vec<u8>)],
    signed_digest: &DigestBytes,
    group_key: &FrostGroupKey,
) -> Result<(FrostSigningPackage, Vec<u8>), CryptoError> {
    let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    for (verifier_id, bytes) in collected {
        let commitment = FrostCommitment::from_bytes(bytes, verifier_id, group_key)?;
        commitments_map.insert(commitment.identifier, commitment.inner);
    }
    let signing_package = FrostSigningPackage {
        inner: SigningPackage::new(commitments_map, signed_digest.as_bytes()),
    };
    let package_bytes = signing_package.to_bytes()?;
    Ok((signing_package, package_bytes))
}

/// Aggregate Round-2 signature shares into a `FrostThresholdApproval`.
///
/// Called by the coordinator after receiving all Round-2 responses.
/// `shares` maps each participating verifier's identity to their serialized
/// share bytes (from `FrostSignatureShare::to_bytes()`).
///
/// # Errors
///
/// - `CryptoError::UnknownVerifier` if any verifier is not in `group_key`.
/// - `CryptoError::AggregationFailed` if any share cannot be deserialized or
///   if the FROST aggregate math fails (invalid shares or mismatched commitments).
pub fn aggregate_signature_shares(
    signing_package: &FrostSigningPackage,
    shares: &[(VerifierId, Vec<u8>)],
    group_key: &FrostGroupKey,
    signed_digest: &DigestBytes,
) -> Result<FrostThresholdApproval, CryptoError> {
    let mut shares_map: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    for (verifier_id, bytes) in shares {
        let share = FrostSignatureShare::from_bytes(bytes, verifier_id, group_key)?;
        shares_map.insert(share.identifier, share.inner);
    }
    let signature = frost::aggregate(&signing_package.inner, &shares_map, &group_key.pub_key_package)
        .map_err(|e| CryptoError::AggregationFailed(e.to_string()))?;

    Ok(FrostThresholdApproval {
        signed_digest: signed_digest.clone(),
        aggregate_signature_bytes: signature.serialize(),
        group_verifying_key_bytes: group_key.verifying_key_bytes(),
    })
}

// ── Coordinator-side signing orchestration ────────────────────────────────────

/// Drive both FROST rounds and produce an aggregate threshold approval.
///
/// This function handles the full in-process FROST protocol:
///
/// 1. **Round 1**: each participant in `signers` generates fresh nonces and
///    commitments (`round1`).
/// 2. **Signing package**: the coordinator assembles a `FrostSigningPackage`
///    from all commitments and `signed_digest`.
/// 3. **Round 2**: each participant computes a partial signature (`round2`).
///    Nonces are consumed and cannot be reused.
/// 4. **Aggregation**: the coordinator combines the shares into a single
///    Schnorr signature.
///
/// # Parameters
///
/// - `signers`: participants to involve in this signing round. Must include
///   at least `quorum.threshold` participants recognized by `group_key`.
/// - `signed_digest`: the 32-byte preimage to sign. **Must** be the output of
///   `approval_signed_digest(envelope_digest)` — do not pass raw digest bytes.
/// - `group_key`: the FROST group public key for this quorum.
/// - `quorum`: the quorum spec. `quorum.threshold` must be >= 2.
///
/// # Errors
///
/// Returns `CryptoError::InsufficientSignatures` if `signers.len() < quorum.threshold`.
/// Returns `CryptoError::UnknownVerifier` if any signer is not in `group_key`.
/// Returns `CryptoError::SigningFailed` if any participant's round-2 fails.
/// Returns `CryptoError::AggregationFailed` if the aggregate math fails.
pub fn frost_collect_approval(
    signers: &[FrostParticipant],
    signed_digest: &DigestBytes,
    group_key: &FrostGroupKey,
    quorum: &QuorumSpec,
) -> Result<FrostThresholdApproval, CryptoError> {
    use rand::rngs::OsRng;

    // Validate participant count before spending any entropy.
    if signers.len() < quorum.threshold {
        return Err(CryptoError::InsufficientSignatures {
            need: quorum.threshold,
            got: signers.len(),
        });
    }

    // ── Round 1 ───────────────────────────────────────────────────────────────
    // Collect (participant_index, nonces) pairs. Nonces are !Clone, so we move
    // them into a Vec here and consume them one-by-one during Round 2.
    let mut nonces_store: Vec<(usize, FrostSigningNonces)> = Vec::with_capacity(signers.len());
    let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

    for (idx, signer) in signers.iter().enumerate() {
        let frost_id = group_key
            .verifier_to_identifier(&signer.verifier_id)
            .ok_or_else(|| CryptoError::UnknownVerifier(signer.verifier_id.to_string()))?;

        let (nonces, commitment) = signer.round1(&mut OsRng);
        commitments_map.insert(*frost_id, commitment.inner);
        nonces_store.push((idx, nonces));
    }

    // ── Build signing package ─────────────────────────────────────────────────
    // The message is the 32-byte signed_digest (output of approval_signed_digest).
    let signing_package = FrostSigningPackage {
        inner: SigningPackage::new(commitments_map, signed_digest.as_bytes()),
    };

    // ── Round 2 ───────────────────────────────────────────────────────────────
    // Nonces are consumed (moved) here — one per participant, never reused.
    let mut shares_map: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();

    for (idx, nonces) in nonces_store {
        let signer = &signers[idx];
        let frost_id = group_key
            .verifier_to_identifier(&signer.verifier_id)
            .expect("already validated in Round 1");

        // nonces moved into round2 — consumed here, cannot be reused.
        let share = signer.round2(&signing_package, nonces)?;
        shares_map.insert(*frost_id, share.inner);
    }

    // ── Aggregation ───────────────────────────────────────────────────────────
    let signature = frost::aggregate(
        &signing_package.inner,
        &shares_map,
        &group_key.pub_key_package,
    )
    .map_err(|e| CryptoError::AggregationFailed(e.to_string()))?;

    let aggregate_signature_bytes: [u8; 64] = signature.serialize();

    Ok(FrostThresholdApproval {
        signed_digest: signed_digest.clone(),
        aggregate_signature_bytes,
        group_verifying_key_bytes: group_key.verifying_key_bytes(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::approval_signed_digest;
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId, types::QuorumSpec};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn verifier(b: u8) -> VerifierId {
        VerifierId::from_bytes([b; 32])
    }

    fn three_verifiers() -> Vec<VerifierId> {
        vec![verifier(1), verifier(2), verifier(3)]
    }

    fn keygen_3_of_3() -> TrustedDealerKeygenOutput {
        frost_trusted_dealer_keygen(&three_verifiers(), 3).unwrap()
    }

    fn keygen_2_of_3() -> TrustedDealerKeygenOutput {
        frost_trusted_dealer_keygen(&three_verifiers(), 2).unwrap()
    }

    fn quorum_3_of_3() -> QuorumSpec {
        QuorumSpec::new(three_verifiers(), 3).unwrap()
    }

    fn quorum_2_of_3() -> QuorumSpec {
        QuorumSpec::new(three_verifiers(), 2).unwrap()
    }

    fn sample_envelope_digest(b: u8) -> DigestBytes {
        DigestBytes::from_bytes([b; 32])
    }

    // ── Phase 3: signing preimage tests ───────────────────────────────────────

    /// The signed_digest is deterministic given the same envelope_digest.
    #[test]
    fn signing_preimage_is_deterministic() {
        let ed = sample_envelope_digest(0xAB);
        let d1 = approval_signed_digest(&ed);
        let d2 = approval_signed_digest(&ed);
        assert_eq!(d1, d2);
    }

    /// Different envelope digests produce different signed_digests.
    #[test]
    fn signing_preimage_is_injective() {
        let d1 = approval_signed_digest(&sample_envelope_digest(0x01));
        let d2 = approval_signed_digest(&sample_envelope_digest(0x02));
        assert_ne!(d1, d2);
    }

    /// The signed_digest is domain-separated from the raw envelope_digest.
    /// An approval cannot be misused as a signature on the raw envelope bytes.
    #[test]
    fn signing_preimage_is_domain_separated_from_envelope() {
        let ed = sample_envelope_digest(0xFF);
        let signed = approval_signed_digest(&ed);
        assert_ne!(*signed.as_bytes(), *ed.as_bytes());
    }

    /// The signing preimage produces output that is not the all-zeros digest.
    /// (Guards against trivial implementations that always return ZERO.)
    #[test]
    fn signing_preimage_is_nonzero() {
        let signed = approval_signed_digest(&sample_envelope_digest(0x55));
        assert_ne!(signed, DigestBytes::ZERO);
    }

    // ── Keygen tests ──────────────────────────────────────────────────────────

    #[test]
    fn trusted_dealer_keygen_2_of_3_succeeds() {
        let out = keygen_2_of_3();
        assert_eq!(out.participants.len(), 3);
        // All participants have distinct FROST identifiers.
        let ids: Vec<_> = out.participants.iter().map(|p| p.identifier).collect();
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn trusted_dealer_keygen_3_of_3_succeeds() {
        let out = keygen_3_of_3();
        assert_eq!(out.participants.len(), 3);
    }

    #[test]
    fn trusted_dealer_keygen_threshold_too_low_fails() {
        // threshold < 2 is rejected by FROST
        let result = frost_trusted_dealer_keygen(&three_verifiers(), 1);
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
            "expected InvalidKeyMaterial"
        );
    }

    #[test]
    fn trusted_dealer_keygen_threshold_exceeds_n_fails() {
        let result = frost_trusted_dealer_keygen(&three_verifiers(), 4);
        assert!(matches!(result, Err(CryptoError::InvalidKeyMaterial(_))));
    }

    #[test]
    fn trusted_dealer_keygen_single_participant_fails() {
        let result = frost_trusted_dealer_keygen(&[verifier(1)], 1);
        assert!(matches!(result, Err(CryptoError::InvalidKeyMaterial(_))));
    }

    #[test]
    fn trusted_dealer_keygen_duplicate_verifiers_fails() {
        let ids = vec![verifier(1), verifier(1), verifier(2)];
        let result = frost_trusted_dealer_keygen(&ids, 2);
        assert!(matches!(result, Err(CryptoError::InvalidKeyMaterial(_))));
    }

    #[test]
    fn group_key_maps_each_verifier_correctly() {
        let vids = three_verifiers();
        let out = frost_trusted_dealer_keygen(&vids, 2).unwrap();
        for vid in &vids {
            assert!(
                out.group_key.verifier_to_identifier(vid).is_some(),
                "verifier {} should have an identifier",
                vid
            );
        }
        // Unknown verifier has no mapping.
        assert!(out.group_key.verifier_to_identifier(&verifier(99)).is_none());
    }

    // ── Phase 4: FROST happy-path signing ─────────────────────────────────────

    #[test]
    fn frost_3_of_3_produces_valid_approval() {
        let envelope_digest = sample_envelope_digest(0xAA);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let out = keygen_3_of_3();
        let quorum = quorum_3_of_3();

        let approval =
            frost_collect_approval(&out.participants, &signed_digest, &out.group_key, &quorum)
                .unwrap();

        // Signature must verify against the embedded group key.
        approval.verify_signature().unwrap();

        // Binding to the envelope digest must hold.
        approval.verify_binding(&envelope_digest).unwrap();
    }

    #[test]
    fn frost_2_of_3_threshold_satisfied_with_exactly_2() {
        let envelope_digest = sample_envelope_digest(0xBB);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();

        // Use only the first 2 participants.
        let two_signers = &out.participants[..2];
        let approval =
            frost_collect_approval(two_signers, &signed_digest, &out.group_key, &quorum).unwrap();

        approval.verify_signature().unwrap();
        approval.verify_binding(&envelope_digest).unwrap();
    }

    #[test]
    fn frost_all_3_signers_on_2_of_3_quorum_succeeds() {
        let envelope_digest = sample_envelope_digest(0xCC);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();

        // All 3 participants sign (more than threshold is fine).
        let approval =
            frost_collect_approval(&out.participants, &signed_digest, &out.group_key, &quorum)
                .unwrap();

        approval.verify_signature().unwrap();
    }

    #[test]
    fn different_envelopes_produce_different_approvals() {
        let ed1 = sample_envelope_digest(0x11);
        let ed2 = sample_envelope_digest(0x22);
        let sd1 = approval_signed_digest(&ed1);
        let sd2 = approval_signed_digest(&ed2);

        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();

        let a1 = frost_collect_approval(&out.participants[..2], &sd1, &out.group_key, &quorum)
            .unwrap();
        let a2 = frost_collect_approval(&out.participants[..2], &sd2, &out.group_key, &quorum)
            .unwrap();

        assert_ne!(a1.aggregate_signature_bytes, a2.aggregate_signature_bytes);
        assert_ne!(a1.signed_digest, a2.signed_digest);
    }

    // ── Phase 5: FROST negative/adversarial tests ─────────────────────────────

    #[test]
    fn below_threshold_signers_is_rejected() {
        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();
        let signed_digest = approval_signed_digest(&sample_envelope_digest(0x30));

        // Only 1 signer, threshold is 2.
        let result = frost_collect_approval(&out.participants[..1], &signed_digest, &out.group_key, &quorum);
        assert!(
            matches!(result, Err(CryptoError::InsufficientSignatures { need: 2, got: 1 })),
            "expected InsufficientSignatures, got {result:?}"
        );
    }

    #[test]
    fn zero_signers_is_rejected() {
        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();
        let signed_digest = approval_signed_digest(&sample_envelope_digest(0x31));

        let result = frost_collect_approval(&[], &signed_digest, &out.group_key, &quorum);
        assert!(matches!(result, Err(CryptoError::InsufficientSignatures { .. })));
    }

    #[test]
    fn signer_not_in_group_key_is_rejected() {
        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3(); // threshold = 2
        let signed_digest = approval_signed_digest(&sample_envelope_digest(0x32));

        // Generate a completely separate quorum with different verifier identities.
        let other_out = frost_trusted_dealer_keygen(
            &[verifier(50), verifier(51), verifier(52)],
            2,
        )
        .unwrap();

        // Pass 2 participants from the OTHER quorum (meets the count threshold)
        // but they are not registered in `out.group_key` — so UnknownVerifier
        // should fire before any signing begins.
        let result = frost_collect_approval(
            &other_out.participants[..2], // 2 signers >= threshold of 2
            &signed_digest,
            &out.group_key, // different group — verifier_ids 50/51 are unknown here
            &quorum,
        );
        assert!(
            matches!(result, Err(CryptoError::UnknownVerifier(_))),
            "expected UnknownVerifier, got {result:?}"
        );
    }

    #[test]
    fn approval_with_tampered_signed_digest_fails_verify() {
        let envelope_digest = sample_envelope_digest(0x40);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();

        let mut approval =
            frost_collect_approval(&out.participants[..2], &signed_digest, &out.group_key, &quorum)
                .unwrap();

        // Tamper with the signed_digest field.
        approval.signed_digest = sample_envelope_digest(0xFF);

        // Signature verification should fail because the stored signed_digest
        // no longer matches what was actually signed.
        assert!(
            approval.verify_signature().is_err(),
            "tampered signed_digest should cause signature verification to fail"
        );
    }

    #[test]
    fn approval_with_tampered_signature_bytes_fails_verify() {
        let envelope_digest = sample_envelope_digest(0x41);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();

        let mut approval =
            frost_collect_approval(&out.participants[..2], &signed_digest, &out.group_key, &quorum)
                .unwrap();

        // Flip one byte in the aggregate signature.
        approval.aggregate_signature_bytes[0] ^= 0xFF;

        assert!(approval.verify_signature().is_err());
    }

    #[test]
    fn approval_with_wrong_group_key_fails_verify() {
        let envelope_digest = sample_envelope_digest(0x42);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let out_a = keygen_2_of_3();
        let quorum = quorum_2_of_3();

        // Generate a DIFFERENT quorum's group key.
        let other_vids = vec![verifier(10), verifier(11), verifier(12)];
        let out_b = frost_trusted_dealer_keygen(&other_vids, 2).unwrap();

        let mut approval =
            frost_collect_approval(&out_a.participants[..2], &signed_digest, &out_a.group_key, &quorum)
                .unwrap();

        // Substitute the other quorum's group key.
        approval.group_verifying_key_bytes = out_b.group_key.verifying_key_bytes();

        assert!(
            approval.verify_signature().is_err(),
            "approval signed under key A should not verify under key B"
        );
    }

    #[test]
    fn verify_binding_rejects_wrong_envelope_digest() {
        let real_envelope = sample_envelope_digest(0x50);
        let wrong_envelope = sample_envelope_digest(0x51);
        let signed_digest = approval_signed_digest(&real_envelope);

        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();

        let approval =
            frost_collect_approval(&out.participants[..2], &signed_digest, &out.group_key, &quorum)
                .unwrap();

        // Signature itself is valid.
        approval.verify_signature().unwrap();

        // But binding to a different envelope must fail.
        assert!(
            approval.verify_binding(&wrong_envelope).is_err(),
            "verify_binding should reject an envelope digest the approval was not made for"
        );
    }

    #[test]
    fn verify_binding_accepts_correct_envelope_digest() {
        let envelope_digest = sample_envelope_digest(0x60);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();

        let approval =
            frost_collect_approval(&out.participants[..2], &signed_digest, &out.group_key, &quorum)
                .unwrap();

        approval.verify_signature().unwrap();
        approval.verify_binding(&envelope_digest).unwrap();
    }

    /// Two independent signings of the same message with the same key material
    /// produce different signatures (because FROST nonces are fresh each time).
    #[test]
    fn two_signings_of_same_message_produce_different_signatures() {
        let envelope_digest = sample_envelope_digest(0x70);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let out = keygen_2_of_3();
        let quorum = quorum_2_of_3();

        let a1 =
            frost_collect_approval(&out.participants[..2], &signed_digest, &out.group_key, &quorum)
                .unwrap();
        let a2 =
            frost_collect_approval(&out.participants[..2], &signed_digest, &out.group_key, &quorum)
                .unwrap();

        // Same message, fresh nonces — signatures must differ.
        // (If they were equal, nonces were reused, which would be a catastrophic bug.)
        assert_ne!(
            a1.aggregate_signature_bytes, a2.aggregate_signature_bytes,
            "distinct signing rounds must produce distinct nonce-randomized signatures"
        );

        // Both must still verify correctly.
        a1.verify_signature().unwrap();
        a2.verify_signature().unwrap();
    }
}
