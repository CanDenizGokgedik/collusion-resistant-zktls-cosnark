//! secp256k1 FROST adapter — EVM-compatible threshold signing.
//!
//! # Why secp256k1?
//!
//! The paper (§IX) explicitly adopts **secp256k1 + FROST** because:
//! - DKG, DVRF, and TSS all share the same prime-order group → single DKG.
//! - EVM on-chain verification costs only **4,200–12,000 gas** vs 115,000 for BLS.
//! - secp256k1 precompiles are optimized in every major EVM implementation.
//!
//! # Relationship to `frost_adapter`
//!
//! `frost_adapter` (Ed25519) remains for backward-compatible tests.
//! This module is the **production path** for Π_coll-min deployments.
//!
//! # Types
//!
//! | Type | Role |
//! |------|------|
//! | `Secp256k1FrostParticipant` | Aux-node — holds key share, runs rounds 1 & 2 |
//! | `Secp256k1FrostGroupKey` | Public group key + VerifierId↔Identifier map |
//! | `Secp256k1SigningNonces` | Single-use Round-1 nonces (`!Clone`) |
//! | `Secp256k1Commitment` | Round-1 broadcast commitment |
//! | `Secp256k1SignatureShare` | Round-2 partial signature |
//! | `Secp256k1SigningPackage` | Assembled package distributed for Round 2 |
//! | `Secp256k1ThresholdApproval`| Final 64-byte aggregated signature + group key |
//!
//! # Key-generation warning
//!
//! `secp256k1_trusted_dealer_keygen` uses a **trusted dealer** and is only safe
//! for tests. Production deployments MUST use `run_secp256k1_dkg` (Pedersen DKG).

use crate::error::CryptoError;
use frost_secp256k1_evm as frost;
use std::collections::{BTreeMap, HashMap};
use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};

// ── Type aliases ──────────────────────────────────────────────────────────────

use frost::keys::{KeyPackage, PublicKeyPackage, SecretShare};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};

// ── Nonces (single-use) ───────────────────────────────────────────────────────

/// Single-use Round-1 nonces for one signing session.
///
/// `!Clone` — Rust's move semantics ensure nonces cannot be reused,
/// preventing the secret-share leakage that nonce reuse causes in Schnorr.
pub struct Secp256k1SigningNonces(SigningNonces);

// ── Round-1 commitment ────────────────────────────────────────────────────────

/// Round-1 output broadcast by a participant to the coordinator.
#[derive(Clone)]
pub struct Secp256k1Commitment {
    pub(crate) identifier: Identifier,
    pub(crate) inner: SigningCommitments,
}

// ── Round-2 signature share ───────────────────────────────────────────────────

/// Round-2 output: one participant's partial signature.
#[derive(Clone)]
pub struct Secp256k1SignatureShare {
    pub(crate) identifier: Identifier,
    pub(crate) inner: SignatureShare,
}

// ── Signing package ───────────────────────────────────────────────────────────

/// The message and all commitments, assembled by the coordinator for Round 2.
pub struct Secp256k1SigningPackage {
    pub(crate) inner: SigningPackage,
}

// ── Group key ─────────────────────────────────────────────────────────────────

/// FROST group public key — public data, no secret material.
///
/// The paper's `pk` in the Signing Phase:
/// `{0,1} ← SC.Verify(σ, pk)`.
#[derive(Clone)]
pub struct Secp256k1GroupKey {
    pub_key_package: PublicKeyPackage,
    /// Protocol VerifierId → FROST Identifier (1-indexed u16).
    verifier_to_id: HashMap<VerifierId, Identifier>,
}

impl Secp256k1GroupKey {
    /// Look up the FROST identifier for a protocol verifier.
    pub fn verifier_to_identifier(&self, vid: &VerifierId) -> Option<&Identifier> {
        self.verifier_to_id.get(vid)
    }

    /// 33-byte compressed secp256k1 group verifying key.
    ///
    /// Used for on-chain `SC.Verify(σ, pk)` — compatible with EVM ecrecover.
    pub fn verifying_key_bytes(&self) -> [u8; 33] {
        let bytes = self.pub_key_package.verifying_key().serialize().unwrap_or_default();
        let mut arr = [0u8; 33];
        let len = bytes.len().min(33);
        arr[..len].copy_from_slice(&bytes[..len]);
        arr
    }

    pub(crate) fn new_from_parts(
        pub_key_package: PublicKeyPackage,
        verifier_to_id: HashMap<VerifierId, Identifier>,
    ) -> Self {
        Self { pub_key_package, verifier_to_id }
    }

    /// Serialize to JSON bytes for persistent storage.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        #[derive(serde::Serialize)]
        struct Export<'a> {
            pub_key_package: &'a PublicKeyPackage,
            verifier_map: Vec<(String, String)>,
        }
        let verifier_map = self.verifier_to_id.iter()
            .map(|(vid, id)| {
                let id_bytes: Vec<u8> = id.serialize().to_vec();
                (hex::encode(vid.as_bytes()), hex::encode(id_bytes))
            })
            .collect();
        serde_json::to_vec(&Export { pub_key_package: &self.pub_key_package, verifier_map })
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("Secp256k1GroupKey serialize: {e}")))
    }

    /// Deserialize from JSON bytes produced by [`to_json_bytes`].
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        #[derive(serde::Deserialize)]
        struct Export {
            pub_key_package: PublicKeyPackage,
            verifier_map: Vec<(String, String)>,
        }
        let e: Export = serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("Secp256k1GroupKey deserialize: {e}")))?;
        let mut verifier_to_id = HashMap::new();
        for (vid_hex, id_hex) in e.verifier_map {
            let vid_bytes = hex::decode(&vid_hex)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("vid hex: {e}")))?;
            let vid_arr: [u8; 32] = vid_bytes.try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial("vid must be 32 bytes".into()))?;
            let id_bytes = hex::decode(&id_hex)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("id hex: {e}")))?;
            let id = Identifier::deserialize(&id_bytes)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("identifier: {e}")))?;
            verifier_to_id.insert(VerifierId::from_bytes(vid_arr), id);
        }
        Ok(Self { pub_key_package: e.pub_key_package, verifier_to_id })
    }
}

// ── Participant ───────────────────────────────────────────────────────────────

/// A secp256k1 FROST participant: holds a key share, runs both rounds.
///
/// One per auxiliary verifier. Contains secret key material.
pub struct Secp256k1FrostParticipant {
    key_package: KeyPackage,
    verifier_id: VerifierId,
}

impl Secp256k1FrostParticipant {
    /// Construct from a `SecretShare` produced by the trusted dealer or DKG.
    pub fn from_secret_share(
        secret_share: SecretShare,
        verifier_id: VerifierId,
    ) -> Result<Self, CryptoError> {
        let key_package = KeyPackage::try_from(secret_share)
            .map_err(|e| CryptoError::AggregationFailed(e.to_string()))?;
        Ok(Self { key_package, verifier_id })
    }

    /// Construct directly from a `KeyPackage` produced by DKG Part 3.
    ///
    /// Used by `secp256k1_dkg_part3` to avoid the `SecretShare` roundtrip.
    pub fn from_key_package(
        key_package: KeyPackage,
        verifier_id: VerifierId,
    ) -> Result<Self, CryptoError> {
        Ok(Self { key_package, verifier_id })
    }

    pub fn verifier_id(&self) -> &VerifierId {
        &self.verifier_id
    }

    /// Serialize to JSON bytes for persistent storage.
    ///
    /// ⚠ Contains secret key material — encrypt before writing to disk.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        #[derive(serde::Serialize)]
        struct Export<'a> {
            key_package: &'a KeyPackage,
            verifier_id_hex: String,
        }
        serde_json::to_vec(&Export {
            key_package: &self.key_package,
            verifier_id_hex: hex::encode(self.verifier_id.as_bytes()),
        }).map_err(|e| CryptoError::InvalidKeyMaterial(format!("Secp256k1FrostParticipant serialize: {e}")))
    }

    /// Deserialize from JSON bytes produced by [`to_json_bytes`].
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        #[derive(serde::Deserialize)]
        struct Export {
            key_package: KeyPackage,
            verifier_id_hex: String,
        }
        let e: Export = serde_json::from_slice(bytes)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("Secp256k1FrostParticipant deserialize: {e}")))?;
        let vid_bytes = hex::decode(&e.verifier_id_hex)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("verifier_id hex: {e}")))?;
        let vid_arr: [u8; 32] = vid_bytes.try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial("verifier_id must be 32 bytes".into()))?;
        Ok(Self {
            key_package: e.key_package,
            verifier_id: VerifierId::from_bytes(vid_arr),
        })
    }

    // ── Round 1 ───────────────────────────────────────────────────────────────

    /// Generate nonces and a commitment for one signing session.
    ///
    /// The returned `Secp256k1Commitment` must be broadcast to the coordinator.
    /// The `Secp256k1SigningNonces` must be kept secret and passed to `round2`.
    pub fn round1<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Secp256k1SigningNonces, Secp256k1Commitment), CryptoError> {
        let (nonces, commitments) =
            frost::round1::commit(&self.key_package.signing_share(), rng);
        let id = *self.key_package.identifier();
        Ok((
            Secp256k1SigningNonces(nonces),
            Secp256k1Commitment { identifier: id, inner: commitments },
        ))
    }

    // ── Round 2 ───────────────────────────────────────────────────────────────

    /// Produce a signature share from the signing package and nonces.
    ///
    /// Nonces are consumed — they cannot be reused.
    pub fn round2(
        &self,
        signing_package: &Secp256k1SigningPackage,
        nonces: Secp256k1SigningNonces,
    ) -> Result<Secp256k1SignatureShare, CryptoError> {
        let share = frost::round2::sign(
            &signing_package.inner,
            &nonces.0,
            &self.key_package,
        )
        .map_err(|e| CryptoError::AggregationFailed(e.to_string()))?;
        let id = *self.key_package.identifier();
        Ok(Secp256k1SignatureShare { identifier: id, inner: share })
    }

    // ── Deterministic Round-1 for DVRF (uniqueness requirement) ──────────────

    /// Deterministic Round-1 for DVRF use.
    ///
    /// Nonces are seeded from `H(signing_share || alpha)` so the same
    /// (key, alpha) pair always produces the same commitment and signature,
    /// satisfying the DVRF uniqueness property required by Π_coll-min.
    pub fn round1_dvrf(
        &self,
        alpha: &[u8],
    ) -> (Secp256k1SigningNonces, Secp256k1Commitment) {
        use rand::SeedableRng;
        let seed = self.dvrf_nonce_seed(alpha);
        let mut seeded_rng = rand::rngs::StdRng::from_seed(seed);
        self.round1(&mut seeded_rng)
            .expect("deterministic round1 must not fail")
    }

    fn dvrf_nonce_seed(&self, alpha: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let share_bytes = self.key_package.signing_share().serialize();
        let key_bytes: &[u8] = share_bytes.as_ref();
        let mut h = sha2::Sha256::new();
        h.update(b"tls-attestation/dvrf-nonce-seed/secp256k1/v1\x00");
        h.update((key_bytes.len() as u64).to_be_bytes());
        h.update(key_bytes);
        h.update((alpha.len() as u64).to_be_bytes());
        h.update(alpha);
        h.finalize().into()
    }
}

// ── Aggregated approval ───────────────────────────────────────────────────────

/// Final aggregated threshold approval.
///
/// The paper's σ: `σ ← Combine(σi)`, verified on-chain via `SC.Verify(σ, pk)`.
#[derive(Clone, Debug)]
pub struct Secp256k1ThresholdApproval {
    /// 64-byte compact secp256k1 Schnorr signature (r || s).
    pub aggregate_signature_bytes: [u8; 65],
    /// 33-byte compressed group verifying key.
    pub group_verifying_key_bytes: [u8; 33],
}

// ── Keygen (trusted dealer — tests only) ─────────────────────────────────────

/// Output of `secp256k1_trusted_dealer_keygen`.
pub struct Secp256k1KeygenOutput {
    pub participants: Vec<Secp256k1FrostParticipant>,
    pub group_key: Secp256k1GroupKey,
}

/// Generate FROST key shares using a trusted dealer.
///
/// **WARNING: NOT production-safe.** The dealer sees all key shares.
/// Use `run_secp256k1_dkg` for production deployments.
pub fn secp256k1_trusted_dealer_keygen(
    verifier_ids: &[VerifierId],
    threshold: usize,
) -> Result<Secp256k1KeygenOutput, CryptoError> {
    use rand::rngs::OsRng;

    let n = verifier_ids.len();
    if n < 2 {
        return Err(CryptoError::InvalidKeyMaterial("need at least 2 participants".into()));
    }
    if threshold < 2 || threshold > n {
        return Err(CryptoError::InvalidKeyMaterial(format!("threshold must be in [2, n={n}]")));
    }

    let max_signers = n as u16;
    let min_signers = threshold as u16;

    let mut rng = OsRng;

    let (shares, public_key_package) =
        frost::keys::generate_with_dealer(max_signers, min_signers, frost::keys::IdentifierList::Default, &mut rng)
            .map_err(|e| CryptoError::AggregationFailed(e.to_string()))?;

    // Map VerifierId → FROST Identifier.
    let mut verifier_to_id: HashMap<VerifierId, Identifier> = HashMap::new();
    let id_order: Vec<Identifier> = shares.keys().cloned().collect();
    for (i, vid) in verifier_ids.iter().enumerate() {
        if i >= id_order.len() {
            return Err(CryptoError::InvalidKeyMaterial("id count mismatch".into()));
        }
        verifier_to_id.insert(vid.clone(), id_order[i]);
    }

    let participants: Vec<Secp256k1FrostParticipant> = shares
        .into_values()
        .zip(verifier_ids.iter())
        .map(|(share, vid)| {
            Secp256k1FrostParticipant::from_secret_share(share, vid.clone())
        })
        .collect::<Result<_, _>>()?;

    let group_key = Secp256k1GroupKey::new_from_parts(public_key_package, verifier_to_id);
    Ok(Secp256k1KeygenOutput { participants, group_key })
}

// ── Coordinator helpers ────────────────────────────────────────────────────────

/// Assemble a signing package from collected Round-1 commitments.
///
/// `message` is the 32-byte digest to be signed (e.g. `approval_signed_digest`
/// or the Handshake Binding `binding_input`).
pub fn secp256k1_build_signing_package(
    commitments: &[Secp256k1Commitment],
    message: &DigestBytes,
) -> Result<Secp256k1SigningPackage, CryptoError> {
    let commitment_map: BTreeMap<Identifier, SigningCommitments> = commitments
        .iter()
        .map(|c| (c.identifier, c.inner.clone()))
        .collect();

    let pkg = SigningPackage::new(commitment_map, message.as_bytes());

    Ok(Secp256k1SigningPackage { inner: pkg })
}

/// Aggregate `t` signature shares into a single 64-byte Schnorr signature.
///
/// Returns a `Secp256k1ThresholdApproval` containing both the signature bytes
/// and the group verifying key bytes needed for on-chain `SC.Verify(σ, pk)`.
pub fn secp256k1_aggregate_signature_shares(
    signing_package: &Secp256k1SigningPackage,
    shares: &[Secp256k1SignatureShare],
    group_key: &Secp256k1GroupKey,
) -> Result<Secp256k1ThresholdApproval, CryptoError> {
    let share_map: BTreeMap<Identifier, SignatureShare> = shares
        .iter()
        .map(|s| (s.identifier, s.inner.clone()))
        .collect();

    let signature = frost::aggregate(
        &signing_package.inner,
        &share_map,
        &group_key.pub_key_package,
    )
    .map_err(|e| CryptoError::AggregationFailed(e.to_string()))?;

    // Serialize to compact 64-byte (r || s).
    let sig_bytes = signature.serialize()
        .map_err(|e| CryptoError::AggregationFailed(e.to_string()))?;
    let mut compact = [0u8; 65];
    let len = sig_bytes.len().min(65);
    compact[..len].copy_from_slice(&sig_bytes[..len]);

    Ok(Secp256k1ThresholdApproval {
        aggregate_signature_bytes: compact,
        group_verifying_key_bytes: group_key.verifying_key_bytes(),
    })
}

/// Verify a `Secp256k1ThresholdApproval` against a message digest.
///
/// Used by auxiliary verifiers and the on-chain contract:
/// `{0,1} ← SC.Verify(σ, pk)`.
pub fn secp256k1_verify_approval(
    approval: &Secp256k1ThresholdApproval,
    message: &DigestBytes,
) -> Result<(), CryptoError> {
    let vk = frost::VerifyingKey::deserialize(approval.group_verifying_key_bytes.as_ref())
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("vk deserialize: {e}")))?;

    let sig = frost::Signature::deserialize(approval.aggregate_signature_bytes.as_ref())
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("sig deserialize: {e}")))?;

    vk.verify(message.as_bytes(), &sig)
        .map_err(|e| CryptoError::SignatureVerificationFailed { reason: format!("verify: {e}") })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use tls_attestation_core::hash::DigestBytes;
    use tls_attestation_core::ids::VerifierId;

    fn vids(n: usize) -> Vec<VerifierId> {
        (0..n as u8).map(|i| VerifierId::from_bytes([i; 32])).collect()
    }

    #[test]
    fn secp256k1_2of3_round_trip() {
        let ids = vids(3);
        let out = secp256k1_trusted_dealer_keygen(&ids, 2).unwrap();
        let message = DigestBytes::from_bytes([0x42u8; 32]);

        // Round 1: all 3 participants generate nonces.
        let mut rng = OsRng;
        let (nonces_and_commits): Vec<_> = out
            .participants
            .iter()
            .map(|p| p.round1(&mut rng).unwrap())
            .collect();
        let (nonces, commits): (Vec<_>, Vec<_>) =
            nonces_and_commits.into_iter().unzip();

        // Use only first 2 (threshold).
        let pkg = secp256k1_build_signing_package(&commits[..2], &message).unwrap();

        // Round 2: first 2 participants sign.
        let shares: Vec<_> = out.participants[..2]
            .iter()
            .zip(nonces.into_iter())
            .take(2)
            .map(|(p, n)| p.round2(&pkg, n).unwrap())
            .collect();

        let approval = secp256k1_aggregate_signature_shares(&pkg, &shares, &out.group_key).unwrap();
        secp256k1_verify_approval(&approval, &message).unwrap();

        assert_ne!(approval.aggregate_signature_bytes, [0u8; 65]);
        println!("secp256k1 2-of-3 FROST OK");
    }

    #[test]
    fn secp256k1_3of5_all_participants() {
        let ids = vids(5);
        let out = secp256k1_trusted_dealer_keygen(&ids, 3).unwrap();
        let message = DigestBytes::from_bytes([0xABu8; 32]);

        let mut rng = OsRng;
        let nc: Vec<_> = out.participants[..3]
            .iter()
            .map(|p| p.round1(&mut rng).unwrap())
            .collect();
        let (nonces, commits): (Vec<_>, Vec<_>) = nc.into_iter().unzip();
        let pkg = secp256k1_build_signing_package(&commits, &message).unwrap();
        let shares: Vec<_> = out.participants[..3]
            .iter()
            .zip(nonces)
            .map(|(p, n)| p.round2(&pkg, n).unwrap())
            .collect();
        let approval = secp256k1_aggregate_signature_shares(&pkg, &shares, &out.group_key).unwrap();
        secp256k1_verify_approval(&approval, &message).unwrap();
        println!("secp256k1 3-of-5 FROST OK");
    }
}