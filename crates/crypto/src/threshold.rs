//! Threshold signature abstraction and prototype implementation.
//!
//! # Production gap
//!
//! `PrototypeThresholdSigner` collects individual ed25519 signatures.
//! This is NOT a real (t,n)-threshold scheme:
//!
//! - Individual signatures are separately verifiable, so t parties must
//!   individually sign. There is no aggregation that hides participation.
//! - A compromised verifier exposes their individual signature.
//! - The "aggregate" is just a vector of (verifier_id, signature) pairs.
//!
//! A production implementation should use FROST (RFC 9591) for ed25519
//! or BLS threshold signatures for compact aggregation.
//!
//! The `ThresholdSigner` trait is designed to be compatible with a FROST
//! implementation: `sign_partial` maps to FROST's round-2 output, and
//! `aggregate` maps to FROST's signature aggregation step.

use crate::error::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tls_attestation_core::{
    hash::{sha256_tagged, DigestBytes},
    ids::VerifierId,
    types::QuorumSpec,
};

/// A verifier's key pair for signing attestation approvals.
pub struct VerifierKeyPair {
    pub verifier_id: VerifierId,
    signing_key: SigningKey,
}

impl VerifierKeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifier_id = VerifierId::from_public_key(signing_key.verifying_key().as_bytes());
        Self {
            verifier_id,
            signing_key,
        }
    }

    /// Derive a deterministic key pair from a 32-byte seed (for tests only).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifier_id = VerifierId::from_public_key(signing_key.verifying_key().as_bytes());
        Self {
            verifier_id,
            signing_key,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign pre-hashed, domain-separated bytes and return 64 raw signature bytes.
    ///
    /// # Caller responsibility
    ///
    /// This method signs `data` as-is. The caller MUST ensure `data` is already
    /// domain-separated (e.g., computed via `CanonicalHasher`) before calling
    /// this method. Signing un-hashed or domain-ambiguous data is a misuse.
    ///
    /// This method exists so that modules outside `threshold.rs` can produce
    /// signed announcements without accessing the private `signing_key` field.
    pub fn sign_raw(&self, data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(data).to_bytes()
    }
}

/// A partial signature produced by a single verifier.
///
/// In FROST, this corresponds to the round-2 signature share.
/// Here it is a plain ed25519 signature over the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    pub verifier_id: VerifierId,
    /// Raw ed25519 signature bytes (64 bytes).
    pub bytes: Vec<u8>,
}

/// An aggregate threshold approval, satisfying the quorum requirement.
///
/// PROTOTYPE: This contains `threshold` individual ed25519 signatures,
/// not a real aggregate. The `signed_digest` is the exact payload that
/// was signed by each participating verifier.
///
/// # Verification
///
/// To verify a `ThresholdApproval`:
/// 1. Recompute `signed_digest = H("tls-attestation/threshold-approval/v1" || envelope_digest)`.
/// 2. For each `(verifier_id, sig)` in `signatures`, verify the sig over `signed_digest`
///    using the verifier's known public key.
/// 3. Count distinct eligible verifiers. Must reach `quorum.threshold`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdApproval {
    /// The quorum spec that was used.
    pub quorum: QuorumSpec,
    /// Verifiers who contributed a valid signature.
    pub signers: Vec<VerifierId>,
    /// Individual (verifier_id, signature_bytes) pairs.
    pub signatures: Vec<(VerifierId, Vec<u8>)>,
    /// The digest that was signed: H("tls-attestation/threshold-approval/v1" || envelope_digest).
    pub signed_digest: DigestBytes,
}

/// The trait all threshold signing engines must implement.
///
/// # FROST compatibility
///
/// This trait is designed so that a FROST implementation fits naturally:
/// - `sign_partial` = FROST round-2 (produce signature share)
/// - `aggregate` = FROST aggregation
/// - `verify_approval` = FROST verification
pub trait ThresholdSigner: Send + Sync {
    /// Produce a partial signature over the given payload.
    fn sign_partial(&self, payload: &[u8]) -> Result<PartialSignature, CryptoError>;

    /// The verifier ID associated with this signer.
    fn verifier_id(&self) -> &VerifierId;
}

/// Combines partial signatures into a `ThresholdApproval`.
///
/// This is a coordinator-side operation, not part of the per-verifier trait.
pub fn aggregate_signatures(
    partials: Vec<PartialSignature>,
    quorum: &QuorumSpec,
    envelope_digest: &DigestBytes,
    public_keys: &[(VerifierId, VerifyingKey)],
) -> Result<ThresholdApproval, CryptoError> {
    let signed_digest = approval_signed_digest(envelope_digest);

    // Verify each partial signature and collect valid ones.
    let mut valid: Vec<(VerifierId, Vec<u8>)> = Vec::new();
    for partial in &partials {
        // Only count verifiers in the quorum.
        if !quorum.verifiers.contains(&partial.verifier_id) {
            continue;
        }
        // Find the public key for this verifier.
        let vk = public_keys
            .iter()
            .find(|(id, _)| id == &partial.verifier_id)
            .map(|(_, vk)| vk)
            .ok_or_else(|| CryptoError::UnknownVerifier(partial.verifier_id.to_string()))?;

        let sig = Signature::from_slice(&partial.bytes).map_err(|e| {
            CryptoError::SignatureVerificationFailed {
                reason: format!("malformed signature: {e}"),
            }
        })?;

        vk.verify(signed_digest.as_bytes(), &sig).map_err(|_| {
            CryptoError::SignatureVerificationFailed {
                reason: format!("signature from {} is invalid", partial.verifier_id),
            }
        })?;

        // Deduplicate: only count each verifier once.
        if !valid.iter().any(|(id, _)| id == &partial.verifier_id) {
            valid.push((partial.verifier_id.clone(), partial.bytes.clone()));
        }
    }

    let signers: Vec<VerifierId> = valid.iter().map(|(id, _)| id.clone()).collect();

    if !quorum.is_satisfied_by(&signers) {
        return Err(CryptoError::InsufficientSignatures {
            need: quorum.threshold,
            got: signers.len(),
        });
    }

    Ok(ThresholdApproval {
        quorum: quorum.clone(),
        signers,
        signatures: valid,
        signed_digest,
    })
}

/// Verify a `ThresholdApproval` against a set of known public keys and an envelope digest.
pub fn verify_threshold_approval(
    approval: &ThresholdApproval,
    envelope_digest: &DigestBytes,
    public_keys: &[(VerifierId, VerifyingKey)],
) -> Result<(), CryptoError> {
    let expected_signed_digest = approval_signed_digest(envelope_digest);

    if approval.signed_digest != expected_signed_digest {
        return Err(CryptoError::SignatureVerificationFailed {
            reason: "signed_digest does not match envelope_digest".into(),
        });
    }

    let mut valid_count = 0usize;
    for (verifier_id, sig_bytes) in &approval.signatures {
        if !approval.quorum.verifiers.contains(verifier_id) {
            continue;
        }
        let vk = public_keys
            .iter()
            .find(|(id, _)| id == verifier_id)
            .map(|(_, vk)| vk)
            .ok_or_else(|| CryptoError::UnknownVerifier(verifier_id.to_string()))?;

        let sig = Signature::from_slice(sig_bytes).map_err(|e| {
            CryptoError::SignatureVerificationFailed {
                reason: format!("malformed signature: {e}"),
            }
        })?;

        vk.verify(approval.signed_digest.as_bytes(), &sig).map_err(|_| {
            CryptoError::SignatureVerificationFailed {
                reason: format!("signature from {verifier_id} is invalid"),
            }
        })?;

        valid_count += 1;
    }

    if !approval.quorum.is_satisfied_by(&approval.signers) || valid_count < approval.quorum.threshold {
        return Err(CryptoError::InsufficientSignatures {
            need: approval.quorum.threshold,
            got: valid_count,
        });
    }

    Ok(())
}

/// Compute the payload that verifiers sign for a threshold approval.
///
/// Domain separation prevents this signature from being repurposed as
/// a signature on any other message type.
pub fn approval_signed_digest(envelope_digest: &DigestBytes) -> DigestBytes {
    sha256_tagged(
        "tls-attestation/threshold-approval/v1",
        envelope_digest.as_bytes(),
    )
}

/// Prototype threshold signer: signs with a plain ed25519 key.
///
/// # WARNING: NOT PRODUCTION SAFE
///
/// See module-level documentation.
pub struct PrototypeThresholdSigner {
    key_pair: VerifierKeyPair,
}

impl PrototypeThresholdSigner {
    pub fn new(key_pair: VerifierKeyPair) -> Self {
        Self { key_pair }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::new(VerifierKeyPair::from_seed(seed))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key_pair.verifying_key()
    }
}

impl ThresholdSigner for PrototypeThresholdSigner {
    fn sign_partial(&self, payload: &[u8]) -> Result<PartialSignature, CryptoError> {
        let sig: Signature = self.key_pair.signing_key.sign(payload);
        Ok(PartialSignature {
            verifier_id: self.key_pair.verifier_id.clone(),
            bytes: sig.to_bytes().to_vec(),
        })
    }

    fn verifier_id(&self) -> &VerifierId {
        &self.key_pair.verifier_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::{hash::DigestBytes, types::QuorumSpec};

    // ── Signing preimage tests (Phase 3) ──────────────────────────────────────
    //
    // These tests verify invariants of `approval_signed_digest` independent of
    // the signing implementation. The same preimage is used by both
    // `PrototypeThresholdSigner` and the FROST adapter.

    /// The preimage is stable — same input always produces the same output.
    #[test]
    fn signing_preimage_is_deterministic() {
        let ed = DigestBytes::from_bytes([0xAB; 32]);
        assert_eq!(approval_signed_digest(&ed), approval_signed_digest(&ed));
    }

    /// Different envelope digests must produce different signed digests.
    /// If this fails, two different envelopes could produce the same approval.
    #[test]
    fn signing_preimage_different_envelopes_produce_different_digests() {
        let d1 = approval_signed_digest(&DigestBytes::from_bytes([0x01; 32]));
        let d2 = approval_signed_digest(&DigestBytes::from_bytes([0x02; 32]));
        assert_ne!(d1, d2);
    }

    /// The signed digest must differ from the raw envelope digest.
    /// This enforces domain separation: the signature cannot be replayed as
    /// a signature directly over the envelope bytes.
    #[test]
    fn signing_preimage_is_domain_separated_from_envelope_digest() {
        let ed = DigestBytes::from_bytes([0xFF; 32]);
        let signed = approval_signed_digest(&ed);
        // If these were equal, the domain tag had no effect.
        assert_ne!(*signed.as_bytes(), *ed.as_bytes());
    }

    /// The signed digest is never all-zeros, which would suggest a broken hash.
    #[test]
    fn signing_preimage_is_not_zero_digest() {
        let signed = approval_signed_digest(&DigestBytes::from_bytes([0x55; 32]));
        assert_ne!(signed, DigestBytes::ZERO);
    }

    /// Changing a single bit of the envelope digest changes the preimage.
    /// This prevents a coordinator from making minor tweaks to an envelope
    /// and reusing a previously collected approval.
    #[test]
    fn signing_preimage_single_bit_change_changes_output() {
        let base = [0x55u8; 32];
        let mut modified = base;
        modified[0] ^= 0x01; // flip one bit

        let d_base = approval_signed_digest(&DigestBytes::from_bytes(base));
        let d_modified = approval_signed_digest(&DigestBytes::from_bytes(modified));
        assert_ne!(d_base, d_modified);
    }

    /// The preimage uses a fixed domain tag. If the tag is changed (e.g. to
    /// "tls-attestation/threshold-approval/v2"), the output must differ.
    /// This test guards against accidental tag collisions.
    #[test]
    fn signing_preimage_domain_tag_provides_separation() {
        use tls_attestation_core::hash::sha256_tagged;
        let ed = DigestBytes::from_bytes([0xAA; 32]);

        let v1 = approval_signed_digest(&ed);
        // Compute what v2 would look like with a different tag.
        let v2_hypothetical = sha256_tagged(
            "tls-attestation/threshold-approval/v2",
            ed.as_bytes(),
        );
        assert_ne!(v1, v2_hypothetical,
            "different version tags must produce different signing preimages"
        );
    }

    fn make_signer(seed: u8) -> PrototypeThresholdSigner {
        PrototypeThresholdSigner::from_seed([seed; 32])
    }

    #[test]
    fn partial_signature_verifies() {
        let signer = make_signer(1);
        let payload = b"test payload";
        let partial = signer.sign_partial(payload).unwrap();

        let vk = signer.verifying_key();
        let sig = Signature::from_slice(&partial.bytes).unwrap();
        vk.verify(payload, &sig).unwrap();
    }

    #[test]
    fn aggregate_requires_threshold() {
        let s1 = make_signer(1);
        let s2 = make_signer(2);
        let s3 = make_signer(3);

        let envelope_digest = DigestBytes::from_bytes([0xAA; 32]);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let quorum = QuorumSpec::new(
            vec![
                s1.verifier_id().clone(),
                s2.verifier_id().clone(),
                s3.verifier_id().clone(),
            ],
            2,
        )
        .unwrap();

        let p1 = s1.sign_partial(signed_digest.as_bytes()).unwrap();
        let p2 = s2.sign_partial(signed_digest.as_bytes()).unwrap();

        let pks = vec![
            (s1.verifier_id().clone(), s1.verifying_key()),
            (s2.verifier_id().clone(), s2.verifying_key()),
            (s3.verifier_id().clone(), s3.verifying_key()),
        ];

        // Two signatures satisfy threshold of 2.
        let approval =
            aggregate_signatures(vec![p1, p2], &quorum, &envelope_digest, &pks).unwrap();
        assert_eq!(approval.signers.len(), 2);

        verify_threshold_approval(&approval, &envelope_digest, &pks).unwrap();
    }

    #[test]
    fn aggregate_fails_below_threshold() {
        let s1 = make_signer(10);
        let s2 = make_signer(11);
        let envelope_digest = DigestBytes::from_bytes([0xBB; 32]);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let quorum = QuorumSpec::new(
            vec![s1.verifier_id().clone(), s2.verifier_id().clone()],
            2,
        )
        .unwrap();

        let p1 = s1.sign_partial(signed_digest.as_bytes()).unwrap();
        let pks = vec![
            (s1.verifier_id().clone(), s1.verifying_key()),
            (s2.verifier_id().clone(), s2.verifying_key()),
        ];

        // Only one signature, threshold is 2.
        assert!(aggregate_signatures(vec![p1], &quorum, &envelope_digest, &pks).is_err());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let s1 = make_signer(20);
        let s2 = make_signer(21);
        let envelope_digest = DigestBytes::from_bytes([0xCC; 32]);
        let signed_digest = approval_signed_digest(&envelope_digest);

        let quorum = QuorumSpec::new(
            vec![s1.verifier_id().clone(), s2.verifier_id().clone()],
            2,
        )
        .unwrap();

        let p1 = s1.sign_partial(signed_digest.as_bytes()).unwrap();
        let p2 = s2.sign_partial(signed_digest.as_bytes()).unwrap();

        let pks = vec![
            (s1.verifier_id().clone(), s1.verifying_key()),
            (s2.verifier_id().clone(), s2.verifying_key()),
        ];

        let mut approval =
            aggregate_signatures(vec![p1, p2], &quorum, &envelope_digest, &pks).unwrap();

        // Tamper with the envelope digest used for verification.
        let tampered_digest = DigestBytes::from_bytes([0xFF; 32]);
        assert!(verify_threshold_approval(&approval, &tampered_digest, &pks).is_err());
    }
}
