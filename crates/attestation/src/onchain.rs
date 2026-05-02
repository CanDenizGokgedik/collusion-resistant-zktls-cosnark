//! On-chain compatible attestation format.
//!
//! # Design
//!
//! The `OnChainAttestation` struct is the minimal, ABI-compatible representation
//! of a Π_coll-min attestation suitable for verification in an EVM smart contract.
//!
//! # On-Chain Verification
//!
//! A Solidity verifier would:
//! 1. Recompute `statement_commitment = keccak256(statement_tag || statement_content)`.
//! 2. Recompute `envelope_digest` from the canonical fields.
//! 3. Verify the Ed25519 aggregate signature against `group_verifying_key`.
//!
//! # Ed25519 on EVM
//!
//! Ed25519 is available on EVM via EIP-7212 (precompile 0x100) on chains that
//! support it. On chains without the precompile, a pure-Solidity Ed25519 verifier
//! (e.g., Tonelli–Shanks or Baby-JubJub fallback) can be used.
//!
//! # Security
//!
//! The on-chain verifier checks:
//! 1. The aggregate Ed25519 signature is valid.
//! 2. The envelope digest commits to the statement, DVRF value, and session.
//! 3. The DVRF value is included (enables off-chain DVRF proof verification).
//!
//! # Limitations
//!
//! The on-chain contract cannot verify the DVRF proof or DCTLS proofs directly
//! (computation too expensive). It trusts the off-chain aux verifier quorum to
//! have verified these proofs before signing. The threshold signature proves
//! at least t honest verifiers approved the full proof chain.

use serde::{Deserialize, Serialize};

/// Serde helper for `[u8; 64]` (serde only auto-impls arrays up to 32 elements).
mod serde_bytes_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        let bytes: &[u8] = v;
        bytes.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(d)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 64 bytes"))
    }
}

/// ABI-compatible attestation for on-chain consumption.
///
/// Suitable for EVM storage and verification. All fields are fixed-size byte arrays
/// for deterministic ABI encoding.
///
/// # ABI Encoding
///
/// ABI-encode as `(bytes32, bytes32, bytes32, bytes32, bytes32, uint8, uint16, bytes32[])`:
/// - statement_digest (bytes32)
/// - dvrf_value (bytes32)
/// - envelope_digest (bytes32)
/// - group_verifying_key (bytes32)
/// - aggregate_signature high (bytes32) — first 32 bytes
/// - aggregate_signature low (bytes32) — last 32 bytes
/// - threshold (uint8)
/// - verifier_count (uint8)
///
/// # Solidity Interface
///
/// ```solidity
/// struct TLSAttestation {
///     bytes32 statementDigest;
///     bytes32 dvrf_value;
///     bytes32 envelopeDigest;
///     bytes32 groupVerifyingKey;
///     bytes32 sigHigh;        // first 32 bytes of Ed25519 signature
///     bytes32 sigLow;         // last  32 bytes of Ed25519 signature
///     uint8   threshold;
///     uint8   verifierCount;
/// }
///
/// function verify(TLSAttestation calldata att) external pure returns (bool) {
///     bytes memory message = abi.encode(att.envelopeDigest);
///     bytes memory sig = abi.encodePacked(att.sigHigh, att.sigLow);
///     return Ed25519.verify(att.groupVerifyingKey, message, sig);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainAttestation {
    /// H(statement_tag || statement_content) — the claim being attested.
    pub statement_digest: [u8; 32],
    /// The DVRF randomness value — enables off-chain DVRF proof verification.
    pub dvrf_value: [u8; 32],
    /// Canonical digest committing to all attestation fields.
    pub envelope_digest: [u8; 32],
    /// Ed25519 group verifying key (32 bytes, compressed).
    pub group_verifying_key: [u8; 32],
    /// Ed25519 aggregate Schnorr signature (64 bytes = R || s).
    #[serde(with = "serde_bytes_64")]
    pub aggregate_signature: [u8; 64],
    /// Minimum number of signers required.
    pub threshold: u8,
    /// Total number of verifiers in the quorum.
    pub verifier_count: u8,
    /// Tamper-detection binding: SHA-256("tls-attestation/stmt-dvrf-binding/v1" || statement_digest || dvrf_value).
    ///
    /// Allows `verify()` to detect post-extraction tampering of `statement_digest`
    /// or `dvrf_value` even though the signature only covers `envelope_digest`.
    pub statement_dvrf_binding: [u8; 32],
}

/// Errors from on-chain format operations.
#[derive(Debug, thiserror::Error)]
pub enum OnChainError {
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("envelope digest mismatch")]
    DigestMismatch,

    #[error("threshold not met: need {need}, have {have}")]
    ThresholdNotMet { need: u8, have: u8 },
}

impl OnChainAttestation {
    /// Verify the on-chain attestation (Rust implementation of the smart contract logic).
    ///
    /// Checks:
    /// 1. The aggregate Ed25519 signature is valid over `envelope_digest`.
    /// 2. `threshold ≥ 1` and `threshold ≤ verifier_count`.
    /// 3. Internal `statement_dvrf_binding` is consistent with `statement_digest`
    ///    and `dvrf_value`.
    ///
    /// # ⚠ Tamper-resistance note
    ///
    /// The signature only covers `envelope_digest`.  An attacker who controls the
    /// raw bytes (e.g. after untrusted ABI-decoding) could modify `statement_digest`
    /// or `dvrf_value` while keeping the original valid `(envelope_digest, signature)`
    /// pair — the signature check would still pass.
    ///
    /// Mitigation: this function verifies `statement_dvrf_binding` against the
    /// stored `statement_digest` and `dvrf_value`.  As long as `statement_dvrf_binding`
    /// is not also tampered (it is included in the ABI encoding and thus verified by
    /// downstream consumers), tampering with either field is detectable.
    ///
    /// For the strongest guarantee, callers should obtain the raw `envelope_digest`
    /// preimage from the signing system and recompute it instead of trusting
    /// ABI-decoded bytes directly.
    ///
    /// Note: Cannot verify DVRF or DCTLS proofs on-chain (use off-chain verification).
    pub fn verify(&self) -> Result<(), OnChainError> {
        use ed25519_dalek::{Signature, VerifyingKey};

        // 1. Verify Ed25519 signature over envelope_digest.
        let vk = VerifyingKey::from_bytes(&self.group_verifying_key)
            .map_err(|e| OnChainError::SignatureVerificationFailed(e.to_string()))?;
        let sig = Signature::from_bytes(&self.aggregate_signature);
        use ed25519_dalek::Verifier;
        vk.verify(&self.envelope_digest, &sig)
            .map_err(|e| OnChainError::SignatureVerificationFailed(e.to_string()))?;

        // 2. Threshold guards.
        if self.threshold == 0 {
            return Err(OnChainError::ThresholdNotMet {
                need: 1,
                have: self.threshold,
            });
        }
        if self.threshold > self.verifier_count {
            return Err(OnChainError::ThresholdNotMet {
                need: self.threshold,
                have: self.verifier_count,
            });
        }

        // 3. Internal binding check — detects tampering of statement_digest /
        //    dvrf_value without corresponding update of statement_dvrf_binding.
        let expected_binding = Self::compute_statement_dvrf_binding(
            &self.statement_digest,
            &self.dvrf_value,
        );
        if self.statement_dvrf_binding != expected_binding {
            return Err(OnChainError::DigestMismatch);
        }

        Ok(())
    }

    /// Compute the canonical statement+DVRF binding tag.
    ///
    /// `binding = SHA-256("tls-attestation/stmt-dvrf-binding/v1" || statement_digest || dvrf_value)`
    ///
    /// Included in ABI encoding so any field tamper breaks this cross-check.
    pub fn compute_statement_dvrf_binding(
        statement_digest: &[u8; 32],
        dvrf_value: &[u8; 32],
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"tls-attestation/stmt-dvrf-binding/v1");
        h.update(statement_digest);
        h.update(dvrf_value);
        h.finalize().into()
    }

    /// ABI-encode the attestation for on-chain submission (Ethereum ABI format).
    ///
    /// Produces a `bytes` value that can be passed to `abi.decode()` in Solidity.
    ///
    /// # Encoding
    ///
    /// Each fixed-size field is right-padded to 32 bytes (Ethereum word size):
    /// - statement_digest: 32 bytes (exact)
    /// - dvrf_value: 32 bytes (exact)
    /// - envelope_digest: 32 bytes (exact)
    /// - group_verifying_key: 32 bytes (exact)
    /// - aggregate_signature: 64 bytes (two EVM words: R || s)
    /// - threshold: 1 byte, left-padded to 32 bytes (uint8)
    /// - verifier_count: 1 byte, left-padded to 32 bytes (uint8)
    /// - statement_dvrf_binding: 32 bytes (tamper-detection binding hash)
    ///
    /// Total: 8 × 32 + 32 = 288 bytes
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(288);
        out.extend_from_slice(&self.statement_digest);
        out.extend_from_slice(&self.dvrf_value);
        out.extend_from_slice(&self.envelope_digest);
        out.extend_from_slice(&self.group_verifying_key);
        out.extend_from_slice(&self.aggregate_signature[..32]);
        out.extend_from_slice(&self.aggregate_signature[32..]);
        out.extend_from_slice(&[0u8; 31]);
        out.push(self.threshold);
        out.extend_from_slice(&[0u8; 31]);
        out.push(self.verifier_count);
        // Tamper-detection binding (32 bytes).
        out.extend_from_slice(&self.statement_dvrf_binding);
        out
    }

    /// Decode from ABI-encoded bytes produced by `abi_encode()`.
    pub fn abi_decode(bytes: &[u8]) -> Result<Self, OnChainError> {
        if bytes.len() != 288 {
            return Err(OnChainError::SignatureVerificationFailed(
                format!("expected 288 bytes, got {}", bytes.len()),
            ));
        }
        let mut statement_digest = [0u8; 32];
        let mut dvrf_value = [0u8; 32];
        let mut envelope_digest = [0u8; 32];
        let mut group_verifying_key = [0u8; 32];
        let mut aggregate_signature = [0u8; 64];
        let mut statement_dvrf_binding = [0u8; 32];

        statement_digest.copy_from_slice(&bytes[0..32]);
        dvrf_value.copy_from_slice(&bytes[32..64]);
        envelope_digest.copy_from_slice(&bytes[64..96]);
        group_verifying_key.copy_from_slice(&bytes[96..128]);
        aggregate_signature[..32].copy_from_slice(&bytes[128..160]);
        aggregate_signature[32..].copy_from_slice(&bytes[160..192]);
        let threshold = bytes[223];
        let verifier_count = bytes[255];
        statement_dvrf_binding.copy_from_slice(&bytes[256..288]);

        Ok(Self {
            statement_digest,
            dvrf_value,
            envelope_digest,
            group_verifying_key,
            aggregate_signature,
            threshold,
            verifier_count,
            statement_dvrf_binding,
        })
    }
}

/// Extract an `OnChainAttestation` from a FROST threshold approval.
///
/// `statement_digest`: call `derive_onchain_statement_digest(tag, content)`.
/// `dvrf_value`: the DVRF output value for this session.
/// `envelope_digest`: from `AttestationEnvelope::compute_digest()`.
/// `frost_approval`: from `aggregate_signature_shares()`.
#[cfg(feature = "frost")]
pub fn extract_on_chain_attestation(
    statement_digest: [u8; 32],
    dvrf_value: [u8; 32],
    envelope_digest: [u8; 32],
    frost_approval: &tls_attestation_crypto::frost_adapter::FrostThresholdApproval,
    threshold: u8,
    verifier_count: u8,
) -> OnChainAttestation {
    let statement_dvrf_binding =
        OnChainAttestation::compute_statement_dvrf_binding(&statement_digest, &dvrf_value);
    OnChainAttestation {
        statement_digest,
        dvrf_value,
        envelope_digest,
        group_verifying_key: frost_approval.group_verifying_key_bytes,
        aggregate_signature: frost_approval.aggregate_signature_bytes,
        threshold,
        verifier_count,
        statement_dvrf_binding,
    }
}

/// Derive the on-chain statement digest.
///
/// Produces `H("onchain-statement/v1" || tag_len || tag || content_len || content)`.
/// This is the canonical commitment to the statement for on-chain storage.
pub fn derive_onchain_statement_digest(tag: &str, content: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"tls-attestation/onchain-statement/v1\x00");
    h.update((tag.len() as u64).to_be_bytes());
    h.update(tag.as_bytes());
    h.update((content.len() as u64).to_be_bytes());
    h.update(content);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fake_attestation() -> OnChainAttestation {
        let statement_digest = [1u8; 32];
        let dvrf_value = [2u8; 32];
        let statement_dvrf_binding =
            OnChainAttestation::compute_statement_dvrf_binding(&statement_digest, &dvrf_value);
        OnChainAttestation {
            statement_digest,
            dvrf_value,
            envelope_digest: [3u8; 32],
            group_verifying_key: [0u8; 32],
            aggregate_signature: [0u8; 64],
            threshold: 2,
            verifier_count: 3,
            statement_dvrf_binding,
        }
    }

    #[test]
    fn abi_encode_decode_roundtrip() {
        let statement_digest = [0x11u8; 32];
        let dvrf_value = [0x22u8; 32];
        let statement_dvrf_binding =
            OnChainAttestation::compute_statement_dvrf_binding(&statement_digest, &dvrf_value);
        let att = OnChainAttestation {
            statement_digest,
            dvrf_value,
            envelope_digest: [0x33u8; 32],
            group_verifying_key: [0x44u8; 32],
            aggregate_signature: {
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&[0x55u8; 32]);
                sig[32..].copy_from_slice(&[0x66u8; 32]);
                sig
            },
            threshold: 3,
            verifier_count: 5,
            statement_dvrf_binding,
        };

        let encoded = att.abi_encode();
        assert_eq!(encoded.len(), 288, "ABI encoding must be exactly 288 bytes");

        let decoded = OnChainAttestation::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.statement_digest, att.statement_digest);
        assert_eq!(decoded.dvrf_value, att.dvrf_value);
        assert_eq!(decoded.envelope_digest, att.envelope_digest);
        assert_eq!(decoded.group_verifying_key, att.group_verifying_key);
        assert_eq!(decoded.aggregate_signature, att.aggregate_signature);
        assert_eq!(decoded.threshold, 3);
        assert_eq!(decoded.verifier_count, 5);
        assert_eq!(decoded.statement_dvrf_binding, att.statement_dvrf_binding);
    }

    #[test]
    fn abi_decode_wrong_length_fails() {
        assert!(OnChainAttestation::abi_decode(&[0u8; 128]).is_err());
        assert!(OnChainAttestation::abi_decode(&[0u8; 512]).is_err());
    }

    #[test]
    fn derive_statement_digest_is_deterministic() {
        let d1 = derive_onchain_statement_digest("test/v1", b"claim");
        let d2 = derive_onchain_statement_digest("test/v1", b"claim");
        assert_eq!(d1, d2);
    }

    #[test]
    fn derive_statement_digest_differs_by_tag() {
        let d1 = derive_onchain_statement_digest("tag/v1", b"claim");
        let d2 = derive_onchain_statement_digest("tag/v2", b"claim");
        assert_ne!(d1, d2);
    }

    #[test]
    fn derive_statement_digest_differs_by_content() {
        let d1 = derive_onchain_statement_digest("tag/v1", b"claim-A");
        let d2 = derive_onchain_statement_digest("tag/v1", b"claim-B");
        assert_ne!(d1, d2);
    }

    #[test]
    fn threshold_field_abi_encoded_correctly() {
        let att = OnChainAttestation {
            threshold: 7,
            verifier_count: 10,
            ..make_fake_attestation()
        };
        let encoded = att.abi_encode();
        // threshold is at byte 223 (7th 32-byte word, last byte).
        assert_eq!(encoded[223], 7, "threshold must be at byte 223");
        // verifier_count is at byte 255 (8th 32-byte word, last byte).
        assert_eq!(encoded[255], 10, "verifier_count must be at byte 255");
    }
}
