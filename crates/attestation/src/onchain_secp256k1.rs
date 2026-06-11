//! secp256k1 FROST on-chain attestation format.
//!
//! Replaces the Ed25519-based `OnChainAttestation` for EVM deployments using
//! FROST(secp256k1, Keccak256) threshold Schnorr signatures.
//!
//! # Paper reference — §IX, Table I
//!
//! > "FROST on secp256k1: 2 ECMUL + 2 ECADD + 1 Hash-to-G → ~4,200 gas"
//!
//! The on-chain verifier (`FrostVerifier.sol`) accepts this format via:
//!   `SC.Verify(σ, pk)` where σ = (R.x, s) and pk = (pk_x, pk_y).
//!
//! # ABI format (352 bytes)
//!
//! ```text
//! Word 0  (  0– 32): statement_digest   [bytes32]
//! Word 1  ( 32– 64): dvrf_value         [bytes32]
//! Word 2  ( 64– 96): envelope_digest    [bytes32]
//! Word 3  ( 96–128): group_key_x        [uint256] secp256k1 pk.x
//! Word 4  (128–160): group_key_y        [uint256] secp256k1 pk.y
//! Word 5  (160–192): sig_R_x            [uint256] Schnorr R.x
//! Word 6  (192–224): sig_s              [uint256] Schnorr scalar s
//! Word 7  (224–256): threshold          [uint256 → uint8 at byte 255]
//! Word 8  (256–288): verifier_count     [uint256 → uint8 at byte 287]
//! Word 9  (288–320): nonce_commitment   [bytes32] α commitment (π_DVRF binding)
//! Word 10 (320–352): session_id         [bytes32] session binding
//! ```

use serde::{Deserialize, Serialize};
use tls_attestation_core::hash::DigestBytes;

// ── Wire type ─────────────────────────────────────────────────────────────────

/// ABI-compatible Π_coll-min attestation for EVM consumption with secp256k1 FROST.
///
/// Produced by `extract_secp256k1_attestation`. Verified on-chain by `FrostVerifier.sol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainAttestationSecp256k1 {
    /// H(tag || statement_content) — the claim being attested.
    pub statement_digest: [u8; 32],
    /// DVRF rand value — enables off-chain π_DVRF verification.
    pub dvrf_value: [u8; 32],
    /// Canonical digest committing to all attestation fields (signed by FROST).
    pub envelope_digest: [u8; 32],
    /// secp256k1 group verifying key x-coordinate.
    pub group_key_x: [u8; 32],
    /// secp256k1 group verifying key y-coordinate.
    pub group_key_y: [u8; 32],
    /// FROST Schnorr signature: nonce commitment R.x.
    pub sig_R_x: [u8; 32],
    /// FROST Schnorr signature: scalar s.
    pub sig_s: [u8; 32],
    /// Threshold t (minimum signers required).
    pub threshold: u8,
    /// Total verifier count n.
    pub verifier_count: u8,
    /// DVRF input α commitment — binds the session to the DKG ceremony.
    pub alpha_commitment: [u8; 32],
    /// Session identifier — prevents cross-session replay.
    pub session_id: [u8; 32],
}

/// Errors from secp256k1 on-chain format operations.
#[derive(Debug, thiserror::Error)]
pub enum Secp256k1OnChainError {
    #[error("ABI decode: expected {expected} bytes, got {got}")]
    WrongLength { expected: usize, got: usize },

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("threshold not met: need {need}, have {have}")]
    ThresholdNotMet { need: u8, have: u8 },
}

impl OnChainAttestationSecp256k1 {
    /// ABI-encode for on-chain submission (11 × 32 = 352 bytes).
    ///
    /// Layout matches `TLSAttestation.sol::Attestation` + extra fields.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(352);
        out.extend_from_slice(&self.statement_digest);  //   0–32
        out.extend_from_slice(&self.dvrf_value);         //  32–64
        out.extend_from_slice(&self.envelope_digest);    //  64–96
        out.extend_from_slice(&self.group_key_x);        //  96–128
        out.extend_from_slice(&self.group_key_y);        // 128–160
        out.extend_from_slice(&self.sig_R_x);            // 160–192
        out.extend_from_slice(&self.sig_s);              // 192–224
        // uint8 threshold — left-padded to 32 bytes.
        out.extend_from_slice(&[0u8; 31]);
        out.push(self.threshold);                        // 224–256, byte 255
        // uint8 verifier_count — left-padded to 32 bytes.
        out.extend_from_slice(&[0u8; 31]);
        out.push(self.verifier_count);                   // 256–288, byte 287
        out.extend_from_slice(&self.alpha_commitment);   // 288–320
        out.extend_from_slice(&self.session_id);         // 320–352
        out
    }

    /// Decode from ABI-encoded bytes.
    pub fn abi_decode(bytes: &[u8]) -> Result<Self, Secp256k1OnChainError> {
        if bytes.len() != 352 {
            return Err(Secp256k1OnChainError::WrongLength {
                expected: 352,
                got: bytes.len(),
            });
        }
        let mut read = |start: usize| -> [u8; 32] {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes[start..start + 32]);
            buf
        };
        Ok(Self {
            statement_digest: read(0),
            dvrf_value:        read(32),
            envelope_digest:   read(64),
            group_key_x:       read(96),
            group_key_y:       read(128),
            sig_R_x:           read(160),
            sig_s:             read(192),
            threshold:         bytes[255],
            verifier_count:    bytes[287],
            alpha_commitment:  read(288),
            session_id:        read(320),
        })
    }

    /// Rust-side Schnorr verification (mirrors `FrostVerifier.sol::verify`).
    ///
    /// Checks: s·G = R + e·PK where e = keccak256(R_x || pk_x || envelope_digest).
    ///
    /// Used by aux verifiers before signing, and in tests.
    #[cfg(feature = "secp256k1")]
    pub fn verify_schnorr(&self) -> Result<(), Secp256k1OnChainError> {
        use k256::{
            AffinePoint, ProjectivePoint, Scalar,
            elliptic_curve::{
                group::GroupEncoding,
                ops::MulByGenerator,
                Field, PrimeField,
            },
            FieldBytes,
        };
        use sha3::{Digest, Keccak256};

        // Compute challenge e = keccak256(R_x || pk_x || envelope_digest) mod N.
        let e_bytes: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(&self.sig_R_x);
            h.update(&self.group_key_x);
            h.update(&self.envelope_digest);
            h.finalize().into()
        };

        // Parse scalars.
        let s = Scalar::from_repr(FieldBytes::from(self.sig_s))
            .into_option()
            .ok_or_else(|| Secp256k1OnChainError::InvalidSignature("invalid s".into()))?;
        let e = Scalar::from_repr(FieldBytes::from(e_bytes))
            .into_option()
            .ok_or_else(|| Secp256k1OnChainError::InvalidSignature("invalid e".into()))?;

        // Parse public key.
        let mut pk_bytes = [0u8; 65];
        pk_bytes[0] = 0x04;
        pk_bytes[1..33].copy_from_slice(&self.group_key_x);
        pk_bytes[33..65].copy_from_slice(&self.group_key_y);
        let pk_point = AffinePoint::from_bytes((&pk_bytes[..]).into())
            .into_option()
            .ok_or_else(|| Secp256k1OnChainError::InvalidSignature("invalid group key".into()))?;

        // s·G
        let sG = ProjectivePoint::mul_by_generator(&s);

        // e·PK
        let ePK = ProjectivePoint::from(pk_point) * e;

        // R_candidate = s·G - e·PK
        let R_candidate = sG - ePK;

        // Extract x-coordinate of R_candidate via projective coordinates.
        let R_affine = AffinePoint::from(R_candidate);
        // Encode as compressed point (33 bytes: parity || x), extract x bytes.
        let compressed = R_affine.to_bytes();
        if compressed.len() < 33 {
            return Err(Secp256k1OnChainError::InvalidSignature("degenerate point".into()));
        }
        let candidate_x: [u8; 32] = compressed[1..33].try_into().unwrap();

        if candidate_x != self.sig_R_x {
            return Err(Secp256k1OnChainError::InvalidSignature(
                "Schnorr verification failed: R.x mismatch".into(),
            ));
        }

        // Threshold consistency.
        if self.threshold > self.verifier_count {
            return Err(Secp256k1OnChainError::ThresholdNotMet {
                need: self.threshold,
                have: self.verifier_count,
            });
        }

        Ok(())
    }

    /// Derive the on-chain statement digest.
    ///
    /// Matches `FrostVerifier.sol`:
    /// `keccak256("tls-attestation/onchain-statement/v1\0" || tag_len || tag || content_len || content)`
    ///
    /// # Fix (was SHA-256, now keccak256)
    ///
    /// The previous implementation used SHA-256, which does not match the
    /// Solidity `keccak256(...)` used in `FrostVerifier.sol`.  Statement digests
    /// computed in Rust would never pass on-chain verification.  This function
    /// now uses keccak256 to match the Solidity contract exactly.
    #[cfg(feature = "secp256k1")]
    pub fn statement_digest_for(tag: &str, content: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let mut h = Keccak256::new();
        h.update(b"tls-attestation/onchain-statement/v1\x00");
        h.update((tag.len() as u64).to_be_bytes());
        h.update(tag.as_bytes());
        h.update((content.len() as u64).to_be_bytes());
        h.update(content);
        h.finalize().into()
    }
}

// ── Builder — from FROST approval ─────────────────────────────────────────────

/// Build an `OnChainAttestationSecp256k1` from a secp256k1 FROST approval.
///
/// The Schnorr signature (R.x, s) and group key (pk_x, pk_y) are extracted
/// from the 65-byte aggregate signature produced by `secp256k1_aggregate_signature_shares`.
///
/// # Wire format of `frost_approval.aggregate_signature_bytes` (65 bytes)
///
/// ```text
/// Bytes  0–32: R compressed (33 bytes) — we skip parity byte
/// Bytes 33–65: s scalar (32 bytes)
/// ```
///
/// Actually FROST secp256k1 serializes as:
/// ```text
/// Bytes 0–32:  R.x (32 bytes) — normalized x-coordinate of R
/// Bytes 32–64: s (32 bytes)
/// ```
#[cfg(feature = "secp256k1")]
pub fn extract_secp256k1_attestation(
    statement_digest: [u8; 32],
    dvrf_value: [u8; 32],
    alpha_commitment: [u8; 32],
    session_id: [u8; 32],
    envelope_digest: [u8; 32],
    sig_bytes: &[u8; 64],      // (R.x || s) from FROST aggregate
    group_key_x: [u8; 32],
    group_key_y: [u8; 32],
    threshold: u8,
    verifier_count: u8,
) -> OnChainAttestationSecp256k1 {
    let mut sig_R_x = [0u8; 32];
    let mut sig_s   = [0u8; 32];
    sig_R_x.copy_from_slice(&sig_bytes[0..32]);
    sig_s.copy_from_slice(&sig_bytes[32..64]);

    OnChainAttestationSecp256k1 {
        statement_digest,
        dvrf_value,
        envelope_digest,
        group_key_x,
        group_key_y,
        sig_R_x,
        sig_s,
        threshold,
        verifier_count,
        alpha_commitment,
        session_id,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_att() -> OnChainAttestationSecp256k1 {
        OnChainAttestationSecp256k1 {
            statement_digest: [0x11u8; 32],
            dvrf_value:        [0x22u8; 32],
            envelope_digest:   [0x33u8; 32],
            group_key_x:       [0x44u8; 32],
            group_key_y:       [0x55u8; 32],
            sig_R_x:           [0x66u8; 32],
            sig_s:             [0x77u8; 32],
            threshold:         3,
            verifier_count:    5,
            alpha_commitment:  [0xAAu8; 32],
            session_id:        [0xBBu8; 32],
        }
    }

    #[test]
    fn abi_encode_length() {
        let att = make_att();
        assert_eq!(att.abi_encode().len(), 352);
    }

    #[test]
    fn abi_roundtrip() {
        let att = make_att();
        let encoded = att.abi_encode();
        let decoded = OnChainAttestationSecp256k1::abi_decode(&encoded).unwrap();

        assert_eq!(decoded.statement_digest, att.statement_digest);
        assert_eq!(decoded.dvrf_value,        att.dvrf_value);
        assert_eq!(decoded.envelope_digest,   att.envelope_digest);
        assert_eq!(decoded.group_key_x,       att.group_key_x);
        assert_eq!(decoded.group_key_y,       att.group_key_y);
        assert_eq!(decoded.sig_R_x,           att.sig_R_x);
        assert_eq!(decoded.sig_s,             att.sig_s);
        assert_eq!(decoded.threshold,         3);
        assert_eq!(decoded.verifier_count,    5);
        assert_eq!(decoded.alpha_commitment,  att.alpha_commitment);
        assert_eq!(decoded.session_id,        att.session_id);
    }

    #[test]
    fn abi_decode_wrong_length_fails() {
        assert!(OnChainAttestationSecp256k1::abi_decode(&[0u8; 256]).is_err());
        assert!(OnChainAttestationSecp256k1::abi_decode(&[0u8; 512]).is_err());
    }

    #[test]
    fn threshold_at_correct_byte() {
        let att = make_att();
        let enc = att.abi_encode();
        assert_eq!(enc[255], 3, "threshold at byte 255");
        assert_eq!(enc[287], 5, "verifier_count at byte 287");
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn statement_digest_deterministic() {
        let d1 = OnChainAttestationSecp256k1::statement_digest_for("test/v1", b"claim");
        let d2 = OnChainAttestationSecp256k1::statement_digest_for("test/v1", b"claim");
        assert_eq!(d1, d2);
    }
}