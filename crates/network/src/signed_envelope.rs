//! Layer 3: ed25519-signed message envelope.
//!
//! # Wire format
//!
//! Every authenticated message is a `SignedEnvelope` serialised as JSON and
//! framed with the standard 4-byte length prefix (see `codec`).
//!
//! The envelope carries:
//!
//! ```text
//! {
//!   "sender_id": <32-byte hex VerifierId>,
//!   "timestamp": <u64 Unix seconds>,
//!   "payload":   <base64-encoded JSON bytes of the inner message>,
//!   "signature": <base64-encoded 64-byte ed25519 signature>
//! }
//! ```
//!
//! # What is signed
//!
//! The signature covers a domain-separated byte string:
//!
//! ```text
//! b"tls-attestation/signed-envelope/v1\x00"
//!   || sender_id (32 bytes)
//!   || timestamp (8 bytes big-endian)
//!   || payload   (variable)
//! ```
//!
//! Including `sender_id` and `timestamp` in the signed bytes prevents:
//! - **Sender impersonation**: a message signed by A cannot be re-attributed to B.
//! - **Replay attacks**: the 30-second timestamp window rejects replayed frames.
//!
//! # Replay protection
//!
//! `TIMESTAMP_TOLERANCE_SECS` (30 s) is the maximum age (or future skew) a
//! message timestamp may have.  Clocks must be roughly synchronised.
//! For production deployments, use NTP or a similar time source.
//!
//! # Authentication vs. confidentiality
//!
//! `SignedEnvelope` provides **integrity and authenticity only** — the payload
//! is visible to any observer.  Add TLS (Layer 4) for confidentiality.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use tls_attestation_core::ids::VerifierId;

use crate::error::NetworkError;

/// Maximum clock skew / message age accepted (30 seconds).
pub const TIMESTAMP_TOLERANCE_SECS: u64 = 30;

/// Domain separator for the signed bytes.
const DOMAIN: &[u8] = b"tls-attestation/signed-envelope/v1\x00";

// ── SignedEnvelope ────────────────────────────────────────────────────────────

/// An authenticated wrapper around any JSON-serializable message.
///
/// Created with [`SignedEnvelope::seal`] and verified with
/// [`SignedEnvelope::open`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    /// The verifier identity of the sender.
    ///
    /// Receivers look up the corresponding `VerifyingKey` in their
    /// `EnvelopeKeyRegistry` before verifying the signature.
    #[serde(with = "verifier_id_serde")]
    pub sender_id: VerifierId,

    /// Unix timestamp (seconds) when this envelope was created.
    ///
    /// Must be within `TIMESTAMP_TOLERANCE_SECS` of the receiver's clock.
    pub timestamp: u64,

    /// JSON-serialized inner message bytes.
    #[serde(with = "bytes_base64")]
    pub payload: Vec<u8>,

    /// ed25519 signature over `DOMAIN || sender_id || timestamp_be || payload`.
    #[serde(with = "sig_serde")]
    pub signature: [u8; 64],
}

impl SignedEnvelope {
    // ── Seal (sign) ───────────────────────────────────────────────────────────

    /// Serialize `message` to JSON, sign it, and wrap in an envelope.
    ///
    /// `signing_key` is the sender's private key.
    /// `sender_id` is the sender's protocol identity (the public verifier ID).
    pub fn seal<T: Serialize>(
        sender_id: &VerifierId,
        signing_key: &SigningKey,
        message: &T,
    ) -> Result<Self, NetworkError> {
        let payload = serde_json::to_vec(message)
            .map_err(|e| NetworkError::Serialization(format!("seal: serialize payload: {e}")))?;

        let timestamp = current_unix_secs();
        let to_sign = signing_bytes(sender_id, timestamp, &payload);
        let sig = signing_key.sign(&to_sign);

        Ok(SignedEnvelope {
            sender_id: sender_id.clone(),
            timestamp,
            payload,
            signature: sig.to_bytes(),
        })
    }

    // ── Open (verify + deserialize) ───────────────────────────────────────────

    /// Verify the envelope's signature and timestamp, then deserialize the
    /// inner message.
    ///
    /// `registry` maps sender identities to their `VerifyingKey`s.
    /// `now` is the verifier's current Unix timestamp in seconds.
    ///
    /// # Errors
    ///
    /// - `AuthFailed("unknown sender …")` if the sender is not in `registry`.
    /// - `AuthFailed("timestamp out of range …")` if the timestamp is stale or
    ///   too far in the future.
    /// - `AuthFailed("signature verification failed")` if the signature is wrong.
    /// - `Serialization(…)` if the payload cannot be deserialized as `T`.
    pub fn open<T: for<'de> Deserialize<'de>>(
        &self,
        registry: &EnvelopeKeyRegistry,
        now: u64,
    ) -> Result<T, NetworkError> {
        // ── 1. Sender known? ──────────────────────────────────────────────
        let verifying_key = registry
            .lookup(&self.sender_id)
            .ok_or_else(|| {
                NetworkError::AuthFailed(format!("unknown sender: {}", self.sender_id))
            })?;

        // ── 2. Timestamp window ───────────────────────────────────────────
        let age = now.saturating_sub(self.timestamp);
        let skew = self.timestamp.saturating_sub(now);
        if age > TIMESTAMP_TOLERANCE_SECS || skew > TIMESTAMP_TOLERANCE_SECS {
            return Err(NetworkError::AuthFailed(format!(
                "timestamp out of range: envelope_ts={} now={} (tolerance={}s)",
                self.timestamp, now, TIMESTAMP_TOLERANCE_SECS
            )));
        }

        // ── 3. Signature ──────────────────────────────────────────────────
        let to_sign = signing_bytes(&self.sender_id, self.timestamp, &self.payload);
        let sig = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&to_sign, &sig)
            .map_err(|_| NetworkError::AuthFailed("signature verification failed".into()))?;

        // ── 4. Deserialize payload ────────────────────────────────────────
        serde_json::from_slice(&self.payload)
            .map_err(|e| NetworkError::Serialization(format!("open: deserialize payload: {e}")))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build the canonical byte string that is signed / verified.
fn signing_bytes(sender_id: &VerifierId, timestamp: u64, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DOMAIN.len() + 32 + 8 + payload.len());
    buf.extend_from_slice(DOMAIN);
    buf.extend_from_slice(sender_id.as_bytes());
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── EnvelopeKeyRegistry ───────────────────────────────────────────────────────

/// Registry mapping sender identities to their `VerifyingKey`s.
///
/// Used by receivers to look up the public key for an incoming `SignedEnvelope`.
///
/// # Mutability
///
/// The registry is immutable after construction. Build it once (at node startup
/// from a `ParticipantRegistry` or static config) and share via `Arc`.
#[derive(Debug, Clone)]
pub struct EnvelopeKeyRegistry {
    keys: HashMap<VerifierId, VerifyingKey>,
}

impl EnvelopeKeyRegistry {
    /// Build a registry from an iterator of `(VerifierId, VerifyingKey)` pairs.
    pub fn new(entries: impl IntoIterator<Item = (VerifierId, VerifyingKey)>) -> Self {
        Self {
            keys: entries.into_iter().collect(),
        }
    }

    /// Look up the verifying key for a sender.
    pub fn lookup(&self, id: &VerifierId) -> Option<&VerifyingKey> {
        self.keys.get(id)
    }

    /// Number of registered keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True if the registry contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ── Serde helpers ─────────────────────────────────────────────────────────────

mod verifier_id_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(id: &VerifierId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(id.as_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifierId, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            serde::de::Error::custom("verifier_id must be 32 bytes")
        })?;
        Ok(VerifierId::from_bytes(arr))
    }
}

mod bytes_base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

mod sig_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(sig))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| {
            serde::de::Error::custom("signature must be 64 bytes")
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_keypair() -> (VerifierId, SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let vid = VerifierId::from_bytes(vk.to_bytes());
        (vid, sk, vk)
    }

    fn registry_for(vid: &VerifierId, vk: &VerifyingKey) -> EnvelopeKeyRegistry {
        EnvelopeKeyRegistry::new([(vid.clone(), vk.clone())])
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let (vid, sk, vk) = make_keypair();
        let registry = registry_for(&vid, &vk);
        let now = current_unix_secs();

        let msg = serde_json::json!({"hello": "world"});
        let env = SignedEnvelope::seal(&vid, &sk, &msg).unwrap();

        let decoded: serde_json::Value = env.open(&registry, now).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn tampered_payload_rejected() {
        let (vid, sk, vk) = make_keypair();
        let registry = registry_for(&vid, &vk);
        let now = current_unix_secs();

        let mut env = SignedEnvelope::seal(&vid, &sk, &"original").unwrap();
        env.payload = serde_json::to_vec(&"tampered").unwrap();

        let result: Result<String, _> = env.open(&registry, now);
        assert!(
            matches!(result, Err(NetworkError::AuthFailed(_))),
            "tampered payload must be rejected"
        );
    }

    #[test]
    fn unknown_sender_rejected() {
        let (vid, sk, _vk) = make_keypair();
        let empty_registry = EnvelopeKeyRegistry::new([]);
        let now = current_unix_secs();

        let env = SignedEnvelope::seal(&vid, &sk, &"msg").unwrap();
        let result: Result<String, _> = env.open(&empty_registry, now);
        assert!(matches!(result, Err(NetworkError::AuthFailed(_))));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (vid, sk, vk) = make_keypair();
        let registry = registry_for(&vid, &vk);

        let mut env = SignedEnvelope::seal(&vid, &sk, &"msg").unwrap();
        // Backdate by 2× the tolerance to ensure rejection.
        env.timestamp = current_unix_secs().saturating_sub(TIMESTAMP_TOLERANCE_SECS * 2);

        let now = current_unix_secs();
        let result: Result<String, _> = env.open(&registry, now);
        assert!(
            matches!(result, Err(NetworkError::AuthFailed(_))),
            "stale timestamp must be rejected"
        );
    }

    #[test]
    fn future_timestamp_rejected() {
        let (vid, sk, vk) = make_keypair();
        let registry = registry_for(&vid, &vk);

        let mut env = SignedEnvelope::seal(&vid, &sk, &"msg").unwrap();
        env.timestamp = current_unix_secs() + TIMESTAMP_TOLERANCE_SECS + 5;

        let now = current_unix_secs();
        let result: Result<String, _> = env.open(&registry, now);
        assert!(matches!(result, Err(NetworkError::AuthFailed(_))));
    }

    #[test]
    fn wrong_signing_key_rejected() {
        let (vid, _sk, vk) = make_keypair();
        let registry = registry_for(&vid, &vk);
        let now = current_unix_secs();

        // Sign with a different key.
        let other_sk = SigningKey::generate(&mut OsRng);
        let env = SignedEnvelope::seal(&vid, &other_sk, &"msg").unwrap();

        let result: Result<String, _> = env.open(&registry, now);
        assert!(matches!(result, Err(NetworkError::AuthFailed(_))));
    }

    #[test]
    fn sender_id_in_signature_prevents_impersonation() {
        let (vid_a, sk_a, vk_a) = make_keypair();
        let (vid_b, _sk_b, vk_b) = make_keypair();

        // Registry knows A and B.
        let registry = EnvelopeKeyRegistry::new([
            (vid_a.clone(), vk_a),
            (vid_b.clone(), vk_b),
        ]);
        let now = current_unix_secs();

        // A signs a message.
        let mut env = SignedEnvelope::seal(&vid_a, &sk_a, &"secret").unwrap();
        // Attacker replaces sender_id with B's identity.
        env.sender_id = vid_b.clone();

        // Verification must fail: the signature was made with A's key under A's ID.
        let result: Result<String, _> = env.open(&registry, now);
        assert!(
            matches!(result, Err(NetworkError::AuthFailed(_))),
            "impersonation via sender_id swap must be rejected"
        );
    }
}