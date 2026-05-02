//! Canonical hashing utilities for the attestation protocol.
//!
//! # Design principles
//!
//! 1. **Domain separation**: Every hash context is prefixed with a domain tag.
//!    This prevents cross-context substitution attacks — a hash produced under
//!    one domain cannot be repurposed as a valid hash under another.
//!
//! 2. **Length prefixing**: Variable-length byte slices are always prefixed with
//!    their length (u64 big-endian). This prevents boundary ambiguity and
//!    extension attacks.
//!
//! 3. **Determinism**: The hash of any value must be identical across platforms,
//!    invocations, and languages. Field ordering is fixed and documented.
//!
//! 4. **Algorithm**: SHA-256. Conservative, widely supported, verifiable in
//!    Ethereum smart contracts via the `sha256` precompile.
//!
//! # Security note
//!
//! Always add fields to `CanonicalHasher` in the documented canonical order.
//! Adding fields in a different order produces a different hash. The canonical
//! order for each type is documented in `docs/PROTOCOL.md`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A 32-byte cryptographic digest used throughout the protocol.
///
/// Used as a commitment, content fingerprint, or session binding value.
/// Always construct via hashing, never by arbitrary byte assignment in
/// production paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DigestBytes([u8; 32]);

impl DigestBytes {
    /// The all-zeros digest, used as a sentinel/placeholder value.
    /// Never appears as the output of a real hash with overwhelming probability.
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// XOR two digests. Used only in the prototype DVRF — not for general use.
    ///
    /// # Security
    ///
    /// XOR combination of hash outputs preserves uniformity only when all
    /// inputs are independently random. Do not use in production randomness
    /// combination without a real DVRF.
    #[doc(hidden)]
    pub fn xor_with(&self, other: &DigestBytes) -> DigestBytes {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i] ^ other.0[i];
        }
        DigestBytes(result)
    }
}

impl fmt::Display for DigestBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// Compute SHA-256 of raw bytes.
pub fn sha256(data: &[u8]) -> DigestBytes {
    DigestBytes(Sha256::digest(data).into())
}

/// Compute SHA-256 with a domain separation tag.
///
/// Encoding: `SHA-256(len_be32(domain) || domain_bytes || data)`
///
/// The 4-byte length prefix on the domain prevents a crafted domain string
/// from overlapping with the data.
pub fn sha256_tagged(domain: &str, data: &[u8]) -> DigestBytes {
    let mut h = Sha256::new();
    let tag = domain.as_bytes();
    h.update((tag.len() as u32).to_be_bytes());
    h.update(tag);
    h.update(data);
    DigestBytes(h.finalize().into())
}

/// A builder for deterministic multi-field hashing.
///
/// Always construct with a domain tag, then add fields in the documented
/// canonical order, then call `finalize()`.
///
/// # Example
///
/// ```rust
/// use tls_attestation_core::hash::CanonicalHasher;
///
/// let mut h = CanonicalHasher::new("my-domain/v1");
/// h.update_fixed(&[1u8; 32]);
/// h.update_u64(42);
/// h.update_bytes(b"hello");
/// let digest = h.finalize();
/// ```
pub struct CanonicalHasher {
    inner: Sha256,
}

impl CanonicalHasher {
    /// Create a new hasher tagged with the given domain string.
    ///
    /// Domain encoding: `len_be32(domain) || domain_bytes` prepended to all input.
    pub fn new(domain: &str) -> Self {
        let mut h = Sha256::new();
        let tag = domain.as_bytes();
        h.update((tag.len() as u32).to_be_bytes());
        h.update(tag);
        Self { inner: h }
    }

    /// Add a variable-length byte slice (length-prefixed with u64 big-endian).
    pub fn update_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update((data.len() as u64).to_be_bytes());
        self.inner.update(data);
        self
    }

    /// Add a fixed-size byte array (no length prefix — length is statically known).
    pub fn update_fixed<const N: usize>(&mut self, data: &[u8; N]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Add a u64 in big-endian encoding.
    pub fn update_u64(&mut self, v: u64) -> &mut Self {
        self.inner.update(v.to_be_bytes());
        self
    }

    /// Add a u32 in big-endian encoding.
    pub fn update_u32(&mut self, v: u32) -> &mut Self {
        self.inner.update(v.to_be_bytes());
        self
    }

    /// Add a boolean (0x00 = false, 0x01 = true).
    pub fn update_bool(&mut self, v: bool) -> &mut Self {
        self.inner.update([v as u8]);
        self
    }

    /// Add a `DigestBytes` value (fixed 32 bytes, no length prefix).
    pub fn update_digest(&mut self, d: &DigestBytes) -> &mut Self {
        self.inner.update(d.as_bytes());
        self
    }

    /// Finalize and return the digest. Consumes the hasher.
    pub fn finalize(self) -> DigestBytes {
        DigestBytes(self.inner.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_deterministic() {
        let a = sha256(b"hello world");
        let b = sha256(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_domain_separation() {
        let a = sha256_tagged("domain-a", b"data");
        let b = sha256_tagged("domain-b", b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn sha256_tagged_differs_from_plain() {
        let a = sha256(b"data");
        let b = sha256_tagged("tag", b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_hasher_is_deterministic() {
        let build = || {
            let mut h = CanonicalHasher::new("test/v1");
            h.update_fixed(&[0xABu8; 32]);
            h.update_u64(12345);
            h.update_bytes(b"payload");
            h.finalize()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn canonical_hasher_field_order_matters() {
        let mut h1 = CanonicalHasher::new("test/v1");
        h1.update_u64(1);
        h1.update_u64(2);
        let d1 = h1.finalize();

        let mut h2 = CanonicalHasher::new("test/v1");
        h2.update_u64(2);
        h2.update_u64(1);
        let d2 = h2.finalize();

        assert_ne!(d1, d2);
    }

    #[test]
    fn canonical_hasher_length_prefix_prevents_ambiguity() {
        // "ab" + "c" should differ from "a" + "bc"
        let mut h1 = CanonicalHasher::new("test/v1");
        h1.update_bytes(b"ab");
        h1.update_bytes(b"c");
        let d1 = h1.finalize();

        let mut h2 = CanonicalHasher::new("test/v1");
        h2.update_bytes(b"a");
        h2.update_bytes(b"bc");
        let d2 = h2.finalize();

        assert_ne!(d1, d2);
    }

    #[test]
    fn domain_separation_prevents_cross_context_collision() {
        let a = CanonicalHasher::new("session-id/v1");
        let b = CanonicalHasher::new("randomness/v1");
        // Even with identical subsequent fields, different domains differ.
        let da = a.finalize();
        let db = b.finalize();
        assert_ne!(da, db);
    }

    #[test]
    fn xor_with_is_symmetric() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        assert_eq!(a.xor_with(&b), b.xor_with(&a));
    }

    #[test]
    fn xor_with_self_is_zero() {
        let a = sha256(b"a");
        assert_eq!(a.xor_with(&a), DigestBytes::ZERO);
    }
}
