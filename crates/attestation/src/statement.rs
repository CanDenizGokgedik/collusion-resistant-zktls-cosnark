//! Statement payload and derivation.
//!
//! The `StatementPayload` is the application-defined claim being attested.
//! Its digest is bound to the session transcript so that a valid statement
//! cannot be detached from the session that produced it.

use serde::{Deserialize, Serialize};
use tls_attestation_core::hash::{CanonicalHasher, DigestBytes};

/// The application-level statement being attested.
///
/// `content` is opaque to the protocol layer — it is application-defined bytes
/// that the prover and consumer agree on. The `derivation_tag` disambiguates
/// statement types within the same protocol deployment.
///
/// # Binding
///
/// The `statement_digest` binds the content to the session transcript,
/// preventing a valid statement from being separated from the session that
/// produced it and reused in another context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementPayload {
    /// Application-defined statement content. Opaque to the protocol.
    pub content: Vec<u8>,
    /// Domain tag identifying the type of statement.
    /// Must be non-empty and agreed upon by protocol participants.
    pub derivation_tag: String,
    /// H("statement/v1" || derivation_tag || session_transcript_digest || content)
    pub statement_digest: DigestBytes,
}

/// Derive the canonical digest of a statement payload.
///
/// # Field order (canonical)
///
/// 1. derivation_tag (length-prefixed bytes)
/// 2. session_transcript_digest (32 bytes fixed)
/// 3. content (length-prefixed bytes)
pub fn derive_statement_digest(
    derivation_tag: &str,
    session_transcript_digest: &DigestBytes,
    content: &[u8],
) -> DigestBytes {
    let mut h = CanonicalHasher::new("tls-attestation/statement/v1");
    h.update_bytes(derivation_tag.as_bytes());
    h.update_digest(session_transcript_digest);
    h.update_bytes(content);
    h.finalize()
}

impl StatementPayload {
    /// Construct a `StatementPayload`, computing the canonical digest.
    pub fn new(
        content: Vec<u8>,
        derivation_tag: String,
        session_transcript_digest: &DigestBytes,
    ) -> Self {
        let statement_digest =
            derive_statement_digest(&derivation_tag, session_transcript_digest, &content);
        Self {
            content,
            derivation_tag,
            statement_digest,
        }
    }

    /// Verify the stored `statement_digest` against the provided context.
    ///
    /// Returns `true` iff the digest is consistent with the content and transcript.
    pub fn verify_digest(&self, session_transcript_digest: &DigestBytes) -> bool {
        let expected =
            derive_statement_digest(&self.derivation_tag, session_transcript_digest, &self.content);
        self.statement_digest == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::hash::DigestBytes;

    #[test]
    fn statement_digest_is_deterministic() {
        let transcript_digest = DigestBytes::from_bytes([1u8; 32]);
        let s1 = StatementPayload::new(b"claim".to_vec(), "type-a/v1".into(), &transcript_digest);
        let s2 = StatementPayload::new(b"claim".to_vec(), "type-a/v1".into(), &transcript_digest);
        assert_eq!(s1.statement_digest, s2.statement_digest);
    }

    #[test]
    fn statement_verify_digest_succeeds() {
        let t = DigestBytes::from_bytes([5u8; 32]);
        let s = StatementPayload::new(b"content".to_vec(), "tag/v1".into(), &t);
        assert!(s.verify_digest(&t));
    }

    #[test]
    fn tampered_content_fails_verify() {
        let t = DigestBytes::from_bytes([5u8; 32]);
        let mut s = StatementPayload::new(b"original".to_vec(), "tag/v1".into(), &t);
        s.content = b"tampered".to_vec();
        assert!(!s.verify_digest(&t));
    }

    #[test]
    fn different_tags_produce_different_digests() {
        let t = DigestBytes::from_bytes([1u8; 32]);
        let a = derive_statement_digest("tag-a", &t, b"data");
        let b = derive_statement_digest("tag-b", &t, b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn different_transcript_digests_produce_different_statement_digests() {
        let t1 = DigestBytes::from_bytes([1u8; 32]);
        let t2 = DigestBytes::from_bytes([2u8; 32]);
        let a = derive_statement_digest("tag", &t1, b"data");
        let b = derive_statement_digest("tag", &t2, b"data");
        assert_ne!(a, b);
    }
}
