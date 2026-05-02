//! Transcript commitment primitives.
//!
//! The transcript represents the attested interaction: a query sent to a remote
//! server and the response received. Both are committed to using session-scoped
//! hashes so that the commitment cannot be detached from the session context.
//!
//! # Security
//!
//! The randomness value is mixed into all transcript commitments. This ensures
//! that a valid commitment to a transcript in one session cannot be copied into
//! another session (where the randomness value would differ).

use serde::{Deserialize, Serialize};
use tls_attestation_core::hash::{CanonicalHasher, DigestBytes};
use tls_attestation_core::ids::SessionId;

/// A single transcript commitment binding a data blob to the session context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptCommitment {
    /// Domain tag identifying the role of this commitment (e.g., "query", "response").
    pub role: String,
    /// H(domain || session_id || randomness_value || data)
    pub digest: DigestBytes,
}

impl TranscriptCommitment {
    /// Compute a commitment to `data` scoped to `session_id` and `randomness`.
    ///
    /// The `role` tag domain-separates query commitments from response commitments.
    pub fn compute(
        role: &str,
        session_id: &SessionId,
        randomness_value: &DigestBytes,
        data: &[u8],
    ) -> Self {
        let domain = format!("tls-attestation/transcript/{role}/v1");
        let mut h = CanonicalHasher::new(&domain);
        h.update_fixed(session_id.as_bytes());
        h.update_digest(randomness_value);
        h.update_bytes(data);
        Self {
            role: role.to_string(),
            digest: h.finalize(),
        }
    }

    /// Verify that this commitment is consistent with the provided data and context.
    pub fn verify(
        &self,
        session_id: &SessionId,
        randomness_value: &DigestBytes,
        data: &[u8],
    ) -> bool {
        let expected = Self::compute(&self.role, session_id, randomness_value, data);
        self.digest == expected.digest
    }
}

/// The full set of transcript commitments for one attestation session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptCommitments {
    /// Commitment to the query sent to the remote.
    pub query: TranscriptCommitment,
    /// Commitment to the response received from the remote.
    pub response: TranscriptCommitment,
    /// Combined commitment over both query and response.
    ///
    /// `H("session-transcript/v1" || session_id || query_digest || response_digest)`
    pub session_transcript_digest: DigestBytes,
}

impl TranscriptCommitments {
    /// Build `TranscriptCommitments` from raw query and response bytes.
    pub fn build(
        session_id: &SessionId,
        randomness_value: &DigestBytes,
        query: &[u8],
        response: &[u8],
    ) -> Self {
        let query_commitment =
            TranscriptCommitment::compute("query", session_id, randomness_value, query);
        let response_commitment =
            TranscriptCommitment::compute("response", session_id, randomness_value, response);

        let session_transcript_digest = {
            let mut h = CanonicalHasher::new("tls-attestation/session-transcript/v1");
            h.update_fixed(session_id.as_bytes());
            h.update_digest(&query_commitment.digest);
            h.update_digest(&response_commitment.digest);
            h.finalize()
        };

        Self {
            query: query_commitment,
            response: response_commitment,
            session_transcript_digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::ids::SessionId;

    #[test]
    fn commitment_is_deterministic() {
        let sid = SessionId::from_bytes([1u8; 16]);
        let rng = DigestBytes::from_bytes([2u8; 32]);
        let data = b"query data";

        let c1 = TranscriptCommitment::compute("query", &sid, &rng, data);
        let c2 = TranscriptCommitment::compute("query", &sid, &rng, data);
        assert_eq!(c1.digest, c2.digest);
    }

    #[test]
    fn commitment_verifies() {
        let sid = SessionId::from_bytes([1u8; 16]);
        let rng = DigestBytes::from_bytes([2u8; 32]);
        let data = b"query data";
        let c = TranscriptCommitment::compute("query", &sid, &rng, data);
        assert!(c.verify(&sid, &rng, data));
    }

    #[test]
    fn commitment_fails_for_wrong_data() {
        let sid = SessionId::from_bytes([1u8; 16]);
        let rng = DigestBytes::from_bytes([2u8; 32]);
        let c = TranscriptCommitment::compute("query", &sid, &rng, b"original");
        assert!(!c.verify(&sid, &rng, b"tampered"));
    }

    #[test]
    fn role_separation() {
        let sid = SessionId::from_bytes([1u8; 16]);
        let rng = DigestBytes::from_bytes([2u8; 32]);
        let data = b"same data";
        let q = TranscriptCommitment::compute("query", &sid, &rng, data);
        let r = TranscriptCommitment::compute("response", &sid, &rng, data);
        assert_ne!(q.digest, r.digest);
    }

    #[test]
    fn different_sessions_produce_different_commitments() {
        let rng = DigestBytes::from_bytes([1u8; 32]);
        let data = b"data";
        let c1 = TranscriptCommitment::compute("query", &SessionId::from_bytes([1u8; 16]), &rng, data);
        let c2 = TranscriptCommitment::compute("query", &SessionId::from_bytes([2u8; 16]), &rng, data);
        assert_ne!(c1.digest, c2.digest);
    }

    #[test]
    fn build_transcript_commitments() {
        let sid = SessionId::from_bytes([5u8; 16]);
        let rng = DigestBytes::from_bytes([6u8; 32]);
        let tc = TranscriptCommitments::build(&sid, &rng, b"GET /api", b"200 OK");
        assert!(tc.query.verify(&sid, &rng, b"GET /api"));
        assert!(tc.response.verify(&sid, &rng, b"200 OK"));
    }
}
