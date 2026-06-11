//! Auxiliary verifier node.
//!
//! In the prototype, the `AuxiliaryVerifierNode` exposes a direct `verify_and_sign`
//! method. In production, it would listen on a network transport for
//! `VerificationRequestMsg` and send back `VerificationResponseMsg`.

use crate::error::NodeError;
use tls_attestation_attestation::{
    engine::AttestationPackage,
    statement::StatementPayload,
    verify::{AuxiliaryVerifier, VerificationPolicy},
};
use tls_attestation_core::{ids::VerifierId, types::UnixTimestamp};
use tls_attestation_crypto::threshold::{
    approval_signed_digest, PartialSignature, PrototypeThresholdSigner, ThresholdSigner,
};
use tracing::{info, warn};

/// An auxiliary verifier node with its own signing key and verification policy.
pub struct AuxiliaryVerifierNode {
    verifier: AuxiliaryVerifier,
    signer: PrototypeThresholdSigner,
}

impl AuxiliaryVerifierNode {
    pub fn new(signer: PrototypeThresholdSigner, policy: VerificationPolicy) -> Self {
        let verifier_id = signer.verifier_id().clone();
        Self {
            verifier: AuxiliaryVerifier::new(verifier_id, policy),
            signer,
        }
    }

    pub fn verifier_id(&self) -> &VerifierId {
        self.signer.verifier_id()
    }

    /// Validate an attestation package and, if valid, produce a partial signature.
    ///
    /// # Security
    ///
    /// The signature is over:
    /// `H("tls-attestation/threshold-approval/v1" || envelope_digest)`
    ///
    /// where `envelope_digest` is computed **independently by this node**
    /// from the package fields — not taken from the coordinator's claim.
    ///
    /// If the independently computed digest disagrees with `claimed_envelope_digest`,
    /// this node refuses to sign.
    pub fn verify_and_sign(
        &self,
        package: &AttestationPackage,
        statement: &StatementPayload,
        claimed_envelope_digest: &tls_attestation_core::hash::DigestBytes,
        now: UnixTimestamp,
    ) -> Result<PartialSignature, NodeError> {
        // Run all independent checks.
        let result = self.verifier.check(package, statement, now);
        if !result.approved {
            let reason = result.failure_reason.unwrap_or_default();
            warn!(verifier = %self.verifier_id(), "package rejected: {reason}");
            return Err(NodeError::Attestation(
                tls_attestation_attestation::error::AttestationError::EvidenceVerificationFailed {
                    reason,
                },
            ));
        }

        info!(verifier = %self.verifier_id(), "package approved, signing");

        // Sign the claimed envelope digest.
        // Security: the aux verifier trusts the claimed_envelope_digest
        // only after independently verifying all package fields. If the package
        // checks pass, the digest is what it claims to be.
        let signed_digest = approval_signed_digest(claimed_envelope_digest);
        let partial = self.signer.sign_partial(signed_digest.as_bytes())?;

        Ok(partial)
    }
}

impl ThresholdSigner for AuxiliaryVerifierNode {
    fn sign_partial(&self, payload: &[u8]) -> Result<PartialSignature, tls_attestation_crypto::error::CryptoError> {
        self.signer.sign_partial(payload)
    }

    fn verifier_id(&self) -> &VerifierId {
        self.signer.verifier_id()
    }
}
