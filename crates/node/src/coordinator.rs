//! Coordinator node orchestration.
//!
//! The `CoordinatorNode` drives the full session lifecycle from attestation
//! request receipt to final envelope assembly. It:
//!
//! 1. Creates the session and persists it.
//! 2. Generates DVRF randomness using the `RandomnessEngine`.
//! 3. Runs the `AttestationEngine` to produce evidence.
//! 4. Sends the `AttestationPackage` to all aux verifiers.
//! 5. Collects threshold approvals.
//! 6. Assembles the `AttestationEnvelope`.
//!
//! # Trust model
//!
//! The coordinator is semi-trusted. It cannot forge aux verifier signatures.
//! But it can attempt to:
//! - Substitute a different randomness value → caught by aux verifier
//!   session binding check.
//! - Tamper with the package before sending → caught by aux verifier
//!   package digest check.
//! - Fail to collect enough signatures → results in `QuorumNotMet`.

use crate::error::NodeError;
use ed25519_dalek::VerifyingKey;
use tls_attestation_crypto::participant_registry::{ParticipantRegistry, RegistryEpoch};
use tls_attestation_attestation::{
    engine::{AttestationEngine, AttestationPackage, CoordinatorEvidence},
    envelope::{AttestationEnvelope, RandomnessBinding},
    session::{Session, SessionContext, SessionState},
    statement::StatementPayload,
};
use tls_attestation_core::{
    ids::{SessionId, VerifierId},
    types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
};
use tls_attestation_crypto::{
    randomness::RandomnessEngine,
    threshold::{aggregate_signatures, approval_signed_digest, PartialSignature, ThresholdSigner},
};
use tls_attestation_network::messages::{AttestationRequest, AttestationResponse};
use tls_attestation_storage::traits::SessionStore;
use tracing::{info, warn};

/// Configuration for a coordinator node.
///
/// # Verifier public key source
///
/// `verifier_public_keys` is the trust anchor for approval signature verification.
/// **Prefer constructing this from a `ParticipantRegistry` snapshot** via
/// `CoordinatorConfig::from_registry` to ensure only currently `Active`
/// participants can produce valid approvals. Constructing from a raw key list
/// bypasses revocation and epoch checks.
pub struct CoordinatorConfig {
    pub coordinator_id: VerifierId,
    pub epoch: Epoch,
    pub quorum: QuorumSpec,
    /// Default session TTL in seconds.
    pub default_ttl_secs: u64,
    /// Verifier public keys for approval verification.
    ///
    /// In production, populate this from `ParticipantRegistry::active_verifier_keys()`
    /// via `CoordinatorConfig::from_registry`. Raw construction is supported for
    /// tests and single-operator bootstraps but bypasses revocation checks.
    pub verifier_public_keys: Vec<(VerifierId, VerifyingKey)>,
}

impl CoordinatorConfig {
    /// Construct a `CoordinatorConfig` from a `ParticipantRegistry` snapshot.
    ///
    /// Only `Active` participants contribute to `verifier_public_keys`. Revoked
    /// and retired participants cannot produce valid approvals under this config.
    ///
    /// `epoch` is set to the registry's epoch (as a `u64` value), aligning the
    /// coordinator's session epoch with the participant registry version.
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// let config = CoordinatorConfig::from_registry(
    ///     coordinator_id,
    ///     quorum,
    ///     3600,
    ///     &participant_registry,
    /// );
    /// ```
    pub fn from_registry(
        coordinator_id: VerifierId,
        quorum: QuorumSpec,
        default_ttl_secs: u64,
        registry: &ParticipantRegistry,
    ) -> Self {
        Self {
            coordinator_id,
            epoch: Epoch(registry.epoch().0),
            quorum,
            default_ttl_secs,
            verifier_public_keys: registry.active_verifier_keys(),
        }
    }
}

/// Output of Steps 1–5 (session setup) shared across all `attest*` variants.
struct PreparedSession {
    session_id:             SessionId,
    session_ctx:            SessionContext,
    session:                Session,
    /// Wall-clock time this session was created (needed by distributed round requests).
    now:                    tls_attestation_core::types::UnixTimestamp,
    /// Computed expiry timestamp (needed by `round_expires_at` in round requests).
    expires_at:             tls_attestation_core::types::UnixTimestamp,
    randomness_output:      tls_attestation_crypto::randomness::RandomnessOutput,
    transcript_commitments: tls_attestation_crypto::transcript::TranscriptCommitments,
    evidence:               tls_attestation_attestation::engine::ExportableEvidence,
    package:                AttestationPackage,
    statement:              StatementPayload,
    randomness_binding:     RandomnessBinding,
    coordinator_evidence:   CoordinatorEvidence,
    envelope_digest:        tls_attestation_core::hash::DigestBytes,
    signed_digest:          tls_attestation_core::hash::DigestBytes,
}

/// The coordinator node.
///
/// Generic over the storage, randomness, attestation, and signing backends
/// to allow swapping implementations in tests and production.
pub struct CoordinatorNode<S, R, A> {
    config: CoordinatorConfig,
    store: S,
    randomness_engine: R,
    attestation_engine: A,
}

impl<S, R, A> CoordinatorNode<S, R, A>
where
    S: SessionStore,
    R: RandomnessEngine,
    A: AttestationEngine,
{
    pub fn new(config: CoordinatorConfig, store: S, randomness_engine: R, attestation_engine: A) -> Self {
        Self {
            config,
            store,
            randomness_engine,
            attestation_engine,
        }
    }

    /// Run the full attestation protocol for one request.
    ///
    /// Returns an `AttestationEnvelope` on success, or a descriptive error.
    ///
    /// The `aux_signers` parameter provides the aux verifiers' signing interfaces
    /// for the prototype. In production, these would be remote calls over an
    /// authenticated transport.
    // ── Common session setup (Steps 1–5) ─────────────────────────────────────

    /// Prepare a session: create, generate randomness, run engine, build package,
    /// compute envelope digest.
    ///
    /// Extracted from `attest`, `attest_frost`, and `attest_frost_distributed_inner`
    /// to eliminate ~120 lines of copy-paste across the three code paths.
    /// All three were identical in Steps 1–5; only the signing step (Step 6+) differs.
    fn prepare_session(
        &self,
        request: &AttestationRequest,
        response: &[u8],
        label: &str,
    ) -> Result<PreparedSession, NodeError> {
        let now = UnixTimestamp::now();
        let expires_at =
            UnixTimestamp(now.0 + request.requested_ttl_secs.min(self.config.default_ttl_secs));

        // Step 1: Create session.
        let session_id = SessionId::new_random();
        let nonce = Nonce::random();
        let session_ctx = SessionContext::new(
            session_id.clone(),
            request.prover_id.clone(),
            self.config.coordinator_id.clone(),
            self.config.quorum.clone(),
            self.config.epoch,
            now,
            expires_at,
            nonce.clone(),
        );
        let mut session = Session::new(session_ctx.clone());
        self.store.insert(session.clone())?;
        info!(session_id = %session_id, "{label}: session created");

        // Step 2: Generate DVRF randomness.
        session.transition(SessionState::Active)?;
        self.store.update_state(&session_id, SessionState::Active)?;
        let randomness_output = self.randomness_engine.generate(
            &session_id,
            &nonce,
            self.config.epoch,
            &self.config.quorum.verifiers,
        )?;
        info!(session_id = %session_id, "{label}: randomness generated");

        // Step 3: Run attestation engine.
        session.transition(SessionState::Attesting)?;
        self.store.update_state(&session_id, SessionState::Attesting)?;
        let (transcript_commitments, evidence) = self.attestation_engine.execute(
            &session_ctx,
            &randomness_output.value,
            &request.query,
            response,
        )?;

        // Step 4: Build attestation package.
        let package = AttestationPackage::build(
            session_ctx.clone(),
            randomness_output.value.clone(),
            transcript_commitments.clone(),
            evidence.clone(),
        );
        let statement = StatementPayload::new(
            response.to_vec(),
            request.statement_tag.clone(),
            &transcript_commitments.session_transcript_digest,
        );

        // Step 5: Compute envelope digest.
        let randomness_binding = RandomnessBinding {
            id: randomness_output.id.clone(),
            value: randomness_output.value.clone(),
            epoch: randomness_output.epoch,
            session_binding: randomness_output.session_binding.clone(),
        };
        let coordinator_evidence = CoordinatorEvidence {
            engine_tag: evidence.engine_tag.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            package_digest: package.package_digest.clone(),
        };
        let envelope_digest = AttestationEnvelope::compute_digest(
            &session_ctx,
            &randomness_binding,
            &transcript_commitments,
            &statement,
            &coordinator_evidence,
        );
        let signed_digest = approval_signed_digest(&envelope_digest);

        Ok(PreparedSession {
            session_id,
            session_ctx,
            session,
            now,
            expires_at,
            randomness_output,
            transcript_commitments,
            evidence,
            package,
            statement,
            randomness_binding,
            coordinator_evidence,
            envelope_digest,
            signed_digest,
        })
    }

    pub fn attest(
        &self,
        request: AttestationRequest,
        response: &[u8],
        aux_signers: &[&dyn ThresholdSigner],
    ) -> Result<AttestationResponse, NodeError> {
        let PreparedSession {
            session_id,
            session_ctx,
            mut session,
            now: _now,
            expires_at,
            randomness_output,
            transcript_commitments,
            evidence,
            package,
            statement,
            randomness_binding,
            coordinator_evidence,
            envelope_digest,
            signed_digest,
        } = self.prepare_session(&request, response, "attest")?;

        // ── Step 6: Collect partial approvals ────────────────────────────────
        session.transition(SessionState::Collecting)?;
        self.store.update_state(&session_id, SessionState::Collecting)?;

        let mut partials: Vec<PartialSignature> = Vec::new();

        for signer in aux_signers {
            let verifier_id = signer.verifier_id().clone();

            // Replay protection: reject a verifier who has already approved
            // this session. Under normal operation this should never fire
            // (each signer appears once in aux_signers), but it defends against
            // a caller who accidentally or maliciously passes duplicate entries.
            if self.store.has_approved(&session_id, &verifier_id) {
                warn!(
                    session_id = %session_id,
                    verifier = %verifier_id,
                    "duplicate approval ignored (verifier already approved this session)"
                );
                continue;
            }

            // In production: send VerificationRequestMsg over network,
            // receive VerificationResponseMsg. The verifier independently
            // validates the package before signing.
            // Here: direct call for the prototype.
            match signer.sign_partial(signed_digest.as_bytes()) {
                Ok(partial) => {
                    // Record the approval before pushing to partials so that
                    // a storage failure is surfaced rather than silently dropped.
                    // If record_approval fails with DuplicateApproval, that is
                    // a logic bug (we just checked has_approved above), so we
                    // treat it as a hard error.
                    self.store.record_approval(&session_id, &verifier_id)?;
                    info!(
                        session_id = %session_id,
                        verifier = %partial.verifier_id,
                        "partial approval received and recorded"
                    );
                    partials.push(partial);
                }
                Err(e) => {
                    warn!(session_id = %session_id, verifier = %verifier_id, "partial signing failed: {e}");
                }
            }
        }

        // ── Step 7: Aggregate approvals ──────────────────────────────────────
        let threshold_approval = aggregate_signatures(
            partials,
            &self.config.quorum,
            &envelope_digest,
            &self.config.verifier_public_keys,
        )
        .map_err(|e| NodeError::Crypto(e))?;

        // ── Step 8: Assemble and return envelope ─────────────────────────────
        let envelope = AttestationEnvelope::assemble(
            session_ctx,
            randomness_binding,
            transcript_commitments,
            statement,
            coordinator_evidence,
            threshold_approval,
        );

        session.transition(SessionState::Finalized)?;
        self.store.update_state(&session_id, SessionState::Finalized)?;

        info!(session_id = %session_id, envelope_digest = %envelope.envelope_digest, "attestation finalized");

        Ok(AttestationResponse::Success(envelope))
    }
}

// ── FROST runtime integration ────────────────────────────────────────────────
//
// `attest_frost` runs the same session lifecycle as `attest` (Steps 1–5 are
// identical) but replaces the per-verifier ThresholdSigner calls with the real
// two-round FROST protocol via `frost_collect_approval`.
//
// # Design choices
//
// - `attest_frost` is an *additional* method, not a replacement.  The prototype
//   path remains untouched; callers opt in to FROST explicitly.
// - The return type is `FrostAttestationEnvelope` — a new struct that carries
//   `FrostThresholdApproval` instead of `ThresholdApproval`.  No existing types
//   are modified, so the prototype path stays binary-compatible.
// - Both FROST rounds run in-process.  A future network round-trip variant will
//   require exposing the round-1 commitments over the wire.
//
// # Restart / persistence gap
//
// FROST nonces (`FrostSigningNonces`) are ephemeral `!Clone` values created
// during `frost_collect_approval` and destroyed when the call returns.  If the
// coordinator crashes between entering `Collecting` and writing `Finalized`, the
// session will be stuck in `Collecting` in the store.  On restart the session
// cannot be resumed — re-run `attest_frost` with a fresh session instead.
// This gap is documented in `docs/FROST_INTEGRATION.md`.

/// The final output of the FROST attestation path.
///
/// Carries a `FrostThresholdApproval` (single 64-byte aggregate Schnorr
/// signature) rather than the prototype `ThresholdApproval` (a vector of
/// individual ed25519 signatures).  All other fields are identical in meaning
/// to `AttestationEnvelope`.
///
/// # Verification
///
/// ```text
/// 1. Recompute envelope_digest from the fields (same algorithm as
///    AttestationEnvelope::compute_digest).
/// 2. Verify frost_approval.verify_binding(&envelope_digest) — binds the
///    approval to this specific envelope.
/// 3. Verify frost_approval.verify_signature() — checks the aggregate
///    Schnorr signature against the embedded group verifying key.
/// 4. Independently verify that group_verifying_key_bytes matches the
///    expected group key for the quorum (from configuration).
/// ```
#[cfg(feature = "frost")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FrostAttestationEnvelope {
    pub session: tls_attestation_attestation::session::SessionContext,
    pub randomness: tls_attestation_attestation::envelope::RandomnessBinding,
    pub transcript: tls_attestation_crypto::transcript::TranscriptCommitments,
    pub statement: tls_attestation_attestation::statement::StatementPayload,
    pub coordinator_evidence: tls_attestation_attestation::engine::CoordinatorEvidence,
    /// The FROST aggregate approval: a single 64-byte Schnorr signature.
    pub frost_approval: tls_attestation_crypto::frost_adapter::FrostThresholdApproval,
    /// Canonical digest over all above fields (identical algorithm to
    /// `AttestationEnvelope::envelope_digest`).
    pub envelope_digest: tls_attestation_core::hash::DigestBytes,
}

#[cfg(feature = "frost")]
impl<S, R, A> CoordinatorNode<S, R, A>
where
    S: SessionStore,
    R: RandomnessEngine,
    A: AttestationEngine,
{
    /// Run the full attestation protocol using real FROST threshold signing.
    ///
    /// Steps 1–5 are identical to [`attest`].  Step 6 replaces the
    /// per-verifier `ThresholdSigner::sign_partial` calls with the two-round
    /// FROST protocol (`frost_collect_approval`), which produces a single
    /// 64-byte aggregate Schnorr signature.
    ///
    /// # Parameters
    ///
    /// - `frost_signers`: the FROST participants to involve in this signing
    ///   round.  Must include at least `quorum.threshold` participants whose
    ///   `verifier_id` and FROST identifier are registered in `group_key`.
    /// - `group_key`: the FROST group public key for this quorum.
    ///
    /// # Errors
    ///
    /// - `NodeError::Crypto(InsufficientSignatures)` if fewer than
    ///   `quorum.threshold` signers are provided.
    /// - `NodeError::Crypto(UnknownVerifier)` if any signer is not in
    ///   `group_key`.
    /// - `NodeError::QuorumNotMet` if `frost_signers` is empty or its
    ///   length falls below the threshold before FROST is invoked.
    ///
    /// # Restart safety
    ///
    /// FROST nonces are ephemeral.  If the coordinator crashes during this
    /// call, the session will be left in `Collecting` state and cannot be
    /// resumed.  Create a new session via a fresh `attest_frost` call instead.
    pub fn attest_frost(
        &self,
        request: AttestationRequest,
        response: &[u8],
        frost_signers: &[tls_attestation_crypto::frost_adapter::FrostParticipant],
        group_key: &tls_attestation_crypto::frost_adapter::FrostGroupKey,
    ) -> Result<FrostAttestationEnvelope, NodeError> {
        use tls_attestation_crypto::frost_adapter::frost_collect_approval;

        let PreparedSession {
            session_id,
            session_ctx,
            mut session,
            now,
            expires_at,
            randomness_output,
            transcript_commitments,
            evidence,
            package,
            statement,
            randomness_binding,
            coordinator_evidence,
            envelope_digest,
            signed_digest,
        } = self.prepare_session(&request, response, "FROST")?;

        // ── Step 6: FROST two-round threshold signing ─────────────────────
        session.transition(SessionState::Collecting)?;
        self.store.update_state(&session_id, SessionState::Collecting)?;

        // Early exit if the caller has not provided enough signers.  The
        // frost_collect_approval call below enforces the same constraint, but
        // we want to surface a NodeError::QuorumNotMet (not a CryptoError)
        // so the caller can distinguish "not enough participants provided" from
        // a cryptographic failure.
        if frost_signers.len() < self.config.quorum.threshold {
            let reason = format!(
                "insufficient FROST signers: need {}, got {}",
                self.config.quorum.threshold,
                frost_signers.len()
            );
            // Use session.fail() (infallible) rather than transition() so we
            // don't need to thread the Failed struct variant through a Result.
            session.fail(reason.clone());
            self.store
                .update_state(&session_id, SessionState::Failed { reason })?;
            return Err(NodeError::QuorumNotMet {
                received: frost_signers.len(),
                required: self.config.quorum.threshold,
            });
        }

        // Drive both FROST rounds in-process.  On success, `frost_approval`
        // contains the 64-byte aggregate Schnorr signature.
        let frost_approval =
            frost_collect_approval(frost_signers, &signed_digest, group_key, &self.config.quorum)
                .map_err(NodeError::Crypto)?;

        // Record each participant's approval for replay-protection bookkeeping.
        // Because this session was just created, none of these should already
        // have entries — a DuplicateApproval error here is a logic bug.
        for signer in frost_signers {
            self.store.record_approval(&session_id, &signer.verifier_id)?;
            info!(
                session_id = %session_id,
                verifier = %signer.verifier_id,
                "FROST: participant approval recorded"
            );
        }

        // ── Step 7: Finalize ──────────────────────────────────────────────
        session.transition(SessionState::Finalized)?;
        self.store.update_state(&session_id, SessionState::Finalized)?;

        info!(
            session_id = %session_id,
            envelope_digest = %envelope_digest,
            "FROST: attestation finalized"
        );

        Ok(FrostAttestationEnvelope {
            session: session_ctx,
            randomness: randomness_binding,
            transcript: transcript_commitments,
            statement,
            coordinator_evidence,
            frost_approval,
            envelope_digest,
        })
    }
}

// ── Layer 2: transport-based distributed FROST ────────────────────────────────
//
// `attest_frost_distributed_over_transport` is the production entry point for
// the distributed FROST path. It is identical in protocol logic to
// `attest_frost_distributed_inner`, but instead of calling methods on
// `FrostAuxiliaryNode` directly, it dispatches through `FrostNodeTransport`
// objects. Each transport can be either in-process (`InProcessTransport`) or
// TCP-based (`TcpNodeTransport`) — the coordinator does not know or care.
//
// This is the hook for Layer 2. Layer 3 will extend it with timeouts and
// retry logic. Layer 4 will add authentication.

#[cfg(feature = "tcp")]
impl<S, R, A> CoordinatorNode<S, R, A>
where
    S: SessionStore,
    R: RandomnessEngine,
    A: AttestationEngine,
{
    /// Run distributed FROST attestation over any `FrostNodeTransport` slice.
    ///
    /// This is the Layer 2 entry point. Transports may be in-process
    /// (`InProcessTransport`) or TCP (`TcpNodeTransport`) — the coordinator
    /// treats them identically.
    ///
    /// Protocol steps 1–5 are identical to `attest_frost_distributed`.
    /// Step 6 dispatches FROST rounds through the supplied transports instead
    /// of calling `FrostAuxiliaryNode` methods directly.
    pub fn attest_frost_distributed_over_transport(
        &self,
        request: AttestationRequest,
        response: &[u8],
        transports: &[&dyn crate::transport::FrostNodeTransport],
        group_key: &tls_attestation_crypto::frost_adapter::FrostGroupKey,
    ) -> Result<FrostAttestationEnvelope, NodeError> {
        use crate::frost_aux::assemble_signing_package_from_responses;
        use tls_attestation_crypto::frost_adapter::aggregate_signature_shares;
        use tls_attestation_network::messages::{FrostRound1Request, FrostRound2Request};

        let PreparedSession {
            session_id,
            session_ctx,
            mut session,
            now,
            expires_at,
            randomness_output,
            transcript_commitments,
            evidence,
            package,
            statement,
            randomness_binding,
            coordinator_evidence,
            envelope_digest,
            signed_digest,
        } = self.prepare_session(&request, response, "FROST-tcp")?;

        // ── Step 6: Collecting state ──────────────────────────────────────
        session.transition(SessionState::Collecting)?;
        self.store.update_state(&session_id, SessionState::Collecting)?;

        if transports.len() < self.config.quorum.threshold {
            let reason = format!(
                "insufficient transports: need {}, got {}",
                self.config.quorum.threshold,
                transports.len()
            );
            session.fail(reason.clone());
            self.store.update_state(&session_id, SessionState::Failed { reason })?;
            return Err(NodeError::QuorumNotMet {
                received: transports.len(),
                required: self.config.quorum.threshold,
            });
        }

        let signer_set: Vec<VerifierId> =
            transports.iter().map(|t| t.verifier_id().clone()).collect();

        // ── FROST Round 1 via transport ────────────────────────────────────
        let round1_req = FrostRound1Request {
            session_id: session_id.clone(),
            coordinator_id: self.config.coordinator_id.clone(),
            signed_digest: signed_digest.clone(),
            envelope_digest: envelope_digest.clone(),
            signer_set: signer_set.clone(),
            round_expires_at: expires_at,
            registry_epoch: RegistryEpoch::GENESIS,
            hsp_proof_bytes: vec![],
            hsp_pvk_bytes: vec![],
            dctls_evidence_bytes: vec![],
            rand_value_bytes: vec![],
            server_cert_hash_bytes: vec![],
        };

        let mut round1_responses = Vec::with_capacity(transports.len());
        for transport in transports {
            match transport.frost_round1(&round1_req, now) {
                Ok(resp) => {
                    info!(
                        session_id = %session_id,
                        verifier   = %resp.verifier_id,
                        "FROST-tcp: round-1 response received"
                    );
                    round1_responses.push(resp);
                }
                Err(e) => {
                    let reason = format!(
                        "round-1 failed for verifier {}: {e}",
                        transport.verifier_id()
                    );
                    warn!(session_id = %session_id, "{reason}");
                    session.fail(reason.clone());
                    self.store.update_state(&session_id, SessionState::Failed { reason })?;
                    return Err(e);
                }
            }
        }

        // ── Build signing package ─────────────────────────────────────────
        let (signing_package, signing_package_bytes) =
            assemble_signing_package_from_responses(&round1_responses, &signed_digest, group_key)?;

        // ── FROST Round 2 via transport ────────────────────────────────────
        let round2_req = FrostRound2Request {
            session_id: session_id.clone(),
            coordinator_id: self.config.coordinator_id.clone(),
            signing_package_bytes,
            signer_set: signer_set.clone(),
        };

        let mut share_entries: Vec<(VerifierId, Vec<u8>)> = Vec::with_capacity(transports.len());
        for transport in transports {
            match transport.frost_round2(&round2_req) {
                Ok(resp) => {
                    info!(
                        session_id = %session_id,
                        verifier   = %resp.verifier_id,
                        "FROST-tcp: round-2 response received"
                    );
                    share_entries.push((resp.verifier_id, resp.signature_share_bytes));
                }
                Err(e) => {
                    let reason = format!(
                        "round-2 failed for verifier {}: {e}",
                        transport.verifier_id()
                    );
                    warn!(session_id = %session_id, "{reason}");
                    session.fail(reason.clone());
                    self.store.update_state(&session_id, SessionState::Failed { reason })?;
                    return Err(e);
                }
            }
        }

        // ── Aggregation ───────────────────────────────────────────────────
        let frost_approval =
            aggregate_signature_shares(&signing_package, &share_entries, group_key, &signed_digest)
                .map_err(NodeError::Crypto)?;

        for vid in &signer_set {
            self.store.record_approval(&session_id, vid)?;
        }

        // ── Finalize ──────────────────────────────────────────────────────
        session.transition(SessionState::Finalized)?;
        self.store.update_state(&session_id, SessionState::Finalized)?;

        info!(
            session_id      = %session_id,
            envelope_digest = %envelope_digest,
            "FROST-tcp: attestation finalized"
        );

        Ok(FrostAttestationEnvelope {
            session: session_ctx,
            randomness: randomness_binding,
            transcript: transcript_commitments,
            statement,
            coordinator_evidence,
            frost_approval,
            envelope_digest,
        })
    }
}

// ── FROST distributed runtime integration ────────────────────────────────────
//
// `attest_frost_distributed` is the production FROST signing path.
//
// KEY DIFFERENCE FROM `attest_frost`:
//   `attest_frost` holds ALL FrostParticipant values (secret shares) in the
//   coordinator process.  This is wrong for production — it centralises secret
//   material.
//
//   `attest_frost_distributed` takes a slice of `&FrostAuxiliaryNode` instead.
//   Each node holds only its own key share.  The coordinator:
//     - Orchestrates the two-round protocol via typed method calls.
//     - Never holds, copies, or inspects any secret key material.
//     - Only receives PUBLIC artifacts: commitments (Round 1) and signature
//       shares (Round 2).
//
// Both `attest_frost` and `attest_frost_distributed` produce identical
// `FrostAttestationEnvelope` output — the difference is purely in which
// process performs the signing.
//
// # In-process vs. network transport
//
// Today both rounds happen via direct Rust method calls on `FrostAuxiliaryNode`.
// In a real deployment, `frost_round1` / `frost_round2` would correspond to
// two round-trip RPC/TLS messages; the `FrostRound1Request` / `FrostRound2Request`
// wire types are already defined for that purpose.  Plugging in a real transport
// layer requires only wrapping the method calls with send/receive.

#[cfg(feature = "frost")]
impl<S, R, A> CoordinatorNode<S, R, A>
where
    S: SessionStore,
    R: RandomnessEngine,
    A: AttestationEngine,
{
    /// Run the full attestation protocol using distributed FROST threshold signing.
    ///
    /// Unlike [`attest_frost`], the coordinator never holds secret key material.
    /// Each `FrostAuxiliaryNode` in `aux_nodes` independently executes its own
    /// Round 1 and Round 2 using only its local key share.
    ///
    /// Uses `RegistryEpoch::GENESIS` — no registry-level admission checks are
    /// performed.  For registry-gated signing, use
    /// [`attest_frost_distributed_with_registry`].
    ///
    /// # Errors
    ///
    /// - `NodeError::QuorumNotMet` if fewer than `quorum.threshold` aux nodes
    ///   are provided.
    /// - `NodeError::FrostProtocol(_)` if any aux node rejects a round request.
    /// - `NodeError::Crypto(_)` if FROST cryptography fails.
    pub fn attest_frost_distributed(
        &self,
        request: AttestationRequest,
        response: &[u8],
        aux_nodes: &[&crate::frost_aux::FrostAuxiliaryNode],
        group_key: &tls_attestation_crypto::frost_adapter::FrostGroupKey,
    ) -> Result<FrostAttestationEnvelope, NodeError> {
        self.attest_frost_distributed_inner(
            request,
            response,
            aux_nodes,
            group_key,
            RegistryEpoch::GENESIS,
        )
    }

    /// Run the full attestation protocol using distributed FROST threshold signing
    /// with registry-based admission.
    ///
    /// Before initiating any FROST round, validates that:
    /// - All `aux_nodes` members correspond to `Active` participants in `registry`
    ///   at epoch `expected_epoch`.
    /// - `expected_epoch` matches `registry.epoch()`.
    ///
    /// The validated `expected_epoch` is embedded in every `FrostRound1Request`
    /// so aux nodes can enforce their own per-node registry checks.
    ///
    /// # Errors
    ///
    /// - `NodeError::SigningAdmission(_)` if the epoch mismatches or any signer
    ///   is not `Active`.
    /// - `NodeError::QuorumNotMet` if fewer than `quorum.threshold` aux nodes
    ///   are provided.
    /// - `NodeError::FrostProtocol(_)` if any aux node rejects a round request.
    /// - `NodeError::Crypto(_)` if FROST cryptography fails.
    pub fn attest_frost_distributed_with_registry(
        &self,
        request: AttestationRequest,
        response: &[u8],
        aux_nodes: &[&crate::frost_aux::FrostAuxiliaryNode],
        group_key: &tls_attestation_crypto::frost_adapter::FrostGroupKey,
        registry: &ParticipantRegistry,
        expected_epoch: RegistryEpoch,
    ) -> Result<FrostAttestationEnvelope, NodeError> {
        // ── Coordinator-level admission gate ─────────────────────────────
        // Validate epoch + Active status for every signer before any round
        // message is sent.  This is the first line of defence; aux nodes
        // perform the same check independently (second line).
        if expected_epoch != registry.epoch() {
            return Err(NodeError::SigningAdmission(format!(
                "registry epoch mismatch: expected {:?}, registry is at {:?}",
                expected_epoch,
                registry.epoch()
            )));
        }
        let signer_ids: Vec<_> = aux_nodes.iter().map(|n| n.verifier_id().clone()).collect();
        registry
            .check_ceremony_admission(expected_epoch, &signer_ids)
            .map_err(|e| NodeError::SigningAdmission(format!("signing admission failed: {e}")))?;

        self.attest_frost_distributed_inner(
            request,
            response,
            aux_nodes,
            group_key,
            expected_epoch,
        )
    }

    /// Internal implementation of distributed FROST attestation.
    ///
    /// `registry_epoch` is embedded in each `FrostRound1Request`; aux nodes
    /// use it to perform their own registry admission checks.
    fn attest_frost_distributed_inner(
        &self,
        request: AttestationRequest,
        response: &[u8],
        aux_nodes: &[&crate::frost_aux::FrostAuxiliaryNode],
        group_key: &tls_attestation_crypto::frost_adapter::FrostGroupKey,
        registry_epoch: RegistryEpoch,
    ) -> Result<FrostAttestationEnvelope, NodeError> {
        use crate::frost_aux::assemble_signing_package_from_responses;
        use tls_attestation_crypto::frost_adapter::aggregate_signature_shares;
        use tls_attestation_network::messages::{FrostRound1Request, FrostRound2Request};

        let PreparedSession {
            session_id,
            session_ctx,
            mut session,
            now,
            expires_at,
            randomness_output,
            transcript_commitments,
            evidence,
            package,
            statement,
            randomness_binding,
            coordinator_evidence,
            envelope_digest,
            signed_digest,
        } = self.prepare_session(&request, response, "FROST-dist")?;

        // ── Step 6: Collecting state ──────────────────────────────────────
        session.transition(SessionState::Collecting)?;
        self.store.update_state(&session_id, SessionState::Collecting)?;

        // Early threshold check — surface QuorumNotMet before touching any
        // aux node, keeping it consistent with attest_frost's error type.
        if aux_nodes.len() < self.config.quorum.threshold {
            let reason = format!(
                "insufficient aux nodes: need {}, got {}",
                self.config.quorum.threshold,
                aux_nodes.len()
            );
            session.fail(reason.clone());
            self.store.update_state(
                &session_id,
                SessionState::Failed { reason },
            )?;
            return Err(NodeError::QuorumNotMet {
                received: aux_nodes.len(),
                required: self.config.quorum.threshold,
            });
        }

        // Build the committed signer set from aux node identities.
        let signer_set: Vec<VerifierId> =
            aux_nodes.iter().map(|n| n.verifier_id().clone()).collect();

        // ── FROST Round 1 ─────────────────────────────────────────────────
        // The coordinator sends each aux node a Round-1 request.
        // The coordinator holds only the PUBLIC commitment bytes returned.
        // No secret material is generated or stored here.
        let round1_req = FrostRound1Request {
            session_id: session_id.clone(),
            coordinator_id: self.config.coordinator_id.clone(),
            signed_digest: signed_digest.clone(),
            envelope_digest: envelope_digest.clone(),
            signer_set: signer_set.clone(),
            round_expires_at: expires_at,
            registry_epoch,
            hsp_proof_bytes: vec![],
            hsp_pvk_bytes: vec![],
            dctls_evidence_bytes: vec![],
            rand_value_bytes: vec![],
            server_cert_hash_bytes: vec![],
        };

        let mut round1_responses = Vec::with_capacity(aux_nodes.len());
        for node in aux_nodes {
            match node.frost_round1(&round1_req, now) {
                Ok(resp) => {
                    info!(
                        session_id = %session_id,
                        verifier   = %resp.verifier_id,
                        "FROST-dist: round-1 response received"
                    );
                    round1_responses.push(resp);
                }
                Err(e) => {
                    let reason = format!("round-1 failed for verifier {}: {e}", node.verifier_id());
                    warn!(session_id = %session_id, "{reason}");
                    session.fail(reason.clone());
                    self.store.update_state(
                        &session_id,
                        SessionState::Failed { reason },
                    )?;
                    return Err(e);
                }
            }
        }

        // ── Signing package assembly ──────────────────────────────────────
        // Coordinator assembles ALL round-1 commitments into a signing package.
        // This is public data — no secrets involved.
        let (signing_package, signing_package_bytes) =
            assemble_signing_package_from_responses(&round1_responses, &signed_digest, group_key)?;

        // ── FROST Round 2 ─────────────────────────────────────────────────
        // Each aux node deserialises the signing package, verifies the message
        // binding, and returns its signature share.
        let round2_req = FrostRound2Request {
            session_id: session_id.clone(),
            coordinator_id: self.config.coordinator_id.clone(),
            signing_package_bytes,
            signer_set: signer_set.clone(),
        };

        let mut share_entries: Vec<(VerifierId, Vec<u8>)> = Vec::with_capacity(aux_nodes.len());
        for node in aux_nodes {
            match node.frost_round2(&round2_req) {
                Ok(resp) => {
                    info!(
                        session_id = %session_id,
                        verifier   = %resp.verifier_id,
                        "FROST-dist: round-2 response received"
                    );
                    share_entries.push((resp.verifier_id, resp.signature_share_bytes));
                }
                Err(e) => {
                    let reason = format!("round-2 failed for verifier {}: {e}", node.verifier_id());
                    warn!(session_id = %session_id, "{reason}");
                    session.fail(reason.clone());
                    self.store.update_state(
                        &session_id,
                        SessionState::Failed { reason },
                    )?;
                    return Err(e);
                }
            }
        }

        // ── Aggregation ───────────────────────────────────────────────────
        let frost_approval =
            aggregate_signature_shares(&signing_package, &share_entries, group_key, &signed_digest)
                .map_err(NodeError::Crypto)?;

        // ── Record approvals ──────────────────────────────────────────────
        for vid in &signer_set {
            self.store.record_approval(&session_id, vid)?;
        }

        // ── Finalize ──────────────────────────────────────────────────────
        session.transition(SessionState::Finalized)?;
        self.store.update_state(&session_id, SessionState::Finalized)?;

        info!(
            session_id       = %session_id,
            envelope_digest  = %envelope_digest,
            "FROST-dist: attestation finalized"
        );

        Ok(FrostAttestationEnvelope {
            session: session_ctx,
            randomness: randomness_binding,
            transcript: transcript_commitments,
            statement,
            coordinator_evidence,
            frost_approval,
            envelope_digest,
        })
    }
}
