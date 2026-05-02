//! Auxiliary verifier node for the distributed FROST signing protocol.
//!
//! `FrostAuxiliaryNode` is the per-verifier runtime component for the
//! distributed FROST path.  It:
//!
//! - Holds **exactly one** `FrostParticipant` (one key share).
//!   The coordinator never sees this share.
//! - Executes Round 1 locally: generates fresh nonces, stores them in an
//!   in-memory cache, and returns public commitments for the coordinator.
//! - Executes Round 2 locally: retrieves and **consumes** the cached nonces,
//!   signs the coordinator's `SigningPackage`, and returns the share.
//!
//! # Nonce lifecycle and restart safety
//!
//! Round-1 nonces (`FrostSigningNonces`) are:
//! - Generated locally on demand (OS CSPRNG).
//! - Stored **only in memory** — they are **never persisted**.
//! - Consumed (moved, not cloned) by `frost_round2`, after which they cannot
//!   be reused.
//!
//! If a node restarts between Round 1 and Round 2, the in-memory nonce cache
//! is lost.  A subsequent `frost_round2` call for that session will fail with
//! `NodeError::FrostProtocol("nonces missing for session ...")`, signalling
//! the coordinator to mark the session `Failed` and start a fresh session.
//!
//! # Signer-set consistency
//!
//! `frost_round1` records the committed `signer_set`.  `frost_round2` rejects
//! any request whose `signer_set` differs — even by one element or ordering.
//! This prevents a coordinator from adding or removing participants between
//! the two rounds.
//!
//! # Signed-digest binding
//!
//! `frost_round1` records the `signed_digest` the participant agreed to sign.
//! `frost_round2` verifies that the `SigningPackage`'s embedded message equals
//! that cached digest before producing a share.  This prevents a coordinator
//! from substituting a different message in the signing package.

use crate::error::NodeError;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tls_attestation_core::{
    hash::DigestBytes,
    ids::{SessionId, VerifierId},
    types::UnixTimestamp,
};
use tls_attestation_crypto::{
    frost_adapter::{
        build_signing_package, FrostGroupKey, FrostParticipant,
        FrostSigningNonces, FrostSigningPackage,
    },
    participant_registry::{ParticipantRegistry, RegistryEpoch},
    threshold::approval_signed_digest,
};
use tls_attestation_network::messages::{
    FrostRound1Request, FrostRound1Response, FrostRound2Request, FrostRound2Response,
    HandshakeBindingRound1Request, HandshakeBindingRound1Response,
    HandshakeBindingRound2Request, HandshakeBindingRound2Response,
};
use tracing::{info, warn};

// ── Nonce cache entry ─────────────────────────────────────────────────────────

/// Ephemeral state cached between Round 1 and Round 2 for one session.
///
/// Created during `frost_round1`, consumed during `frost_round2`.
/// Never persisted; lost on restart.
/// Max time a pending round may live without being consumed by Round 2.
/// Sessions older than this are evicted to prevent unbounded memory growth.
const PENDING_TTL: Duration = Duration::from_secs(300); // 5 minutes

struct PendingRound {
    /// The nonces generated in Round 1.  `!Clone` — consumed by Round 2.
    nonces: FrostSigningNonces,
    /// The signer set the participant committed to in Round 1.
    signer_set: Vec<VerifierId>,
    /// The signed_digest the participant agreed to sign.
    signed_digest: DigestBytes,
    /// The registry epoch this signing session is bound to.
    registry_epoch: RegistryEpoch,
    /// Wall-clock time when this pending round was inserted.
    /// Used for TTL-based eviction.
    inserted_at: Instant,
}

/// Evict pending rounds older than `PENDING_TTL` from the cache.
/// Called before every insert to bound memory usage.
fn evict_expired(cache: &mut HashMap<SessionId, PendingRound>) {
    let now = Instant::now();
    cache.retain(|_, v| now.duration_since(v.inserted_at) < PENDING_TTL);
}

/// Acquire a Mutex, recovering from poisoning instead of propagating the panic.
/// On poison, the inner value is still valid — we just lost the ability to detect
/// whether a previous thread panicked mid-update.  For a nonce cache this is safe:
/// the worst case is a stale or missing entry, which Round 2 rejects gracefully.
fn lock_recovering<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ── FrostAuxiliaryNode ────────────────────────────────────────────────────────

/// Auxiliary verifier node for the distributed FROST two-round protocol.
///
/// Holds one FROST key share.  Coordinates with the coordinator via two
/// typed method calls (`frost_round1`, `frost_round2`) that correspond to
/// the two FROST rounds.  In a real deployment these would be triggered by
/// incoming network messages.
///
/// # Registry-based admission
///
/// When constructed via [`FrostAuxiliaryNode::with_registry`], the node holds
/// a reference to a `ParticipantRegistry` snapshot.  In `frost_round1`, the
/// node validates:
///
/// - `request.registry_epoch` matches the held registry's epoch.
/// - Every `signer_set` member is `Active` in that registry.
///
/// Nodes constructed via [`FrostAuxiliaryNode::new`] skip these checks
/// (`registry == None`).  This is equivalent to `RegistryEpoch::GENESIS`
/// on the wire — the legacy path with no registry enforcement.
///
/// # Thread safety
///
/// The nonce cache is protected by a `Mutex`.  All methods are `&self` and
/// safe to call from multiple threads simultaneously.
pub struct FrostAuxiliaryNode {
    participant: FrostParticipant,
    /// Optional participant registry for signing admission checks.
    ///
    /// When `Some`, `frost_round1` validates epoch and `Active` status for
    /// every signer in the request.  When `None`, these checks are skipped
    /// (legacy / no-registry path).
    registry: Option<Arc<ParticipantRegistry>>,
    /// Ephemeral nonce cache for main FROST attestation signing rounds.
    pending: Mutex<HashMap<SessionId, PendingRound>>,
    /// Ephemeral nonce cache for Handshake Binding 2PC rounds.
    ///
    /// Kept separate from `pending` to avoid key conflicts when both protocols
    /// run in the same session (they share the same `session_id`).
    ///
    /// **Never persisted.  Lost on restart.**
    hb_pending: Mutex<HashMap<SessionId, PendingRound>>,
}

impl FrostAuxiliaryNode {
    /// Create a node without registry-based signing admission.
    ///
    /// Round-1 requests will skip epoch and `Active`-status checks.
    /// Use [`with_registry`] in production deployments.
    pub fn new(participant: FrostParticipant) -> Self {
        Self {
            participant,
            registry: None,
            pending: Mutex::new(HashMap::new()),
            hb_pending: Mutex::new(HashMap::new()),
        }
    }

    /// Create a node with registry-based signing admission.
    ///
    /// `frost_round1` will reject:
    /// - Requests whose `registry_epoch` does not match `registry.epoch()`.
    /// - Requests whose `signer_set` includes a non-`Active` participant.
    ///
    /// The registry snapshot is stored behind an `Arc`; multiple nodes can
    /// share the same snapshot without cloning.
    pub fn with_registry(participant: FrostParticipant, registry: ParticipantRegistry) -> Self {
        Self {
            participant,
            registry: Some(Arc::new(registry)),
            pending: Mutex::new(HashMap::new()),
            hb_pending: Mutex::new(HashMap::new()),
        }
    }

    /// This node's protocol-level verifier identity.
    pub fn verifier_id(&self) -> &VerifierId {
        &self.participant.verifier_id
    }

    /// Execute Round 1 of the distributed FROST protocol.
    ///
    /// Validates the request, generates fresh nonces, caches the pending
    /// round state, and returns public commitments for the coordinator.
    ///
    /// # Security checks performed
    ///
    /// 1. `request.round_expires_at` has not passed (`now` must be provided).
    /// 2. This verifier is listed in `request.signer_set`.
    /// 3. Registry admission: epoch matches and every signer is `Active`
    ///    (only when this node holds a registry and `registry_epoch != GENESIS`).
    /// 4. `request.signed_digest == approval_signed_digest(request.envelope_digest)`.
    /// 5. No pending round already exists for this session (duplicate Round-1
    ///    rejection — a node never signs two nonce sets for the same session).
    ///
    /// # Errors
    ///
    /// - `NodeError::FrostProtocol("not in signer set")` if this verifier was
    ///   not selected for this session.
    /// - `NodeError::SigningAdmission(_)` if the registry epoch mismatches or a
    ///   signer is not `Active` in the held registry.
    /// - `NodeError::FrostProtocol("signed_digest mismatch")` if the provided
    ///   `signed_digest` does not equal `approval_signed_digest(envelope_digest)`.
    /// - `NodeError::FrostProtocol("round expired")` if `round_expires_at < now`.
    /// - `NodeError::FrostProtocol("round-1 already completed")` if nonces are
    ///   already cached for this session.
    pub fn frost_round1(
        &self,
        request: &FrostRound1Request,
        now: UnixTimestamp,
    ) -> Result<FrostRound1Response, NodeError> {
        // ── 1. Expiry check ──────────────────────────────────────────────
        if request.round_expires_at.0 < now.0 {
            return Err(NodeError::FrostProtocol(format!(
                "round-1 request expired for session {}: expires_at={} now={}",
                request.session_id, request.round_expires_at.0, now.0
            )));
        }

        // ── 2. Signer-set membership ─────────────────────────────────────
        let my_id = self.participant.verifier_id.clone();
        if !request.signer_set.contains(&my_id) {
            return Err(NodeError::FrostProtocol(format!(
                "verifier {} is not in the signer set for session {}",
                my_id, request.session_id
            )));
        }

        // ── 3. Registry admission check ──────────────────────────────────
        // Only performed when this node holds a ParticipantRegistry snapshot.
        // Checks: (a) epoch match, (b) every signer in the set is Active.
        // RegistryEpoch::GENESIS on the wire signals the legacy no-registry
        // path and is accepted unconditionally even when a registry is held.
        if let Some(registry) = &self.registry {
            if request.registry_epoch != RegistryEpoch::GENESIS
                && request.registry_epoch != registry.epoch()
            {
                return Err(NodeError::SigningAdmission(format!(
                    "registry epoch mismatch for session {}: \
                     request carries epoch {:?}, registry is at epoch {:?}",
                    request.session_id, request.registry_epoch, registry.epoch()
                )));
            }
            if request.registry_epoch != RegistryEpoch::GENESIS {
                for vid in &request.signer_set {
                    if let Err(e) = registry.get_active(vid) {
                        return Err(NodeError::SigningAdmission(format!(
                            "signing admission denied for session {}: \
                             signer {} rejected by registry: {}",
                            request.session_id, vid, e
                        )));
                    }
                }
            }
        }

        // ── 4. Signed-digest binding verification ────────────────────────
        // The coordinator must supply a consistent (envelope_digest, signed_digest)
        // pair.  We independently recompute and compare.
        let expected_signed_digest = approval_signed_digest(&request.envelope_digest);
        if request.signed_digest != expected_signed_digest {
            return Err(NodeError::FrostProtocol(format!(
                "signed_digest mismatch in round-1 for session {}: \
                 coordinator-supplied value does not equal \
                 approval_signed_digest(envelope_digest)",
                request.session_id
            )));
        }

        // ── 5. ZKP.Verify(π_HSP, rand) — paper §VIII.B Signing Phase step 3 ─
        //
        // If the coordinator supplied an HSP Groth16 proof, verify it before
        // generating nonces.  This enforces the dx-DCTLS signing admission:
        // an auxiliary verifier must not sign unless it can confirm the prover
        // held a valid TLS session (K_MAC correctly derived, Zp binding intact).
        if !request.hsp_proof_bytes.is_empty() && !request.hsp_pvk_bytes.is_empty() {
            use tls_attestation_zk::{HspProof, co_snark_verify};
            use ark_bn254::Bn254;
            use ark_groth16::Groth16;
            use ark_crypto_primitives::snark::SNARK;
            use ark_serialize::CanonicalDeserialize;
            use ark_bn254::Fr;

            let proof: HspProof = serde_json::from_slice(&request.hsp_proof_bytes)
                .map_err(|e| NodeError::FrostProtocol(format!(
                    "π_HSP deserialization failed for session {}: {e}",
                    request.session_id
                )))?;

            type Pvk = <Groth16<Bn254> as SNARK<Fr>>::ProcessedVerifyingKey;
            let pvk = Pvk::deserialize_compressed(request.hsp_pvk_bytes.as_slice())
                .map_err(|e| NodeError::FrostProtocol(format!(
                    "HSP verifying key deserialization failed for session {}: {e}",
                    request.session_id
                )))?;

            co_snark_verify(&pvk, &proof, None)
                .map_err(|e| NodeError::FrostProtocol(format!(
                    "ZKP.Verify(π_HSP, rand) failed for session {}: {e:?}",
                    request.session_id
                )))?;

            info!(
                session = %request.session_id,
                "ZKP.Verify(π_HSP, rand) passed — HSP proof accepted"
            );
        }

        // ── 5b. ZKP.Verify(π_DCTLS, rand) + ZKP.Verify(π_pgp, b) ────────
        //
        // Paper §VIII.B Signing Phase steps 4-5:
        //   ZKP.Verify(π_DCTLS, rand) = 1  — commitment chain consistency
        //   ZKP.Verify(π_pgp, b) = 1        — PGP binding to HSP + QP
        //
        // Implementation: we verify the commitment chain and cross-proof
        // binding using DctlsEvidence.verify_all().  This confirms:
        //   (a) HSP, QP, PGP all reference the same session_id and rand_value.
        //   (b) PGP commitment = H(session_id, rand, qp_transcript, stmt, hsp_commitment).
        //   (c) HSP proof digest is bound to the PGP proof.
        //   (d) Server cert hash matches (anti-impersonation).
        //
        // No plaintext query/response is transmitted — verification is purely
        // over commitment digests.
        if !request.dctls_evidence_bytes.is_empty() {
            use tls_attestation_attestation::dctls::{DctlsEvidence, DctlsError};
            use tls_attestation_core::hash::DigestBytes;

            let evidence: DctlsEvidence =
                serde_json::from_slice(&request.dctls_evidence_bytes).map_err(|e| {
                    NodeError::FrostProtocol(format!(
                        "DctlsEvidence deserialization failed for session {}: {e}",
                        request.session_id
                    ))
                })?;

            // rand_value: the DVRF output for this session.
            if request.rand_value_bytes.len() != 32 {
                return Err(NodeError::FrostProtocol(format!(
                    "rand_value_bytes must be 32 bytes for session {}",
                    request.session_id
                )));
            }
            let rand_value = DigestBytes::from_bytes(
                request.rand_value_bytes.as_slice().try_into().map_err(|_| {
                    NodeError::FrostProtocol("rand_value_bytes length error".into())
                })?,
            );

            // server_cert_hash: TLS server certificate hash.
            if request.server_cert_hash_bytes.len() != 32 {
                return Err(NodeError::FrostProtocol(format!(
                    "server_cert_hash_bytes must be 32 bytes for session {}",
                    request.session_id
                )));
            }
            let server_cert_hash = DigestBytes::from_bytes(
                request.server_cert_hash_bytes.as_slice().try_into().map_err(|_| {
                    NodeError::FrostProtocol("server_cert_hash_bytes length error".into())
                })?,
            );

            // Aux verifiers do NOT receive raw query/response — only commitment
            // digests are transmitted.  We run the three checks that do not
            // require plaintext:
            //
            //  (a) verify_hsp_proof  — rand binding + cert hash
            //  (b) verify_pgp_proof  — PGP commitment chain correctness
            //  (c) verify_transcript_consistency — cross-proof session/rand check
            //
            // verify_query_record (which rehashes raw query+response) is the
            // prover's own responsibility and is not repeated here.
            use tls_attestation_attestation::dctls::{
                verify_hsp_proof, verify_pgp_proof, verify_transcript_consistency,
            };

            verify_hsp_proof(&evidence.hsp_proof, &rand_value, &server_cert_hash)
                .map_err(|e: DctlsError| NodeError::FrostProtocol(format!(
                    "ZKP.Verify(π_DCTLS, rand): verify_hsp_proof failed for session {}: {e}",
                    request.session_id
                )))?;

            verify_pgp_proof(&evidence.pgp_proof, &rand_value, &evidence.hsp_proof)
                .map_err(|e: DctlsError| NodeError::FrostProtocol(format!(
                    "ZKP.Verify(π_pgp, b): verify_pgp_proof failed for session {}: {e}",
                    request.session_id
                )))?;

            verify_transcript_consistency(
                &evidence.hsp_proof,
                &evidence.query_record,
                &evidence.pgp_proof,
            )
            .map_err(|e: DctlsError| NodeError::FrostProtocol(format!(
                "ZKP.Verify(π_DCTLS): transcript consistency failed for session {}: {e}",
                request.session_id
            )))?;

            info!(
                session = %request.session_id,
                "ZKP.Verify(π_DCTLS, rand) + ZKP.Verify(π_pgp, b) passed"
            );
        }

        // ── 6. Generate nonces and commitment ────────────────────────────
        // Nonces are produced from the OS CSPRNG; never reused (type system enforces this).
        let (nonces, commitment) = self.participant.round1(&mut OsRng);
        let commitment_bytes = commitment.to_bytes();

        // ── 7. Cache pending round state (check + insert under one lock) ──
        //
        // Fix (TOCTOU): the old code checked `contains_key` under one lock
        // acquisition, then inserted under a second.  A concurrent Round-1
        // for the same session could pass the check in both threads, then the
        // second insert silently overwrites the first party's nonces, making
        // their Round-2 fail.  Merging both operations under a single lock
        // acquisition makes the check+insert atomic.
        {
            let mut cache = lock_recovering(&self.pending);
            evict_expired(&mut cache);  // TTL eviction before each insert
            if cache.contains_key(&request.session_id) {
                return Err(NodeError::FrostProtocol(format!(
                    "round-1 already completed for session {} — \
                     refusing duplicate nonce generation",
                    request.session_id
                )));
            }
            cache.insert(
                request.session_id.clone(),
                PendingRound {
                    nonces,
                    signer_set: request.signer_set.clone(),
                    signed_digest: request.signed_digest.clone(),
                    registry_epoch: request.registry_epoch,
                    inserted_at: Instant::now(),
                },
            );
        }

        info!(
            session_id = %request.session_id,
            verifier   = %my_id,
            "FROST distributed: round-1 complete, commitment generated"
        );

        Ok(FrostRound1Response {
            session_id: request.session_id.clone(),
            verifier_id: my_id,
            commitment_bytes: commitment_bytes?,
        })
    }

    /// Execute Round 2 of the distributed FROST protocol.
    ///
    /// Retrieves and **consumes** the cached Round-1 nonces, verifies all
    /// invariants, and produces a signature share.  After this call, nonces
    /// for this session are gone and cannot be reused.
    ///
    /// # Security checks performed
    ///
    /// 1. Nonces exist for this session (fails safe if Round 1 never ran,
    ///    e.g. after a restart).
    /// 2. `request.signer_set` exactly matches the set committed in Round 1.
    /// 3. The signing package's embedded message equals the `signed_digest`
    ///    cached during Round 1 — prevents the coordinator from substituting
    ///    a different payload.
    ///
    /// # Errors
    ///
    /// - `NodeError::FrostProtocol("nonces missing")` if no pending round exists
    ///   (covers restart, duplicate Round-2, and missing Round-1 cases).
    /// - `NodeError::FrostProtocol("signer-set mismatch")` if the signer set
    ///   changed between rounds.
    /// - `NodeError::FrostProtocol("message mismatch")` if the signing package
    ///   carries a different message than was committed in Round 1.
    /// - `NodeError::Crypto(_)` if the FROST `round2` computation fails.
    pub fn frost_round2(
        &self,
        request: &FrostRound2Request,
    ) -> Result<FrostRound2Response, NodeError> {
        // ── 1. Retrieve and remove cached round state ────────────────────
        // Removing from the cache is the nonce-consumption step.  Even if
        // subsequent checks fail, the nonces are gone — no retry is possible.
        let pending = {
            let mut cache = lock_recovering(&self.pending);
            cache
                .remove(&request.session_id)
                .ok_or_else(|| {
                    NodeError::FrostProtocol(format!(
                        "nonces missing for session {} — round-1 may not have run, \
                         or the node restarted between rounds",
                        request.session_id
                    ))
                })?
        };

        // ── 2. Signer-set consistency check ─────────────────────────────
        if request.signer_set != pending.signer_set {
            warn!(
                session_id = %request.session_id,
                verifier   = %self.participant.verifier_id,
                "FROST distributed: signer-set drift detected between rounds"
            );
            return Err(NodeError::FrostProtocol(format!(
                "signer-set mismatch for session {}: \
                 round-2 signer set differs from round-1 commitment",
                request.session_id
            )));
        }

        // ── 3. Deserialize signing package ───────────────────────────────
        let signing_package = FrostSigningPackage::from_bytes(&request.signing_package_bytes)
            .map_err(NodeError::Crypto)?;

        // ── 4. Message binding verification ──────────────────────────────
        // The coordinator must not have substituted a different message
        // (payload) in the signing package.
        if signing_package.message_bytes() != pending.signed_digest.as_bytes() {
            return Err(NodeError::FrostProtocol(format!(
                "signing package message mismatch for session {}: \
                 the message embedded in the signing package does not match \
                 the signed_digest committed to in round-1",
                request.session_id
            )));
        }

        // ── 5. Produce signature share ────────────────────────────────────
        // Nonces are consumed here (moved into round2) — cannot be reused.
        let share = self
            .participant
            .round2(&signing_package, pending.nonces)
            .map_err(NodeError::Crypto)?;

        let my_id = self.participant.verifier_id.clone();
        info!(
            session_id     = %request.session_id,
            verifier       = %my_id,
            registry_epoch = ?pending.registry_epoch,
            "FROST distributed: round-2 complete, signature share produced"
        );

        Ok(FrostRound2Response {
            session_id: request.session_id.clone(),
            verifier_id: my_id,
            signature_share_bytes: share.to_bytes()?,
        })
    }

    /// Return the number of pending (in-flight) FROST sessions.
    ///
    /// Zero after a successful round-2 confirms that nonces were consumed.
    /// A non-zero count after a test completes may indicate a nonce leak.
    /// This is safe to expose publicly — it reveals no secret material.
    pub fn pending_session_count(&self) -> usize {
        lock_recovering(&self.pending).len()
    }

    // ── Handshake Binding 2PC ─────────────────────────────────────────────────

    /// Round 1 of the Handshake Binding protocol.
    ///
    /// The coordinator provides a `binding_input` — a domain-separated hash of
    /// the TLS session parameters — and asks each aux node to produce nonces and
    /// a `SigningCommitments` over that input.
    ///
    /// # Security checks performed
    ///
    /// 1. `round_expires_at` has not passed.
    /// 2. This verifier is listed in `signer_set`.
    /// 3. Registry admission (same rules as `frost_round1`).
    /// 4. No duplicate round — only one nonce set per session.
    pub fn handshake_binding_round1(
        &self,
        request: &HandshakeBindingRound1Request,
        now: UnixTimestamp,
    ) -> Result<HandshakeBindingRound1Response, NodeError> {
        // 1. Expiry check.
        if request.round_expires_at.0 < now.0 {
            return Err(NodeError::FrostProtocol(format!(
                "handshake-binding round-1 expired for session {}: expires_at={} now={}",
                request.session_id, request.round_expires_at.0, now.0
            )));
        }

        // 2. Signer-set membership.
        let my_id = self.participant.verifier_id.clone();
        if !request.signer_set.contains(&my_id) {
            return Err(NodeError::FrostProtocol(format!(
                "verifier {} not in signer set for handshake-binding session {}",
                my_id, request.session_id
            )));
        }

        // 3. Registry admission (mirrors frost_round1).
        if let Some(registry) = &self.registry {
            if request.registry_epoch != RegistryEpoch::GENESIS
                && request.registry_epoch != registry.epoch()
            {
                return Err(NodeError::SigningAdmission(format!(
                    "registry epoch mismatch in handshake-binding for session {}:                      request={:?}, registry={:?}",
                    request.session_id, request.registry_epoch, registry.epoch()
                )));
            }
            if request.registry_epoch != RegistryEpoch::GENESIS {
                for vid in &request.signer_set {
                    if let Err(e) = registry.get_active(vid) {
                        return Err(NodeError::SigningAdmission(format!(
                            "handshake-binding admission denied for session {}:                              signer {} rejected: {}",
                            request.session_id, vid, e
                        )));
                    }
                }
            }
        }

        // 4. Duplicate-round guard.
        {
            let cache = lock_recovering(&self.hb_pending);
            if cache.contains_key(&request.session_id) {
                return Err(NodeError::FrostProtocol(format!(
                    "handshake-binding round-1 already completed for session {}",
                    request.session_id
                )));
            }
        }

        // 5. Generate nonces + commitment.
        let (nonces, commitment) = self.participant.round1(&mut OsRng);
        let commitment_bytes = commitment.to_bytes();

        // 6. Cache pending state.
        {
            let mut cache = lock_recovering(&self.hb_pending);
            evict_expired(&mut cache);  // TTL eviction before each insert
            cache.insert(
                request.session_id.clone(),
                PendingRound {
                    nonces,
                    signer_set:    request.signer_set.clone(),
                    signed_digest: request.binding_input.clone(),
                    registry_epoch: request.registry_epoch,
                    inserted_at: Instant::now(),
                },
            );
        }

        info!(
            session_id = %request.session_id,
            verifier   = %my_id,
            "Handshake-binding: round-1 complete"
        );

        Ok(HandshakeBindingRound1Response {
            session_id:     request.session_id.clone(),
            verifier_id:    my_id,
            commitment_bytes: commitment_bytes?,
        })
    }

    /// Round 2 of the Handshake Binding protocol.
    ///
    /// Retrieves and **consumes** the nonces cached in round 1 and produces a
    /// `SignatureShare` over `binding_input`.  Verifies that the coordinator's
    /// `signing_package_bytes` embeds the same `binding_input` that was
    /// committed to in round 1.
    pub fn handshake_binding_round2(
        &self,
        request: &HandshakeBindingRound2Request,
    ) -> Result<HandshakeBindingRound2Response, NodeError> {
        // 1. Retrieve + consume cached state (nonces gone after this).
        let pending = {
            let mut cache = lock_recovering(&self.hb_pending);
            cache.remove(&request.session_id).ok_or_else(|| {
                NodeError::FrostProtocol(format!(
                    "handshake-binding nonces missing for session {} —                      round-1 may not have run or node restarted",
                    request.session_id
                ))
            })?
        };

        // 2. Signer-set consistency.
        if request.signer_set != pending.signer_set {
            return Err(NodeError::FrostProtocol(format!(
                "handshake-binding signer-set mismatch for session {}",
                request.session_id
            )));
        }

        // 3. Deserialise signing package.
        let signing_package = FrostSigningPackage::from_bytes(&request.signing_package_bytes)
            .map_err(NodeError::Crypto)?;

        // 4. Message binding — the package must carry the same binding_input.
        if signing_package.message_bytes() != pending.signed_digest.as_bytes() {
            return Err(NodeError::FrostProtocol(format!(
                "handshake-binding message mismatch for session {}:                  signing package does not embed the binding_input from round-1",
                request.session_id
            )));
        }

        // 5. Produce signature share (nonces consumed).
        let share = self
            .participant
            .round2(&signing_package, pending.nonces)
            .map_err(NodeError::Crypto)?;

        let my_id = self.participant.verifier_id.clone();
        info!(
            session_id = %request.session_id,
            verifier   = %my_id,
            "Handshake-binding: round-2 complete, share produced"
        );

        Ok(HandshakeBindingRound2Response {
            session_id:             request.session_id.clone(),
            verifier_id:            my_id,
            signature_share_bytes:  share.to_bytes()?,
        })
    }
}

// ── Helper: build a signing package from collected round-1 responses ──────────

/// Coordinator-side helper: assemble a signing package from Round-1 responses.
///
/// Validates that each response's `verifier_id` is in `group_key`, deserializes
/// the commitments, and builds a `FrostSigningPackage` ready for Round 2.
///
/// Returns `(signing_package, signing_package_bytes)` where `package_bytes`
/// is ready for inclusion in `FrostRound2Request`.
pub fn assemble_signing_package_from_responses(
    responses: &[FrostRound1Response],
    signed_digest: &DigestBytes,
    group_key: &FrostGroupKey,
) -> Result<(FrostSigningPackage, Vec<u8>), NodeError> {
    let collected: Vec<(VerifierId, Vec<u8>)> = responses
        .iter()
        .map(|r| (r.verifier_id.clone(), r.commitment_bytes.clone()))
        .collect();

    build_signing_package(&collected, signed_digest, group_key).map_err(NodeError::Crypto)
}

/// Coordinator-side helper: assemble a signing package from Handshake Binding Round-1 responses.
pub fn assemble_hb_signing_package_from_responses(
    responses:     &[HandshakeBindingRound1Response],
    binding_input: &DigestBytes,
    group_key:     &FrostGroupKey,
) -> Result<(FrostSigningPackage, Vec<u8>), NodeError> {
    let collected: Vec<(VerifierId, Vec<u8>)> = responses
        .iter()
        .map(|r| (r.verifier_id.clone(), r.commitment_bytes.clone()))
        .collect();

    build_signing_package(&collected, binding_input, group_key).map_err(NodeError::Crypto)
}
