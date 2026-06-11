//! Coordinator-side Handshake 2PC binding protocol.
//!
//! After a TLS handshake completes, the coordinator has:
//!
//! - `cert_hash`, `tls_version`, `server_name`, `established_at` — TLS session facts.
//! - `session_nonce` — a 32-byte RFC 5705 TLS exporter unique to this session
//!   (`TLS-Exporter("tls-attestation/session-nonce/v1", context=None, 32)`).
//!
//! The coordinator then:
//!
//! 1. Calls [`compute_2pc_binding_input`] to hash everything into a 32-byte
//!    `binding_input`.
//! 2. Calls [`run_handshake_binding`] — a two-round FROST ceremony over
//!    `binding_input` across `t` of `n` aux nodes — to get σ.
//! 3. Calls [`derive_2pc_dvrf_exporter`] to derive
//!    `dvrf_exporter = H("2pc-exporter/v1" || σ)`.
//!
//! # Security guarantee
//!
//! `dvrf_exporter` requires BOTH a real TLS session (for `session_nonce`) AND
//! threshold cooperation of `t` aux nodes (for σ).
//! A coordinator cannot forge `dvrf_exporter` without running a genuine TLS
//! session and colluding with at least `t` nodes.

use crate::error::NodeError;
use crate::frost_aux::assemble_hb_signing_package_from_responses;
use crate::transport::FrostNodeTransport;
use tls_attestation_core::{
    hash::DigestBytes,
    ids::{SessionId, VerifierId},
    types::UnixTimestamp,
};
use tls_attestation_crypto::{
    frost_adapter::{aggregate_signature_shares, FrostGroupKey},
    participant_registry::RegistryEpoch,
};
use tls_attestation_network::messages::{
    HandshakeBindingRound1Request, HandshakeBindingRound2Request,
};

// Re-export from the attestation crate (no circular dependency).
pub use tls_attestation_attestation::tls_2pc::{
    TlsSessionParams, compute_2pc_binding_input, derive_2pc_dvrf_exporter,
};

// ── Coordinator protocol ───────────────────────────────────────────────────────

/// Run the two-round Handshake Binding FROST ceremony.
///
/// Sends `binding_input` to all `transports`, collects nonce commitments
/// (Round 1), assembles a `SigningPackage`, distributes it (Round 2), and
/// aggregates the resulting shares into a 64-byte aggregate signature σ.
///
/// Pass the returned σ to [`derive_2pc_dvrf_exporter`] to obtain the final
/// `dvrf_exporter`.
///
/// # Arguments
///
/// - `session_id`      — session identifier embedded in request structs.
/// - `coordinator_id`  — the coordinator's own `VerifierId`.
/// - `binding_input`   — the domain-separated hash of TLS session parameters.
/// - `group_key`       — the FROST group key for this quorum.
/// - `transports`      — at least `threshold` transports to aux nodes.
/// - `round_ttl_secs`  — Round-1 expiry window in seconds.
/// - `registry_epoch`  — pass `RegistryEpoch::GENESIS` to skip admission checks.
pub fn run_handshake_binding(
    session_id:     &SessionId,
    coordinator_id: &VerifierId,
    binding_input:  &DigestBytes,
    group_key:      &FrostGroupKey,
    transports:     &[&dyn FrostNodeTransport],
    round_ttl_secs: u64,
    registry_epoch: RegistryEpoch,
) -> Result<[u8; 64], NodeError> {
    let now       = UnixTimestamp::now();
    let expires   = UnixTimestamp(now.0.saturating_add(round_ttl_secs));
    let signer_set: Vec<VerifierId> =
        transports.iter().map(|t| t.verifier_id().clone()).collect();

    // ── Round 1 ───────────────────────────────────────────────────────────────
    let r1_req = HandshakeBindingRound1Request {
        session_id:       session_id.clone(),
        coordinator_id:   coordinator_id.clone(),
        binding_input:    binding_input.clone(),
        signer_set:       signer_set.clone(),
        round_expires_at: expires,
        registry_epoch,
    };

    let r1_responses: Vec<_> = transports
        .iter()
        .map(|t| t.handshake_binding_round1(&r1_req, now))
        .collect::<Result<Vec<_>, _>>()?;

    // ── Assemble signing package ───────────────────────────────────────────────
    let (signing_pkg, pkg_bytes) =
        assemble_hb_signing_package_from_responses(&r1_responses, binding_input, group_key)?;

    // ── Round 2 ───────────────────────────────────────────────────────────────
    let r2_req = HandshakeBindingRound2Request {
        session_id:            session_id.clone(),
        coordinator_id:        coordinator_id.clone(),
        signing_package_bytes: pkg_bytes,
        signer_set,
    };

    let r2_responses: Vec<_> = transports
        .iter()
        .map(|t| t.handshake_binding_round2(&r2_req))
        .collect::<Result<Vec<_>, _>>()?;

    // ── Aggregate shares ───────────────────────────────────────────────────────
    let shares: Vec<(VerifierId, Vec<u8>)> = r2_responses
        .iter()
        .map(|r| (r.verifier_id.clone(), r.signature_share_bytes.clone()))
        .collect();

    let approval =
        aggregate_signature_shares(&signing_pkg, &shares, group_key, binding_input)
            .map_err(NodeError::Crypto)?;

    Ok(approval.aggregate_signature_bytes)
}