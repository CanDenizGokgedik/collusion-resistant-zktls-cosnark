//! Handshake 2PC shared types and deterministic helpers.
//!
//! This module has **no feature gates** so it can be used by both the
//! `tls` attestation engine and the `node` coordination layer without
//! creating circular dependencies.

use tls_attestation_core::{
    hash::{CanonicalHasher, DigestBytes},
    ids::SessionId,
};

// ── TlsSessionParams ──────────────────────────────────────────────────────────

/// TLS session parameters captured by the coordinator after the handshake.
///
/// Used as input to [`compute_2pc_binding_input`].  The coordinator sends
/// `cert_hash`, `tls_version`, `server_name`, and `established_at` to the
/// prover as evidence of the connection.  `session_nonce` is a TLS RFC 5705
/// exporter that proves a genuine TLS session took place.
#[derive(Debug, Clone)]
pub struct TlsSessionParams {
    /// SHA-256 of the DER-encoded leaf certificate.
    pub server_cert_hash: DigestBytes,
    /// TLS wire version: `0x0304` = TLS 1.3, `0x0303` = TLS 1.2.
    pub tls_version:      u16,
    /// SNI hostname used during the handshake.
    pub server_name:      String,
    /// Unix timestamp (seconds) when the TCP connection was established.
    pub established_at:   u64,
    /// 32-byte RFC 5705 exporter: `TLS-Exporter("tls-attestation/session-nonce/v1", None, 32)`.
    ///
    /// Unique per TLS session and independent of DVRF randomness — proves
    /// the coordinator established a real TLS session.
    pub session_nonce: DigestBytes,
}

// ── Deterministic protocol helpers ────────────────────────────────────────────

/// Compute the Handshake 2PC binding input.
///
/// ```text
/// H("tls-attestation/2pc-binding/v1"
///   || session_id   [16 bytes]
///   || rand_value   [32 bytes]
///   || cert_hash    [32 bytes]
///   || tls_version  [8 bytes BE]
///   || server_name  [length-prefixed UTF-8]
///   || session_nonce[32 bytes])
/// ```
///
/// This is the exact bytes that aux nodes sign in the binding protocol.
/// A valid binding proves the coordinator ran a real TLS session (the
/// `session_nonce` is derived from the TLS master secret via RFC 5705).
pub fn compute_2pc_binding_input(
    session_id: &SessionId,
    rand_value: &DigestBytes,
    params:     &TlsSessionParams,
) -> DigestBytes {
    let mut h = CanonicalHasher::new("tls-attestation/2pc-binding/v1");
    h.update_fixed(session_id.as_bytes());
    h.update_digest(rand_value);
    h.update_digest(&params.server_cert_hash);
    h.update_fixed(&(params.tls_version as u64).to_be_bytes());
    h.update_bytes(params.server_name.as_bytes());
    h.update_digest(&params.session_nonce);
    h.finalize()
}

/// Derive the threshold-locked `dvrf_exporter` from the FROST aggregate
/// signature σ.
///
/// ```text
/// dvrf_exporter = H("tls-attestation/2pc-exporter/v1" || σ[64])
/// ```
///
/// This value requires BOTH a real TLS session (for `session_nonce` embedded
/// in the binding input) AND threshold cooperation of `t` aux nodes (for σ).
pub fn derive_2pc_dvrf_exporter(aggregate_sig: &[u8; 64]) -> DigestBytes {
    let mut h = CanonicalHasher::new("tls-attestation/2pc-exporter/v1");
    h.update_fixed(aggregate_sig);
    h.finalize()
}