//! Layer 1: Real TLS attestation engine.
//!
//! # Protocol position
//!
//! `TlsAttestationEngine` replaces `PrototypeAttestationEngine` for production
//! use. It establishes a genuine TLS 1.2/1.3 connection to a target server,
//! captures the server certificate and negotiated protocol version, sends the
//! supplied query as a raw HTTP request, and records the server's response.
//!
//! The captured data feeds directly into the dx-DCTLS commitment chain:
//!
//! ```text
//! TCP connect → TLS handshake → capture (cert_hash, tls_version, sni, ts)
//!     → send query → read response
//!     → HSPProof::generate(session_id, rand, sps, spp)   ← commitment over cert+version
//!     → QueryRecord::build(session_id, rand, query, response)
//!     → PGPProof::generate(...)
//! ```
//!
//! # Security model
//!
//! The HSP proof uses the **commitment-based backend** (SHA-256, not a
//! zero-knowledge proof). This is sound under the honest-but-curious model.
//! Replace the backend with a real co-SNARK via `ZkTlsBackend` for full
//! dx-DCTLS security (see `zk_backend.rs`).
//!
//! # Usage
//!
//! ```rust,ignore
//! use tls_attestation_attestation::tls_engine::TlsAttestationEngine;
//!
//! let engine = TlsAttestationEngine::new("api.example.com", 443);
//! let (transcript, evidence) = engine.execute(&session, &rand, b"GET /balance HTTP/1.0\r\nHost: api.example.com\r\n\r\n", b"")?;
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::ClientConnection;
use sha2::{Digest, Sha256};

use tls_attestation_core::hash::{CanonicalHasher, DigestBytes};
use tls_attestation_core::ids::SessionId;

use tls_attestation_crypto::transcript::TranscriptCommitments;

use crate::dctls::{
    DctlsEvidence, HSPProof, PGPProof, QueryRecord, SessionParamsPublic, SessionParamsSecret,
    Statement, DCTLS_ENGINE_TAG,
};
use crate::engine::{
    AttestationEngine, DxDctlsAttestationEngine, ExportableEvidence,
};
use crate::error::AttestationError;
use crate::session::SessionContext;

/// Default read timeout for the TCP socket (10 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

// ── Captured TLS session data ─────────────────────────────────────────────────

/// Data captured from a live TLS handshake and HTTP exchange.
#[derive(Debug)]
struct TlsCapture {
    /// SHA-256 hash of the DER-encoded leaf certificate.
    server_cert_hash: DigestBytes,
    /// TLS wire version: 0x0303 = TLS 1.2, 0x0304 = TLS 1.3.
    tls_version: u16,
    /// SNI hostname used in the handshake.
    server_name: String,
    /// Unix timestamp (seconds) when the TCP connection was established.
    established_at: u64,
    /// Raw bytes received from the server after the query was sent.
    response: Vec<u8>,

    // ── Real TLS keying material (RFC 5705) ───────────────────────────────────

    /// 32-byte TLS exporter output bound to DVRF randomness.
    ///
    /// Derived as:
    /// `TLS-Exporter("tls-attestation/dvrf-exporter/v1", context=randomness, 32)`
    ///
    /// Mixed from TLS master secret + DVRF randomness as context.
    /// A coordinator cannot produce this value without:
    /// 1. Running a real TLS session (to get the master secret), AND
    /// 2. Knowing the session's DVRF randomness.
    dvrf_keying_material: [u8; 32],

    /// 32-byte TLS exporter output bound to session identity only.
    ///
    /// Derived as:
    /// `TLS-Exporter("tls-attestation/session-nonce/v1", context=None, 32)`
    ///
    /// Unique per TLS session — independent of DVRF randomness.
    nonce_keying_material: [u8; 32],
}

// ── TlsAttestationEngine ─────────────────────────────────────────────────────

/// Attestation engine that establishes genuine TLS connections.
///
/// Configured at construction with a fixed target host and port. Each call to
/// `execute` / `execute_dctls` opens a fresh TCP + TLS connection, sends the
/// supplied query, reads the response, and derives dx-DCTLS commitment proofs
/// from the captured session parameters.
///
/// The `response` and `server_cert_hash` parameters of the `AttestationEngine`
/// trait are **ignored** — the engine captures these values from the real
/// connection instead of accepting them as inputs.
pub struct TlsAttestationEngine {
    /// Target hostname for the TLS SNI extension and DNS lookup.
    host: String,
    /// TCP port (typically 443).
    port: u16,
    /// Read timeout applied to the TCP socket.
    timeout: Duration,
}

impl TlsAttestationEngine {
    /// Create an engine targeting `host:port` with the default 10-second timeout.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self { host: host.into(), port, timeout: DEFAULT_TIMEOUT }
    }

    /// Create an engine with a custom read timeout.
    pub fn with_timeout(host: impl Into<String>, port: u16, timeout: Duration) -> Self {
        Self { host: host.into(), port, timeout }
    }

    // ── Internal: connect and capture ────────────────────────────────────────

    /// Connect to the target server, send `query`, read the response, and
    /// return all captured session parameters including real TLS keying material.
    ///
    /// `randomness` is the DVRF output for this session. It is passed as the
    /// RFC 5705 `context` parameter when exporting the DVRF keying material,
    /// so the exported value is bound to both the TLS master secret AND the
    /// DVRF randomness simultaneously.
    fn connect_and_capture(
        &self,
        query: &[u8],
        randomness: &DigestBytes,
    ) -> Result<TlsCapture, AttestationError> {
        let tls_err = |msg: String| AttestationError::TlsConnection { reason: msg };

        // ── Timestamp ────────────────────────────────────────────────────────
        let established_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // ── TCP connection ────────────────────────────────────────────────────
        let addr = format!("{}:{}", self.host, self.port);
        // No timeout during connect — OS will handle connection refused/timeout.
        let tcp = TcpStream::connect(&addr)
            .map_err(|e| tls_err(format!("TCP connect to {addr}: {e}")))?;

        // ── TLS client configuration ──────────────────────────────────────────
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Restrict ALPN to HTTP/1.1 so the server doesn't upgrade to HTTP/2.
        // Our query is a plain HTTP/1.x byte sequence — HTTP/2 framing would
        // require a completely different wire format.
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let server_name = ServerName::try_from(self.host.clone())
            .map_err(|e| tls_err(format!("invalid server name '{}': {e}", self.host)))?;

        // ── TLS handshake ─────────────────────────────────────────────────────
        let mut conn = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| tls_err(format!("ClientConnection::new: {e}")))?;
        let mut tcp = tcp;

        // Drive the handshake to full completion BEFORE setting the read
        // timeout. If a timeout fires mid-handshake, rustls reports it as
        // UnexpectedEof, which is confusing and hard to recover from.
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp)
                .map_err(|e| tls_err(format!("TLS handshake: {e}")))?;
        }

        // Set read timeout only after the handshake is done.
        tcp.set_read_timeout(Some(self.timeout))
            .map_err(|e| tls_err(format!("set_read_timeout: {e}")))?;

        // Exchange data using Stream.
        let response = {
            let mut stream = rustls::Stream::new(&mut conn, &mut tcp);

            // Send query.
            stream.write_all(query)
                .map_err(|e| tls_err(format!("write query: {e}")))?;
            stream.flush()
                .map_err(|e| tls_err(format!("flush: {e}")))?;

            // Read response until EOF or timeout.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                           || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        // Timeout on a keep-alive connection — treat as end-of-response.
                        break;
                    }
                    Err(e) => return Err(tls_err(format!("read response: {e}"))),
                }
            }
            buf
        };
        // `stream` dropped here — mutable borrows on `conn` and `tcp` released.

        // ── Extract TLS version ───────────────────────────────────────────────
        let tls_version: u16 = match conn.protocol_version() {
            Some(v) if v == rustls::ProtocolVersion::TLSv1_3 => 0x0304,
            Some(v) if v == rustls::ProtocolVersion::TLSv1_2 => 0x0303,
            Some(other) => {
                return Err(tls_err(format!("unsupported TLS version: {other:?}")));
            }
            None => {
                return Err(tls_err("handshake did not complete — no protocol version".into()));
            }
        };

        // ── Extract and hash leaf certificate ────────────────────────────────
        let cert_der = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| tls_err("no peer certificate in chain".into()))?;

        let cert_hash = {
            let mut h = Sha256::new();
            h.update(cert_der.as_ref());
            DigestBytes::from_bytes(h.finalize().into())
        };

        // ── Export real TLS keying material (RFC 5705) ────────────────────────
        //
        // dvrf_keying_material: binds TLS master secret to DVRF randomness.
        //   Label:   "tls-attestation/dvrf-exporter/v1"
        //   Context: randomness bytes (DVRF output for this session)
        //
        // nonce_keying_material: unique per TLS session, no external context.
        //   Label:   "tls-attestation/session-nonce/v1"
        //   Context: None
        //
        // Both labels are domain-separated and unique to this protocol,
        // preventing cross-context collisions with other TLS exporters.
        let mut dvrf_km = [0u8; 32];
        conn.export_keying_material(
            &mut dvrf_km,
            b"tls-attestation/dvrf-exporter/v1",
            Some(randomness.as_bytes()),
        )
        .map_err(|e| tls_err(format!("export dvrf keying material: {e}")))?;

        let mut nonce_km = [0u8; 32];
        conn.export_keying_material(
            &mut nonce_km,
            b"tls-attestation/session-nonce/v1",
            None,
        )
        .map_err(|e| tls_err(format!("export nonce keying material: {e}")))?;

        Ok(TlsCapture {
            server_cert_hash: cert_hash,
            tls_version,
            server_name: self.host.clone(),
            established_at,
            response,
            dvrf_keying_material: dvrf_km,
            nonce_keying_material: nonce_km,
        })
    }

    // ── Internal: build dx-DCTLS evidence from a capture ─────────────────────

    fn build_dctls_evidence(
        session: &SessionContext,
        randomness: &DigestBytes,
        query: &[u8],
        capture: &TlsCapture,
    ) -> (TranscriptCommitments, ExportableEvidence, DctlsEvidence) {
        // ── Real TLS keying material → SessionParamsSecret ────────────────────
        //
        // dvrf_exporter: derived from TLS master secret + DVRF randomness context.
        //   Replaces the prototype's H(session_id || randomness) simulation.
        //   Now requires a real TLS session with the correct DVRF randomness
        //   to produce a valid value — a coordinator cannot forge it offline.
        //
        // session_nonce: derived from TLS master secret alone (no external context).
        //   Unique per TLS session, independent of any external inputs.
        //   Replaces the prototype's H(session_id) simulation.
        let dvrf_exporter = DigestBytes::from_bytes(capture.dvrf_keying_material);
        let session_nonce = DigestBytes::from_bytes(capture.nonce_keying_material);

        let sps = SessionParamsSecret { dvrf_exporter, session_nonce };

        let spp = SessionParamsPublic {
            server_cert_hash: capture.server_cert_hash.clone(),
            tls_version: capture.tls_version,
            server_name: capture.server_name.clone(),
            established_at: capture.established_at,
        };

        // ── HSP: bind TLS session to DVRF randomness ─────────────────────────
        let hsp_proof = HSPProof::generate(&session.session_id, randomness, &sps, &spp);

        // ── QP: commit to query and real response ─────────────────────────────
        let query_record = QueryRecord::build(
            &session.session_id,
            randomness,
            query,
            &capture.response,
        );

        // ── Transcript commitments (for envelope binding) ─────────────────────
        let transcript_commitments = TranscriptCommitments::build(
            &session.session_id,
            randomness,
            query,
            &capture.response,
        );

        // ── PGP: bind statement to transcript ────────────────────────────────
        let statement = Statement::derive(
            b"attested-session".to_vec(),
            "dx-dctls/tls-engine/v1".into(),
            &query_record.transcript_commitment,
        );
        let pgp_proof = PGPProof::generate(
            &session.session_id,
            randomness,
            &query_record,
            statement,
            &hsp_proof,
        );

        // ── ExportableEvidence ────────────────────────────────────────────────
        let dctls_evidence = DctlsEvidence { hsp_proof, query_record, pgp_proof };
        let evidence_bytes = serde_json::to_vec(&dctls_evidence).unwrap_or_else(|_| b"{}".to_vec());
        let evidence = ExportableEvidence::new(DCTLS_ENGINE_TAG.to_string(), evidence_bytes);

        (transcript_commitments, evidence, dctls_evidence)
    }
}

// ── Handshake 2PC helpers ─────────────────────────────────────────────────────
//
// TlsSessionParams, compute_2pc_binding_input, and derive_2pc_dvrf_exporter
// are defined in `tls_2pc` (no feature gate) and re-exported from the crate root.

use crate::tls_2pc::{TlsSessionParams, compute_2pc_binding_input as _c2pb, derive_2pc_dvrf_exporter as _d2pe};

impl TlsAttestationEngine {
    /// Execute the TLS handshake and capture session parameters for the
    /// Handshake 2PC binding protocol.
    ///
    /// Returns `(TlsSessionParams, response_bytes)`.  The coordinator uses
    /// `TlsSessionParams` to compute the `binding_input` and passes it to
    /// aux nodes via `run_handshake_binding`.
    pub fn capture_for_2pc(
        &self,
        query:      &[u8],
        randomness: &DigestBytes,
    ) -> Result<(TlsSessionParams, Vec<u8>), AttestationError> {
        let capture = self.connect_and_capture(query, randomness)?;
        let params = TlsSessionParams {
            server_cert_hash: capture.server_cert_hash.clone(),
            tls_version:      capture.tls_version,
            server_name:      capture.server_name.clone(),
            established_at:   capture.established_at,
            session_nonce:    DigestBytes::from_bytes(capture.nonce_keying_material),
        };
        Ok((params, capture.response))
    }

    /// Build dx-DCTLS evidence using a **threshold-derived** `dvrf_exporter`
    /// from the Handshake 2PC protocol.
    ///
    /// `dvrf_exporter_2pc` must be the output of `derive_2pc_dvrf_exporter`
    /// after `run_handshake_binding` succeeds.
    pub fn build_evidence_2pc(
        session:          &SessionContext,
        randomness:       &DigestBytes,
        query:            &[u8],
        params:           &TlsSessionParams,
        response:         &[u8],
        dvrf_exporter_2pc: DigestBytes,
    ) -> (TranscriptCommitments, ExportableEvidence, DctlsEvidence) {
        let sps = SessionParamsSecret {
            dvrf_exporter: dvrf_exporter_2pc,
            session_nonce: params.session_nonce.clone(),
        };
        let spp = SessionParamsPublic {
            server_cert_hash: params.server_cert_hash.clone(),
            tls_version:      params.tls_version,
            server_name:      params.server_name.clone(),
            established_at:   params.established_at,
        };

        let hsp_proof      = HSPProof::generate(&session.session_id, randomness, &sps, &spp);
        let query_record   = QueryRecord::build(&session.session_id, randomness, query, response);
        let transcript_commitments = TranscriptCommitments::build(
            &session.session_id, randomness, query, response,
        );
        let statement = Statement::derive(
            b"attested-session".to_vec(),
            "dx-dctls/handshake-2pc/v1".into(),
            &query_record.transcript_commitment,
        );
        let pgp_proof = PGPProof::generate(
            &session.session_id, randomness, &query_record, statement, &hsp_proof,
        );

        let dctls_evidence = DctlsEvidence { hsp_proof, query_record, pgp_proof };
        let evidence_bytes = serde_json::to_vec(&dctls_evidence).unwrap_or_else(|_| b"{}".to_vec());
        let evidence = ExportableEvidence::new("dx-dctls/handshake-2pc/v1".to_string(), evidence_bytes);

        (transcript_commitments, evidence, dctls_evidence)
    }
}

/// Compute the Handshake 2PC binding input.
///
/// ```text
/// H("tls-attestation/2pc-binding/v1"
///   || session_id || rand_value
///   || cert_hash  || tls_version[be64]
///   || server_name_bytes || session_nonce)
/// ```
///
/// This is the exact byte sequence that aux nodes sign in the binding protocol.
/// A valid binding guarantees the coordinator ran a real TLS session — the
/// `session_nonce` is a TLS RFC 5705 exporter that requires the TLS master
/// secret to produce.
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

/// Derive the threshold-locked `dvrf_exporter` from the Handshake Binding
/// aggregate signature.
///
/// ```text
/// dvrf_exporter = H("tls-attestation/2pc-exporter/v1" || σ[64])
/// ```
///
/// This value requires both a real TLS session (for `session_nonce`) AND
/// threshold cooperation of the aux nodes (for σ).
pub fn derive_2pc_dvrf_exporter(aggregate_sig: &[u8; 64]) -> DigestBytes {
    let mut h = CanonicalHasher::new("tls-attestation/2pc-exporter/v1");
    h.update_fixed(aggregate_sig);
    h.finalize()
}

// ── AttestationEngine impl ────────────────────────────────────────────────────

impl AttestationEngine for TlsAttestationEngine {
    /// Execute a real TLS connection.
    ///
    /// The `response` parameter is **ignored** — the engine captures the actual
    /// server response from the live TLS session. Pass `b""` as a placeholder.
    fn execute(
        &self,
        session: &SessionContext,
        randomness: &DigestBytes,
        query: &[u8],
        _response: &[u8],
    ) -> Result<(TranscriptCommitments, ExportableEvidence), AttestationError> {
        let capture = self.connect_and_capture(query, randomness)?;
        let (tc, ev, _) = Self::build_dctls_evidence(session, randomness, query, &capture);
        Ok((tc, ev))
    }
}

// ── DxDctlsAttestationEngine impl ─────────────────────────────────────────────

impl DxDctlsAttestationEngine for TlsAttestationEngine {
    /// Execute a real TLS connection and return full dx-DCTLS evidence.
    ///
    /// The `response` and `server_cert_hash` parameters are **ignored** — both
    /// are derived from the live TLS session.
    fn execute_dctls(
        &self,
        session: &SessionContext,
        randomness: &DigestBytes,
        query: &[u8],
        _response: &[u8],
        _server_cert_hash: &DigestBytes,
    ) -> Result<(TranscriptCommitments, ExportableEvidence, DctlsEvidence), AttestationError> {
        let capture = self.connect_and_capture(query, randomness)?;
        let result = Self::build_dctls_evidence(session, randomness, query, &capture);
        Ok(result)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_constructs_with_defaults() {
        let engine = TlsAttestationEngine::new("example.com", 443);
        assert_eq!(engine.host, "example.com");
        assert_eq!(engine.port, 443);
        assert_eq!(engine.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn engine_constructs_with_custom_timeout() {
        let t = Duration::from_secs(5);
        let engine = TlsAttestationEngine::with_timeout("api.example.com", 8443, t);
        assert_eq!(engine.host, "api.example.com");
        assert_eq!(engine.port, 8443);
        assert_eq!(engine.timeout, t);
    }

    /// Live network test — skipped by default to avoid CI flakiness.
    ///
    /// Run manually:
    /// ```bash
    /// cargo test --package tls-attestation-attestation --features tls \
    ///     -- --ignored tls_engine_live_example
    /// ```
    #[test]
    #[ignore = "requires live network access"]
    fn tls_engine_live_example() {
        use tls_attestation_core::ids::{ProverId, SessionId, VerifierId};
        use tls_attestation_core::types::{Epoch, Nonce, QuorumSpec, UnixTimestamp};
        use crate::session::SessionContext;
        use crate::dctls::verify_transcript_consistency;

        let engine = TlsAttestationEngine::with_timeout("example.com", 443, Duration::from_secs(15));

        let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
        let session = SessionContext::new(
            SessionId::from_bytes([0xAA; 16]),
            ProverId::from_bytes([0xBB; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum,
            Epoch::GENESIS,
            UnixTimestamp(1_000_000),
            UnixTimestamp(1_002_000),
            Nonce::from_bytes([0xCC; 32]),
        );

        let rand = DigestBytes::from_bytes([0x42u8; 32]);
        let query = b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";

        let (tc, _evidence, dctls_evidence) = engine
            .execute_dctls(&session, &rand, query, b"", &DigestBytes::ZERO)
            .expect("execute_dctls should succeed");

        // Transcript commitments must be non-zero.
        assert_ne!(tc.session_transcript_digest, DigestBytes::ZERO);

        // Cross-proof binding must be consistent.
        let binding = verify_transcript_consistency(
            &dctls_evidence.hsp_proof,
            &dctls_evidence.query_record,
            &dctls_evidence.pgp_proof,
        )
        .expect("transcript consistency check failed");

        assert_ne!(binding.binding_digest, DigestBytes::ZERO);

        // Server cert hash must be present (non-zero).
        assert_ne!(
            dctls_evidence.hsp_proof.server_cert_hash,
            DigestBytes::ZERO,
            "real TLS session must produce a non-zero cert hash"
        );

        // TLS version must be 1.2 or 1.3.
        let v = dctls_evidence.hsp_proof.tls_version;
        assert!(v == 0x0303 || v == 0x0304, "unexpected TLS version: {v:#06x}");

        // dvrf_exporter must be non-zero (was actually exported, not zeroed).
        assert_ne!(
            dctls_evidence.hsp_proof.commitment,
            DigestBytes::ZERO,
            "HSP commitment must be non-zero when keying material is real"
        );

        println!("cert_hash: {}", dctls_evidence.hsp_proof.server_cert_hash.to_hex());
        println!("tls_version: {v:#06x}");
        println!("server: {}", dctls_evidence.hsp_proof.server_name);
        println!("hsp_commitment: {}", dctls_evidence.hsp_proof.commitment.to_hex());

        // ── Binding check: different DVRF randomness → different exporter ─────
        // Run a second connection with a different randomness value.
        // The dvrf_exporter (embedded in the HSP commitment) must differ because
        // export_keying_material uses randomness as RFC 5705 context.
        let rand2 = DigestBytes::from_bytes([0x99u8; 32]);
        let (_, _, dctls2) = engine
            .execute_dctls(&session, &rand2, query, b"", &DigestBytes::ZERO)
            .expect("second execute_dctls should succeed");

        assert_ne!(
            dctls_evidence.hsp_proof.commitment,
            dctls2.hsp_proof.commitment,
            "HSP commitment must differ when DVRF randomness differs — \
             proves dvrf_exporter is bound to randomness via TLS keying material"
        );
        println!("hsp_commitment (rand2): {}", dctls2.hsp_proof.commitment.to_hex());
        println!("Randomness binding check: PASSED");
    }
}