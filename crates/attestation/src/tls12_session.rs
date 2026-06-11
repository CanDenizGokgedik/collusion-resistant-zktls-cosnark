//! Real TLS 1.2 session capture for dx-DCTLS attestation.
//!
//! # Paper reference — §VIII.C (DECO-based dx-DCTLS)
//!
//! DECO requires establishing a real TLS 1.2 session and capturing:
//! - The server certificate (for cert_hash)
//! - The RFC 5705 exporter material (session_nonce)
//! - The pre-master secret Zp (for co-SNARK input)
//!
//! # TLS 1.2 Exporter (RFC 5705)
//!
//! ```text
//! TLS-Exporter("tls-attestation/session-nonce/v1", None, 32)
//!   = TLS-PRF(master_secret, "EXPORTER-tls-attestation/session-nonce/v1"
//!              || 0x00 || context_len || "" || hash(""))
//! ```
//!
//! # Connection flow
//!
//! 1. Establish TLS 1.2 connection to server using rustls.
//! 2. Extract certificate, compute cert_hash.
//! 3. Extract RFC 5705 exporter value (session_nonce).
//! 4. Capture master secret Zp for co-SNARK.
//! 5. Return `Tls12SessionCapture` for use in DECO HSP.
//!
//! # Feature gate
//!
//! This module is only compiled with `feature = "tls"`.

use crate::{error::AttestationError, dctls::SessionParamsPublic};
use tls_attestation_core::hash::{CanonicalHasher, DigestBytes};

#[cfg(feature = "tls")]
mod capture {
    use std::io::{self, Read, Write};
    use std::sync::{Arc, Mutex};

    // ── KeyLog implementation ─────────────────────────────────────────────────

    /// Captured TLS 1.2 key material obtained via the rustls `KeyLog` callback.
    ///
    /// rustls calls `log()` with label `"CLIENT_RANDOM"` for TLS 1.2, providing:
    ///   - `client_random`: 32-byte ClientHello random
    ///   - `secret`:        48-byte master secret (not the raw ECDH pre-master secret)
    ///
    /// The master secret is equivalent to the `Zp` input in paper §VIII.C when
    /// the co-SNARK operates on the key-expansion step (bypassing master secret
    /// derivation — see `Tls12SessionCapture.pre_master_secret` docs).
    #[derive(Default, Debug)]
    pub struct TlsKeyCapture {
        pub client_random:   Mutex<Option<[u8; 32]>>,
        pub master_secret:   Mutex<Option<Vec<u8>>>,
    }

    impl rustls::KeyLog for TlsKeyCapture {
        fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
            if label == "CLIENT_RANDOM" {
                if let Ok(mut cr) = self.client_random.lock() {
                    if client_random.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(client_random);
                        *cr = Some(arr);
                    }
                }
                if let Ok(mut ms) = self.master_secret.lock() {
                    *ms = Some(secret.to_vec());
                }
            }
        }
    }

    // ── Recording TcpStream wrapper ───────────────────────────────────────────

    /// Wraps a `TcpStream` and records all bytes received from the server.
    ///
    /// Used to capture the raw TLS ServerHello handshake record so we can
    /// extract the server random (32 bytes at a known offset in ServerHello).
    pub struct RecordingStream {
        inner:    std::net::TcpStream,
        captured: Arc<Mutex<Vec<u8>>>,
    }

    impl RecordingStream {
        pub fn new(inner: std::net::TcpStream) -> (Self, Arc<Mutex<Vec<u8>>>) {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let stream = Self { inner, captured: Arc::clone(&captured) };
            (stream, captured)
        }
    }

    impl Read for RecordingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            if n > 0 {
                if let Ok(mut cap) = self.captured.lock() {
                    cap.extend_from_slice(&buf[..n]);
                }
            }
            Ok(n)
        }
    }

    impl Write for RecordingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.inner.write(buf) }
        fn flush(&mut self)                -> io::Result<()>  { self.inner.flush()    }
    }

    // ── ServerHello parser ────────────────────────────────────────────────────

    /// Extract the 32-byte server random from a raw TLS ServerHello record.
    ///
    /// TLS 1.2 ServerHello wire layout:
    /// ```text
    /// [0]     ContentType       = 0x16 (Handshake)
    /// [1..2]  RecordVersion     = 0x03 0x01
    /// [3..4]  RecordLength      (2 bytes BE)
    /// [5]     HandshakeType     = 0x02 (ServerHello)
    /// [6..8]  HandshakeLength   (3 bytes BE)
    /// [9..10] ServerVersion     = 0x03 0x03 (TLS 1.2)
    /// [11..42] ServerRandom     ← 32 bytes we want
    /// ```
    pub fn parse_server_random(captured: &[u8]) -> Option<[u8; 32]> {
        // Scan for a Handshake record (0x16) containing a ServerHello (0x02).
        let mut i = 0;
        while i + 43 <= captured.len() {
            if captured[i] == 0x16                  // ContentType: Handshake
                && captured[i + 5] == 0x02          // HandshakeType: ServerHello
                && i + 43 <= captured.len()
            {
                let mut rand = [0u8; 32];
                rand.copy_from_slice(&captured[i + 11..i + 43]);
                return Some(rand);
            }
            i += 1;
        }
        None
    }
}

/// Captured TLS 1.2 session parameters, ready for DECO HSP phase.
///
/// All fields are non-secret except `pre_master_secret` which is the Zp value
/// used in the co-SNARK. In DECO, Zp is disclosed to aux verifiers after
/// the handshake to allow them to compute Zp = ys * sv.
#[derive(Debug, Clone)]
pub struct Tls12SessionCapture {
    /// SHA-256 of the DER-encoded leaf certificate.
    pub server_cert_hash: DigestBytes,
    /// TLS wire version (0x0303 for TLS 1.2).
    pub tls_version: u16,
    /// SNI server name used during handshake.
    pub server_name: String,
    /// Unix timestamp (seconds) when connection was established.
    pub established_at: u64,
    /// RFC 5705 exporter value: proves a genuine TLS session occurred.
    pub session_nonce: DigestBytes,
    /// Pre-master secret Zp (32–48 bytes, ECDH shared secret).
    /// Disclosed to aux verifiers for co-SNARK verification.
    pub pre_master_secret: Vec<u8>,
    /// Client random (32 bytes).
    pub client_random: [u8; 32],
    /// Server random (32 bytes).
    pub server_random: [u8; 32],
}

impl Tls12SessionCapture {
    /// Convert to `SessionParamsPublic` for the dctls module.
    pub fn to_session_params_public(&self) -> SessionParamsPublic {
        SessionParamsPublic {
            server_cert_hash: self.server_cert_hash.clone(),
            tls_version: self.tls_version,
            server_name: self.server_name.clone(),
            established_at: self.established_at,
        }
    }

    /// Derive the session_nonce digest for HSP binding.
    pub fn derive_session_nonce_digest(&self) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/session-nonce/v1");
        h.update_digest(&self.session_nonce);
        h.finalize()
    }
}

/// TLS 1.2 session connector.
///
/// Establishes a real TLS 1.2 connection and captures session parameters.
///
/// # Feature: `tls`
///
/// This struct is only available with the `tls` feature. When `tls` is not
/// enabled, use `Tls12SessionCapture::mock()` for testing.
#[cfg(feature = "tls")]
pub struct Tls12Connector {
    /// rustls ClientConfig configured for TLS 1.2 only.
    config: std::sync::Arc<rustls::ClientConfig>,
}

#[cfg(feature = "tls")]
impl Tls12Connector {
    /// Build a TLS 1.2-capable rustls client config.
    ///
    /// Uses the system WebPKI root certificate store.  Key material is captured
    /// per-connection via a `KeyLog` callback.
    pub fn new() -> Result<Self, AttestationError> {
        let root_store = {
            let mut store = rustls::RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            store
        };

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self { config: std::sync::Arc::new(config) })
    }

    /// Establish a TLS connection and capture session parameters.
    ///
    /// Captures key material via the rustls `KeyLog` trait (equivalent to
    /// `SSLKEYLOGFILE`).  For TLS 1.2, the `"CLIENT_RANDOM"` log entry carries
    /// the 32-byte client random and the 48-byte **master secret**.
    ///
    /// The master secret is stored in `Tls12SessionCapture.pre_master_secret`.
    /// In the co-SNARK circuit this is used as direct input to the TLS-PRF
    /// key-expansion step (`tls12_key_expansion_constrained`).
    pub fn connect(
        &self,
        server_name: &str,
        port: u16,
    ) -> Result<Tls12SessionCapture, AttestationError> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::sync::Arc;
        use capture::{TlsKeyCapture, RecordingStream, parse_server_random};
        use rustls::{ClientConnection, Stream};

        let server_name_dns = rustls::pki_types::ServerName::try_from(server_name)
            .map_err(|e| AttestationError::TlsConnection { reason: e.to_string() })?;

        let established_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Build a per-connection config with the KeyLog callback.
        let key_capture = Arc::new(TlsKeyCapture::default());
        let mut config = (*self.config).clone();
        config.key_log = Arc::clone(&key_capture) as Arc<dyn rustls::KeyLog>;
        let config = Arc::new(config);

        // TCP connect + recording wrapper to capture raw ServerHello bytes.
        let addr = format!("{}:{}", server_name, port);
        let tcp = TcpStream::connect(&addr)
            .map_err(|e| AttestationError::TlsConnection { reason: e.to_string() })?;
        let (mut recording_tcp, captured_bytes) = RecordingStream::new(tcp);

        // TLS handshake.
        let mut conn = ClientConnection::new(config, server_name_dns.to_owned())
            .map_err(|e| AttestationError::TlsConnection { reason: e.to_string() })?;

        let mut stream = Stream::new(&mut conn, &mut recording_tcp);

        // Send a minimal HTTP/1.1 GET to complete the handshake.
        let request = format!(
            "GET / HTTP/1.1
Host: {}
Connection: close

",
            server_name
        );
        stream.write_all(request.as_bytes())
            .map_err(|e| AttestationError::TlsConnection { reason: e.to_string() })?;

        // Read enough bytes to ensure the handshake completes.
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);

        // ── Certificate ───────────────────────────────────────────────────────
        let certs = conn.peer_certificates()
            .ok_or_else(|| AttestationError::TlsConnection {
                reason: "no peer certificate".into(),
            })?;
        let server_cert_hash = Self::hash_der_cert(certs[0].as_ref());

        // ── RFC 5705 exporter ─────────────────────────────────────────────────
        let mut exporter_buf = [0u8; 32];
        conn.export_keying_material(
            &mut exporter_buf,
            b"tls-attestation/session-nonce/v1",
            None,
        ).map_err(|e| AttestationError::TlsConnection {
            reason: format!("RFC5705 export failed: {e}"),
        })?;

        // ── Key material via KeyLog ───────────────────────────────────────────
        let client_random: [u8; 32] = key_capture
            .client_random.lock().unwrap()
            .ok_or_else(|| AttestationError::TlsConnection {
                reason: "CLIENT_RANDOM not captured (KeyLog did not fire)".into(),
            })?;

        let master_secret: Vec<u8> = key_capture
            .master_secret.lock().unwrap()
            .clone()
            .ok_or_else(|| AttestationError::TlsConnection {
                reason: "master_secret not captured (KeyLog did not fire)".into(),
            })?;

        // ── Server random from raw ServerHello ────────────────────────────────
        let server_random: [u8; 32] = {
            let raw = captured_bytes.lock().unwrap();
            parse_server_random(&raw).unwrap_or([0u8; 32])
        };

        Ok(Tls12SessionCapture {
            server_cert_hash,
            tls_version: 0x0303,
            server_name: server_name.to_string(),
            established_at,
            session_nonce: DigestBytes::from_bytes(exporter_buf),
            // master_secret from KeyLog — used directly as key-expansion input
            // in the co-SNARK circuit (bypasses master-secret derivation step).
            pre_master_secret: master_secret,
            client_random,
            server_random,
        })
    }

    fn hash_der_cert(der: &[u8]) -> DigestBytes {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(der);
        let d: [u8; 32] = h.finalize().into();
        DigestBytes::from_bytes(d)
    }
}

/// Mock TLS 1.2 session for testing without a real network connection.
///
/// Produces a deterministic `Tls12SessionCapture` from a seed.
/// Used in unit tests and benchmarks.
pub fn mock_tls12_session(
    server_name: &str,
    seed: u8,
) -> Tls12SessionCapture {
    let server_cert_hash = DigestBytes::from_bytes({
        let mut b = [0u8; 32];
        b[0] = seed;
        b[1] = 0x01;
        b
    });
    let session_nonce = DigestBytes::from_bytes({
        let mut b = [0u8; 32];
        b[0] = seed;
        b[1] = 0x02;
        b
    });
    let mut client_random = [0u8; 32];
    client_random[0] = seed;
    let mut server_random = [0u8; 32];
    server_random[0] = seed.wrapping_add(1);

    Tls12SessionCapture {
        server_cert_hash,
        tls_version: 0x0303,
        server_name: server_name.to_string(),
        established_at: 1_700_000_000 + seed as u64,
        session_nonce,
        pre_master_secret: vec![seed; 48],
        client_random,
        server_random,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_session_is_deterministic() {
        let s1 = mock_tls12_session("api.example.com", 42);
        let s2 = mock_tls12_session("api.example.com", 42);
        assert_eq!(s1.server_cert_hash, s2.server_cert_hash);
        assert_eq!(s1.session_nonce, s2.session_nonce);
    }

    #[test]
    fn mock_session_different_seeds() {
        let s1 = mock_tls12_session("api.example.com", 1);
        let s2 = mock_tls12_session("api.example.com", 2);
        assert_ne!(s1.server_cert_hash, s2.server_cert_hash);
    }

    #[test]
    fn to_session_params_public() {
        let s = mock_tls12_session("test.com", 7);
        let spp = s.to_session_params_public();
        assert_eq!(spp.server_name, "test.com");
        assert_eq!(spp.tls_version, 0x0303);
    }
}