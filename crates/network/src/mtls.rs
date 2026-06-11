//! Layer 4: mutual TLS certificate generation and rustls configuration.
//!
//! # Design
//!
//! A single `MtlsCaBundle` is the trust anchor for one cluster:
//! - A self-signed CA certificate and private key.
//! - Every node receives an `MtlsNodeBundle` — a certificate signed by the CA,
//!   plus the node's private key.
//!
//! Both sides of a connection verify each other's certificate against the
//! shared CA, providing:
//! - **Confidentiality** — traffic is TLS-encrypted.
//! - **Server authentication** — the client verifies the server's cert was
//!   issued by the cluster CA.
//! - **Client authentication** (mutual TLS) — the server verifies the client's
//!   cert was also issued by the cluster CA.
//!
//! # Certificate DNS names
//!
//! All node certificates include `"localhost"` as a DNS SAN so that
//! loopback tests can use `"localhost"` as the TLS `ServerName` while
//! connecting to `127.0.0.1`.  Production deployments should add the node's
//! actual hostname.

use std::sync::Arc;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
    ClientConfig, RootCertStore, ServerConfig,
};

use crate::error::NetworkError;

// ── MtlsCaBundle ─────────────────────────────────────────────────────────────

/// CA certificate and private key for one cluster.
#[derive(Clone)]
pub struct MtlsCaBundle {
    /// DER-encoded CA certificate (shared with nodes as a trust anchor).
    pub cert_der: Vec<u8>,
    /// PEM-encoded CA private key.
    key_pem: String,
}

impl MtlsCaBundle {
    /// Generate a fresh self-signed CA certificate and key pair.
    pub fn generate() -> Result<Self, NetworkError> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| NetworkError::Serialization(format!("CA key gen: {e}")))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "tls-attestation cluster CA");
        params.distinguished_name = dn;

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| NetworkError::Serialization(format!("CA self-sign: {e}")))?;

        Ok(Self {
            cert_der: cert.der().to_vec(),
            key_pem: key_pair.serialize_pem(),
        })
    }

    /// Issue a node certificate signed by this CA.
    ///
    /// `common_name` is embedded in the certificate's Distinguished Name for
    /// human-readable identification (not used for authentication).
    pub fn issue_node_bundle(&self, common_name: &str) -> Result<MtlsNodeBundle, NetworkError> {
        // Reconstruct the CA as an `Issuer` from DER + PEM key material.
        let ca_key = KeyPair::from_pem(&self.key_pem)
            .map_err(|e| NetworkError::Serialization(format!("CA key load: {e}")))?;
        let ca_der = CertificateDer::from(self.cert_der.clone());
        let issuer = Issuer::from_ca_cert_der(&ca_der, ca_key)
            .map_err(|e| NetworkError::Serialization(format!("CA issuer: {e}")))?;

        // Generate a fresh key for the node.
        let node_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| NetworkError::Serialization(format!("node key gen: {e}")))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        // All loopback tests connect using "localhost" as the TLS ServerName.
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|e| NetworkError::Serialization(format!("SAN: {e}")))?,
        )];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        let node_cert = params
            .signed_by(&node_key, &issuer)
            .map_err(|e| NetworkError::Serialization(format!("node sign: {e}")))?;

        Ok(MtlsNodeBundle {
            cert_der: node_cert.der().to_vec(),
            key_pem: node_key.serialize_pem(),
            ca_cert_der: self.cert_der.clone(),
        })
    }

    /// Build a `RootCertStore` that trusts only this CA.
    pub fn root_store(&self) -> Result<RootCertStore, NetworkError> {
        let mut store = RootCertStore::empty();
        store
            .add(CertificateDer::from(self.cert_der.clone()))
            .map_err(|e| NetworkError::Serialization(format!("root store: {e}")))?;
        Ok(store)
    }
}

// ── MtlsNodeBundle ────────────────────────────────────────────────────────────

/// A node's TLS credentials: CA-signed certificate + private key.
#[derive(Clone)]
pub struct MtlsNodeBundle {
    /// DER-encoded node certificate (chain: just the node cert for now).
    pub cert_der: Vec<u8>,
    /// PEM-encoded PKCS#8 private key.
    key_pem: String,
    /// DER-encoded CA certificate — used to build root stores.
    pub ca_cert_der: Vec<u8>,
}

impl MtlsNodeBundle {
    /// Build a rustls `ServerConfig` for an aux node requiring client auth.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, NetworkError> {
        let cert_chain = vec![CertificateDer::from(self.cert_der.clone())];
        let private_key = self.private_key()?;

        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(self.ca_cert_der.clone()))
            .map_err(|e| NetworkError::Serialization(format!("server root store: {e}")))?;

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| NetworkError::Serialization(format!("client verifier: {e}")))?;

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| NetworkError::Serialization(format!("server TLS config: {e}")))?;

        Ok(Arc::new(config))
    }

    /// Build a rustls `ClientConfig` presenting this node's certificate (mTLS).
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, NetworkError> {
        let cert_chain = vec![CertificateDer::from(self.cert_der.clone())];
        let private_key = self.private_key()?;

        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(self.ca_cert_der.clone()))
            .map_err(|e| NetworkError::Serialization(format!("client root store: {e}")))?;

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|e| NetworkError::Serialization(format!("client TLS config: {e}")))?;

        Ok(Arc::new(config))
    }

    /// The TLS `ServerName` to use when connecting to any cluster node.
    ///
    /// All issued certificates include `"localhost"` as a DNS SAN.
    pub fn server_name() -> ServerName<'static> {
        ServerName::try_from("localhost").unwrap().to_owned()
    }

    fn private_key(&self) -> Result<PrivateKeyDer<'static>, NetworkError> {
        rustls_pemfile::private_key(&mut self.key_pem.as_bytes())
            .map_err(|e| NetworkError::Serialization(format!("parse key: {e}")))?
            .ok_or_else(|| NetworkError::Serialization("no private key in PEM".into()))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ca() -> MtlsCaBundle {
        MtlsCaBundle::generate().unwrap()
    }

    #[test]
    fn ca_generate_succeeds() {
        let ca = make_ca();
        assert!(!ca.cert_der.is_empty());
        assert!(!ca.key_pem.is_empty());
    }

    #[test]
    fn issue_node_bundle_succeeds() {
        let ca = make_ca();
        let bundle = ca.issue_node_bundle("node-1").unwrap();
        assert!(!bundle.cert_der.is_empty());
        assert!(!bundle.key_pem.is_empty());
        assert_eq!(bundle.ca_cert_der, ca.cert_der);
    }

    #[test]
    fn server_config_builds() {
        let ca = make_ca();
        ca.issue_node_bundle("node-1").unwrap().server_config().unwrap();
    }

    #[test]
    fn client_config_builds() {
        let ca = make_ca();
        ca.issue_node_bundle("node-1").unwrap().client_config().unwrap();
    }

    #[test]
    fn two_nodes_get_distinct_certs() {
        let ca = make_ca();
        let b1 = ca.issue_node_bundle("n1").unwrap();
        let b2 = ca.issue_node_bundle("n2").unwrap();
        assert_ne!(b1.cert_der, b2.cert_der);
        assert_eq!(b1.ca_cert_der, b2.ca_cert_der);
    }

    #[test]
    fn root_store_builds() {
        let ca = make_ca();
        ca.root_store().unwrap();
    }
}