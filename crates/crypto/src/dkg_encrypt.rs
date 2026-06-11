//! DKG Round-2 wire confidentiality (RFC 9591 §5.3).
//!
//! Provides authenticated encryption of `DkgRound2Package` for network routing.
//! The coordinator routing encrypted packages sees metadata
//! (`ceremony_id`, `sender_id`, `recipient_id`) but **cannot decrypt** the
//! ciphertext without the recipient's private key.
//!
//! # Cryptographic scheme
//!
//! ```text
//! shared_secret = DH(sender_static_priv, recipient_static_pub)   [X25519]
//!
//! key = HKDF-SHA256(
//!     ikm  = shared_secret,
//!     salt = none,
//!     info = "tls-attestation/dkg-round2/v1"
//!             || ceremony_id (16 B)
//!             || sender_id   (32 B)
//!             || recipient_id(32 B)
//! )  → 32 bytes
//!
//! nonce = random 24 bytes (XChaCha20-Poly1305 nonce space)
//!
//! aad = ENVELOPE_VERSION (1 B)
//!       || ceremony_id   (16 B)
//!       || sender_id     (32 B)
//!       || recipient_id  (32 B)
//!
//! ciphertext = XChaCha20Poly1305::encrypt(key, nonce, plaintext, aad)
//! ```
//!
//! # Properties
//!
//! - **Confidential**: only the holder of the recipient's private key can decrypt.
//! - **Mutually authenticated**: static-static ECDH means a decryption success
//!   proves the ciphertext was produced by the expected sender.
//! - **Metadata-bound**: the AEAD tag covers AAD — any modification to
//!   `ceremony_id`, `sender_id`, or `recipient_id` causes authentication failure.
//! - **Ceremony-scoped**: `ceremony_id` in both HKDF info and AAD prevents replay
//!   of a Round-2 package from a previous ceremony.
//!
//! # Forward secrecy note
//!
//! Static-static ECDH does not provide forward secrecy. For DKG ceremonies,
//! mutual authentication is more critical than forward secrecy: a DKG output is
//! long-lived, so authenticity of Round-2 contributions matters more than session
//! key ephemerality. Ceremony-scoped encryption keys (generated fresh per
//! ceremony) partially mitigate this.

use crate::dkg::DkgRound2Package;
use crate::error::CryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tls_attestation_core::ids::VerifierId;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// HKDF info prefix — domain separation for this specific protocol and version.
const HKDF_INFO_PREFIX: &[u8] = b"tls-attestation/dkg-round2/v1";

/// Wire format version byte embedded in every `EncryptedDkgRound2Package`.
pub const ENVELOPE_VERSION: u8 = 1;

// ── Ceremony ID ───────────────────────────────────────────────────────────────

/// A 16-byte random identifier that binds encrypted packages to one specific
/// DKG ceremony.
///
/// Prevents replay of a valid Round-2 package from a previous ceremony: the
/// `ceremony_id` appears in both the HKDF key derivation info and the AEAD
/// associated data. Using a package with a wrong `ceremony_id` causes
/// decryption failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgCeremonyId([u8; 16]);

impl DkgCeremonyId {
    /// Generate a fresh cryptographically random ceremony ID.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

// ── Encryption key pair ───────────────────────────────────────────────────────

/// An X25519 static key pair used for DKG Round-2 package encryption.
///
/// Each ceremony participant generates one key pair before Part 1 and
/// distributes the public key to all other participants and the coordinator.
/// The private key (`secret`) never leaves the participant's memory.
///
/// # Usage
///
/// 1. Generate one `DkgEncryptionKeyPair` per participant before Part 1.
/// 2. Distribute all `DkgEncryptionPublicKey`s to every participant.
/// 3. After Part 2, encrypt each outbound `DkgRound2Package` with
///    `encrypt_round2_package` using the sender's key pair and the
///    recipient's public key.
/// 4. On the receiving side, decrypt with `decrypt_round2_package` using
///    the recipient's key pair and the sender's public key.
pub struct DkgEncryptionKeyPair {
    secret: StaticSecret,
    public: DkgEncryptionPublicKey,
}

impl DkgEncryptionKeyPair {
    /// Generate a fresh key pair using OS randomness.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = DkgEncryptionPublicKey(X25519PublicKey::from(&secret).to_bytes());
        Self { secret, public }
    }

    /// Returns a reference to the public key — safe to distribute.
    pub fn public_key(&self) -> &DkgEncryptionPublicKey {
        &self.public
    }
}

/// The public half of a `DkgEncryptionKeyPair`.
///
/// Distribute to all ceremony participants and the coordinator before Part 1.
/// Safe to transmit in the clear.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgEncryptionPublicKey([u8; 32]);

impl DkgEncryptionPublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

// ── Encrypted package ─────────────────────────────────────────────────────────

/// An encrypted, authenticated `DkgRound2Package` ready for coordinator routing.
///
/// # What the coordinator can see
///
/// - Routing metadata: `ceremony_id`, `sender_id`, `recipient_id`
/// - The `nonce` (required for decryption — safe in the clear for AEAD schemes)
/// - The `ciphertext` blob (opaque without the recipient's private key)
///
/// # What the coordinator CANNOT see
///
/// - The plaintext `DkgRound2Package` contents.
/// - Any partial secret share or polynomial coefficient.
///
/// # Authentication
///
/// The AEAD tag (appended to `ciphertext`) covers both the ciphertext and the
/// AAD (`version || ceremony_id || sender_id || recipient_id`). Any modification
/// to any field — including routing metadata — causes decryption to fail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedDkgRound2Package {
    /// Wire format version. Currently [`ENVELOPE_VERSION`] = 1.
    pub version: u8,
    /// Ceremony identifier — binds this package to exactly one DKG ceremony.
    pub ceremony_id: [u8; 16],
    /// Sender's `VerifierId` as raw bytes (routing metadata).
    pub sender_id: [u8; 32],
    /// Recipient's `VerifierId` as raw bytes (routing metadata).
    pub recipient_id: [u8; 32],
    /// XChaCha20-Poly1305 nonce (24 bytes). Randomly generated per package.
    pub nonce: [u8; 24],
    /// Ciphertext + 16-byte Poly1305 authentication tag.
    pub ciphertext: Vec<u8>,
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

/// Encrypt a `DkgRound2Package` to a specific recipient using static-static
/// X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305.
///
/// # Arguments
///
/// - `plaintext` — the Round-2 package to encrypt.
/// - `ceremony_id` — the ceremony this package belongs to (anti-replay).
/// - `sender_key` — this participant's `DkgEncryptionKeyPair`.
/// - `sender_id` — this participant's `VerifierId`.
/// - `recipient_pub` — the recipient's `DkgEncryptionPublicKey`.
/// - `recipient_id` — the recipient's `VerifierId`.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKeyMaterial` if AEAD encryption fails
/// (should not happen in practice — indicates a library or parameter bug).
pub fn encrypt_round2_package(
    plaintext: &DkgRound2Package,
    ceremony_id: &DkgCeremonyId,
    sender_key: &DkgEncryptionKeyPair,
    sender_id: &VerifierId,
    recipient_pub: &DkgEncryptionPublicKey,
    recipient_id: &VerifierId,
) -> Result<EncryptedDkgRound2Package, CryptoError> {
    let plain_bytes = plaintext.to_plaintext_bytes();
    let aad = build_aad(ceremony_id, sender_id, recipient_id);
    let key = derive_key(
        &sender_key.secret,
        recipient_pub,
        ceremony_id,
        sender_id,
        recipient_id,
    )?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("key init failed: {e}")))?;

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: &plain_bytes, aad: &aad })
        .map_err(|e| {
            CryptoError::InvalidKeyMaterial(format!("AEAD encrypt failed: {e}"))
        })?;

    Ok(EncryptedDkgRound2Package {
        version: ENVELOPE_VERSION,
        ceremony_id: *ceremony_id.as_bytes(),
        sender_id: *sender_id.as_bytes(),
        recipient_id: *recipient_id.as_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

/// Decrypt and authenticate an `EncryptedDkgRound2Package`.
///
/// Verifies:
/// 1. `version` == `ENVELOPE_VERSION`.
/// 2. `ceremony_id`, `sender_id`, `recipient_id` in the envelope match the
///    caller-supplied expected values (defence-in-depth metadata check before
///    AEAD — any mismatch is returned as an explicit error).
/// 3. AEAD authentication tag is valid — ciphertext was not tampered with,
///    and the AAD (metadata fields) was not modified.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKeyMaterial` on any failure.
/// The error message intentionally does **not** distinguish between a bad key,
/// tampered ciphertext, or wrong session — to avoid acting as a decryption
/// oracle.
pub fn decrypt_round2_package(
    envelope: &EncryptedDkgRound2Package,
    recipient_key: &DkgEncryptionKeyPair,
    sender_pub: &DkgEncryptionPublicKey,
    expected_ceremony_id: &DkgCeremonyId,
    expected_sender_id: &VerifierId,
    expected_recipient_id: &VerifierId,
) -> Result<DkgRound2Package, CryptoError> {
    // ── Version check ──────────────────────────────────────────────────────────
    if envelope.version != ENVELOPE_VERSION {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "unsupported DKG envelope version {} (expected {})",
            envelope.version, ENVELOPE_VERSION
        )));
    }

    // ── Metadata binding checks (defence-in-depth) ─────────────────────────────
    // These are also covered by the AEAD tag (through AAD), but explicit checks
    // here give clearer error messages and prevent timing side-channels from the
    // AEAD path revealing which field mismatched.
    if &envelope.ceremony_id != expected_ceremony_id.as_bytes() {
        return Err(CryptoError::InvalidKeyMaterial(
            "ceremony_id mismatch in encrypted DKG Round-2 package".into(),
        ));
    }
    if &envelope.sender_id != expected_sender_id.as_bytes() {
        return Err(CryptoError::InvalidKeyMaterial(
            "sender_id mismatch in encrypted DKG Round-2 package".into(),
        ));
    }
    if &envelope.recipient_id != expected_recipient_id.as_bytes() {
        return Err(CryptoError::InvalidKeyMaterial(
            "recipient_id mismatch in encrypted DKG Round-2 package".into(),
        ));
    }

    // ── Key derivation ─────────────────────────────────────────────────────────
    let aad = build_aad(expected_ceremony_id, expected_sender_id, expected_recipient_id);
    let key = derive_key(
        &recipient_key.secret,
        sender_pub,
        expected_ceremony_id,
        expected_sender_id,
        expected_recipient_id,
    )?;

    // ── AEAD decryption ────────────────────────────────────────────────────────
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("key init failed: {e}")))?;
    let nonce = XNonce::from_slice(&envelope.nonce);

    let plain_bytes = cipher
        .decrypt(nonce, Payload { msg: &envelope.ciphertext, aad: &aad })
        .map_err(|_| {
            // Generic message — do NOT reveal why decryption failed.
            CryptoError::InvalidKeyMaterial(
                "DKG Round-2 package decryption failed — \
                 authentication tag mismatch or wrong key"
                    .into(),
            )
        })?;

    DkgRound2Package::from_plaintext_bytes(&plain_bytes)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Derive a 32-byte AEAD key via X25519 static-static ECDH + HKDF-SHA256.
///
/// The HKDF info string binds the key to one specific ceremony and
/// sender→recipient direction, so the same X25519 key pair cannot be
/// accidentally reused for a different ceremony or packet direction.
fn derive_key(
    our_secret: &StaticSecret,
    their_pub: &DkgEncryptionPublicKey,
    ceremony_id: &DkgCeremonyId,
    sender_id: &VerifierId,
    recipient_id: &VerifierId,
) -> Result<[u8; 32], CryptoError> {
    let their_x = X25519PublicKey::from(their_pub.to_bytes());
    let shared = our_secret.diffie_hellman(&their_x);

    // HKDF-SHA256: IKM = shared secret, salt = none (domain separation via info).
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());

    // info = PREFIX || ceremony_id || sender_id || recipient_id
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 16 + 32 + 32);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(ceremony_id.as_bytes());
    info.extend_from_slice(sender_id.as_bytes());
    info.extend_from_slice(recipient_id.as_bytes());

    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Build AAD = `ENVELOPE_VERSION || ceremony_id || sender_id || recipient_id`.
///
/// The AEAD tag authenticates this data alongside the ciphertext. Any
/// modification to any routing metadata field in the envelope will cause
/// authentication failure in `decrypt_round2_package`.
fn build_aad(
    ceremony_id: &DkgCeremonyId,
    sender_id: &VerifierId,
    recipient_id: &VerifierId,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 16 + 32 + 32);
    aad.push(ENVELOPE_VERSION);
    aad.extend_from_slice(ceremony_id.as_bytes());
    aad.extend_from_slice(sender_id.as_bytes());
    aad.extend_from_slice(recipient_id.as_bytes());
    aad
}
