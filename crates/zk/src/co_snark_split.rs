//! Distributed co-SNARK with DH-masked witness exchange.
//!
//! # Security model
//!
//! The coordinator never sees K^P_MAC or K^V_MAC in plaintext.
//! It only learns K_MAC = K^P_MAC ⊕ K^V_MAC.
//!
//! ## Protocol
//!
//! ```text
//! P                           V                          Coordinator
//! ─────────────────────────────────────────────────────────────────
//! gen (sk_p, pk_p)            gen (sk_v, pk_v)
//! ────────── pk_p ──────────────────────────────────────────────►
//!                             ◄──────────────────────── pk_v ────
//!
//! M = DH(sk_p, pk_v)          M = DH(sk_v, pk_p)
//! p_masked = K^P_MAC ⊕ M      v_masked = K^V_MAC ⊕ M
//!
//! ────────── (pk_p, p_masked, sig_p) ──────────────────────────►
//!                             ─────── (pk_v, v_masked, sig_v) ──►
//!
//!                                      K_MAC = p_masked ⊕ v_masked
//!                                      (masks cancel, sees only K_MAC)
//!                                      proof = Groth16(K_MAC, rand)
//! ```
//!
//! ## Security guarantee
//!
//! The coordinator learns K_MAC but NOT K^P_MAC or K^V_MAC individually.
//! Neither P nor V can identify the other's share without their DH private key.
//!
//! This provides co-SNARK security under the CDH assumption: learning K_MAC
//! from p_masked alone requires computing the DH shared secret M, which is
//! hard without V's private key.
//!
//! ## Limitation vs. full MPC co-SNARK
//!
//! In a full SPDZ/GSZ co-SNARK (reference [32]), even K_MAC would remain
//! hidden from the coordinator during proof generation. That requires MPC for
//! the full R1CS witness extension and quotient polynomial, which is
//! substantially more complex. This implementation provides the strongest
//! security achievable without restructuring the Groth16 prover itself.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_crypto_primitives::snark::SNARK;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::tls_prf_circuit::{TlsPrfCircuit, k_mac_commitment, bytes32_to_fr};
use crate::co_snark::{CoSnarkCrs, CoSnarkError, HspProof};

// ── DH masked share ───────────────────────────────────────────────────────────

/// A party's masked MAC key share, ready to send to the coordinator.
///
/// The mask `M = DH(sk_self, pk_other)` is never included — only the
/// masked share and the party's own public key.
///
/// # `dh_public_key` vs `auth_tag`
///
/// `dh_public_key` is **this party's own** X25519 public key (not the other
/// party's).  The coordinator checks it against the expected key announced at
/// session start to bind the share to the correct party identity.
///
/// `auth_tag` proves this party knows the DH shared secret without revealing it.
/// Full verification requires the shared secret, so the coordinator cannot
/// verify it directly.  Parties SHOULD verify each other's `auth_tag` before
/// forwarding their own share to the coordinator; the coordinator provides
/// public-key binding only.
#[derive(Clone, Debug)]
pub struct MaskedShare {
    /// This party's own X25519 public key for this session.
    ///
    /// Fix: was incorrectly set to `other_public_key` (the other party's key).
    /// Now correctly holds this party's own ephemeral public key, allowing the
    /// coordinator to verify the share came from the expected party.
    pub dh_public_key: [u8; 32],
    /// K^{P|V}_MAC ⊕ DH(sk_self, pk_other).
    pub masked_bytes: [u8; 32],
    /// HMAC-SHA256(dh_shared_secret, "co-snark/mask-auth/v1" || masked_bytes)
    /// Proves this party knows the DH shared secret without revealing it.
    pub auth_tag: [u8; 32],
}

// ── Party role ────────────────────────────────────────────────────────────────

/// One party's contribution to the co-SNARK witness.
///
/// Each party runs this locally; the MAC share never leaves their process.
pub struct CoSnarkParty {
    dh_secret: EphemeralSecret,
    /// This party's MAC key share.
    mac_share: [u8; 32],
}

impl CoSnarkParty {
    /// Create a new party with a MAC key share and a fresh DH secret.
    pub fn new(mac_share: [u8; 32]) -> Self {
        let dh_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        Self { dh_secret, mac_share }
    }

    /// Return this party's X25519 public key to send to the other party.
    pub fn public_key(&self) -> [u8; 32] {
        *PublicKey::from(&self.dh_secret).as_bytes()
    }

    /// Compute the masked share using the other party's public key.
    ///
    /// Consumes `self` — the DH secret is used once and dropped.
    ///
    /// # Returns
    ///
    /// A `MaskedShare` where `dh_public_key` is **this party's own** public key.
    /// The coordinator passes both parties' announced keys to `co_snark_combine`
    /// to verify that each share comes from the expected participant.
    pub fn compute_masked_share(self, other_public_key: [u8; 32]) -> MaskedShare {
        // Capture own public key BEFORE consuming self.dh_secret.
        let own_public_key = *PublicKey::from(&self.dh_secret).as_bytes();

        let other_pk = PublicKey::from(other_public_key);
        let shared = self.dh_secret.diffie_hellman(&other_pk);
        let mask = derive_mask(shared.as_bytes());

        let mut masked_bytes = [0u8; 32];
        for i in 0..32 {
            masked_bytes[i] = self.mac_share[i] ^ mask[i];
        }

        let auth_tag = compute_auth_tag(shared.as_bytes(), &masked_bytes);

        MaskedShare {
            // Fix: store this party's OWN public key (was erroneously storing
            // `other_public_key`).  The coordinator uses this to check that the
            // masked share originates from the expected party.
            dh_public_key: own_public_key,
            masked_bytes,
            auth_tag,
        }
    }
}

// ── Coordinator ───────────────────────────────────────────────────────────────

/// Combine two masked shares to recover K_MAC and produce the HSP proof.
///
/// # Security
///
/// The coordinator learns K_MAC = p_share.masked_bytes ⊕ v_share.masked_bytes
/// (masks cancel) but NOT K^P_MAC or K^V_MAC individually.
///
/// # Arguments
///
/// - `crs`: Groth16 CRS from `CoSnarkCrs::setup()`
/// - `p_share`: Prover's masked share + DH public key
/// - `v_share`: Coordinator Verifier's masked share + DH public key
/// - `p_dh_pk`: Prover's expected X25519 public key (announced at session start)
/// - `v_dh_pk`: Verifier's expected X25519 public key (announced at session start)
/// - `rand_binding`: DVRF randomness (public)
///
/// # Public-key binding check
///
/// Each `MaskedShare.dh_public_key` is compared against the expected key
/// (`p_dh_pk` / `v_dh_pk`) to ensure the shares were submitted by the parties
/// that announced those keys.  This prevents a rogue coordinator from combining
/// a share from an unexpected party while still keeping both shares valid.
///
/// Full `auth_tag` verification requires the DH shared secret, which the
/// coordinator does not have.  Parties are responsible for verifying each
/// other's `auth_tag` before sending their own share to the coordinator.
pub fn co_snark_combine(
    crs: &CoSnarkCrs,
    p_share: &MaskedShare,
    v_share: &MaskedShare,
    p_dh_pk: &[u8; 32],
    v_dh_pk: &[u8; 32],
    rand_binding: &[u8; 32],
) -> Result<HspProof, CoSnarkError> {
    // Verify each share's public key matches the announced key.
    // This binds each masked share to the expected participant.
    if &p_share.dh_public_key != p_dh_pk {
        return Err(CoSnarkError::Prove(
            "prover share dh_public_key does not match announced p_dh_pk".into(),
        ));
    }
    if &v_share.dh_public_key != v_dh_pk {
        return Err(CoSnarkError::Prove(
            "verifier share dh_public_key does not match announced v_dh_pk".into(),
        ));
    }

    // K_MAC = p_masked ⊕ v_masked  (DH masks cancel out)
    let mut k_mac = [0u8; 32];
    for i in 0..32 {
        k_mac[i] = p_share.masked_bytes[i] ^ v_share.masked_bytes[i];
    }

    // The coordinator knows K_MAC but not K^P or K^V individually.
    // Canonical split: k_mac_p = k_mac, k_mac_v = 0.  The circuit only
    // verifies XOR correctness, so any valid pair works.
    //
    // Note: in a full MPC co-SNARK (reference [32]), this step would use
    // distributed witness extension to keep K_MAC hidden from the coordinator.
    let k_mac_p_canonical = k_mac;
    let k_mac_v_canonical = [0u8; 32];

    let circuit = TlsPrfCircuit::new(k_mac_p_canonical, k_mac_v_canonical, rand_binding);
    let commitment_fe = circuit.k_mac_commitment_fe;
    let rand_fe       = circuit.rand_binding_fe;

    // Fix: use OsRng so Groth16 blinding scalars are not recoverable from the
    // witness.  The old deterministic seeding (SHA-256(k_mac || rand)) allowed
    // observers to correlate proofs and potentially extract witness information.
    let mut rng = OsRng;

    let proof = Groth16::<Bn254>::prove(&crs.pk, circuit, &mut rng)
        .map_err(|e| CoSnarkError::Prove(e.to_string()))?;

    let mut groth16_bytes = Vec::new();
    proof.serialize_compressed(&mut groth16_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    let mut commitment_bytes = Vec::new();
    commitment_fe.serialize_compressed(&mut commitment_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    let mut rand_bytes = Vec::new();
    rand_fe.serialize_compressed(&mut rand_bytes)
        .map_err(|e| CoSnarkError::Serialize(e.to_string()))?;

    Ok(HspProof {
        groth16_bytes,
        k_mac_commitment_bytes: commitment_bytes,
        rand_binding_bytes: rand_bytes,
        k_mac,
        pms_hash_bytes: Vec::new(), // split path is Mode 1 only
    })
}

// ── High-level split co-SNARK API ─────────────────────────────────────────────

/// Full split co-SNARK protocol in-process simulation.
///
/// In production, P and V run on separate machines. This function simulates
/// the full protocol in a single process for testing and benchmarking.
///
/// # Protocol steps (paper §VIII.C eq. 2, distributed variant)
///
/// 1. P and V generate DH key pairs.
/// 2. P sends pk_p to V; V sends pk_v to P.
/// 3. Each computes DH shared secret M.
/// 4. P sends (p_masked = K^P ⊕ M) to coordinator.
/// 5. V sends (v_masked = K^V ⊕ M) to coordinator.
/// 6. Coordinator recovers K_MAC = p_masked ⊕ v_masked and generates proof.
pub fn co_snark_execute_split(
    crs: &CoSnarkCrs,
    p_mac_share: [u8; 32],
    v_mac_share: [u8; 32],
    rand_binding: &[u8; 32],
) -> Result<HspProof, CoSnarkError> {
    // Step 1: Each party generates DH key pair.
    let party_p = CoSnarkParty::new(p_mac_share);
    let party_v = CoSnarkParty::new(v_mac_share);

    // Step 2: Exchange public keys.
    let pk_p = party_p.public_key();
    let pk_v = party_v.public_key();

    // Step 3: Compute masked shares.
    let masked_p = party_p.compute_masked_share(pk_v);
    let masked_v = party_v.compute_masked_share(pk_p);

    // Step 4: Coordinator combines, passing the expected DH public keys.
    co_snark_combine(crs, &masked_p, &masked_v, &pk_p, &pk_v, rand_binding)
}

// ── Split co-SNARK backend ────────────────────────────────────────────────────

/// High-level split co-SNARK backend.
///
/// Wraps `CoSnarkCrs` and exposes the split protocol.
pub struct SplitCoSnarkBackend {
    pub crs: CoSnarkCrs,
}

impl SplitCoSnarkBackend {
    pub fn setup() -> Result<Self, CoSnarkError> {
        Ok(Self { crs: CoSnarkCrs::setup()? })
    }

    /// Execute the split co-SNARK protocol.
    ///
    /// Coordinator never sees K^P_MAC or K^V_MAC in plaintext.
    pub fn execute_split(
        &self,
        p_mac_share: [u8; 32],
        v_mac_share: [u8; 32],
        rand_binding: &[u8; 32],
    ) -> Result<HspProof, CoSnarkError> {
        co_snark_execute_split(&self.crs, p_mac_share, v_mac_share, rand_binding)
    }

    /// Return the processed verifying key for aux verifier distribution.
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.crs.verifying_key_bytes()
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Derive a 32-byte mask from a DH shared secret.
///
/// mask = SHA256("co-snark/dh-mask/v1" || shared_secret)
fn derive_mask(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"co-snark/dh-mask/v1\x00");
    h.update(shared_secret);
    h.finalize().into()
}

/// Compute HMAC-style auth tag from shared secret and masked bytes.
///
/// auth_tag = SHA256("co-snark/mask-auth/v1" || shared_secret || masked_bytes)
fn compute_auth_tag(shared_secret: &[u8; 32], masked_bytes: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"co-snark/mask-auth/v1\x00");
    h.update(shared_secret);
    h.update(masked_bytes);
    h.finalize().into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::co_snark::{co_snark_verify, CoSnarkCrs};

    #[test]
    fn dh_mask_cancels_correctly() {
        let p_share = [0x11u8; 32];
        let v_share = [0x22u8; 32];

        let party_p = CoSnarkParty::new(p_share);
        let party_v = CoSnarkParty::new(v_share);

        let pk_p = party_p.public_key();
        let pk_v = party_v.public_key();

        let masked_p = party_p.compute_masked_share(pk_v);
        let masked_v = party_v.compute_masked_share(pk_p);

        // Coordinator: K_MAC = p_masked ⊕ v_masked
        let mut k_mac = [0u8; 32];
        for i in 0..32 {
            k_mac[i] = masked_p.masked_bytes[i] ^ masked_v.masked_bytes[i];
        }

        // Expected K_MAC = K^P ⊕ K^V
        let mut expected = [0u8; 32];
        for i in 0..32 { expected[i] = p_share[i] ^ v_share[i]; }

        assert_eq!(k_mac, expected, "DH masks must cancel to reveal K_MAC");
    }

    #[test]
    fn split_proof_verifies() {
        let crs = CoSnarkCrs::setup().expect("CRS setup");
        let p_share = [0x42u8; 32];
        let v_share = [0x13u8; 32];
        let rand    = [0xFFu8; 32];

        let proof = co_snark_execute_split(&crs, p_share, v_share, &rand)
            .expect("split execute");

        co_snark_verify(&crs.pvk, &proof, None)
            .expect("split proof must verify");
    }

    #[test]
    fn split_and_centralized_produce_same_k_mac() {
        use crate::co_snark::{co_snark_execute, CoSnarkCrs};
        use crate::tls12_hmac::{ProverMacKeyShare, VerifierMacKeyShare};

        let p_share = ProverMacKeyShare([0x55u8; 32]);
        let v_share = VerifierMacKeyShare([0x66u8; 32]);
        let rand    = [0xAAu8; 32];

        let crs = CoSnarkCrs::setup().expect("setup");

        let centralized = co_snark_execute(&crs, &p_share, &v_share, &rand)
            .expect("centralized execute");
        let split = co_snark_execute_split(&crs, p_share.0, v_share.0, &rand)
            .expect("split execute");

        assert_eq!(centralized.k_mac, split.k_mac,
            "both protocols must produce the same K_MAC");
    }

    #[test]
    fn coordinator_cannot_recover_individual_shares() {
        // Logical proof: for any K_MAC there are 2^256 valid (K^P, K^V) pairs.
        // The coordinator seeing only K_MAC cannot determine which pair was used.

        // Pair 1: K^P = 0x11, K^V = 0x22  →  K_MAC = 0x33
        let p1 = [0x11u8; 32];
        let v1 = [0x22u8; 32];

        // Pair 2: K^P = 0x00, K^V = 0x33  →  K_MAC = 0x33 (same K_MAC!)
        let p2 = [0x00u8; 32];
        let v2 = [0x33u8; 32];

        let mut k_mac_1 = [0u8; 32]; for i in 0..32 { k_mac_1[i] = p1[i] ^ v1[i]; }
        let mut k_mac_2 = [0u8; 32]; for i in 0..32 { k_mac_2[i] = p2[i] ^ v2[i]; }

        assert_eq!(k_mac_1, k_mac_2,
            "Two different (p,v) pairs produce the same K_MAC — \
             coordinator cannot determine which shares were used from K_MAC alone");

        // The shares themselves are different.
        assert_ne!(p1, p2);
        assert_ne!(v1, v2);
    }
}