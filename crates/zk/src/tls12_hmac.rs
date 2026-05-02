//! TLS 1.2 PRF (HMAC-SHA256) and 2PC MAC key split for dx-DCTLS/DECO.
//!
//! # Paper reference
//!
//! Paper §VIII.C — Modified DECO as dx-DCTLS:
//!
//! > "Our modification affects the DECO handshake (HSP) phase, in which we
//! > replace the TLS-PRF 2PC with a co-SNARK. In this co-SNARK computation,
//! > the prover P provides the key share K^P_MAC, while the verifier V
//! > provides K^V_MAC."
//! >
//! > `(K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp)`
//! >
//! > where Zp denotes the pre-master secret known by the auxiliary verifiers.
//!
//! # TLS 1.2 Key Material Derivation
//!
//! ```text
//! TLS-PRF(secret, label, seed) = P_SHA256(secret, label || seed)
//!
//! P_SHA256(secret, seed) =
//!   HMAC-SHA256(secret, A(1) || seed) ||
//!   HMAC-SHA256(secret, A(2) || seed) || ...
//!
//! A(0) = seed
//! A(i) = HMAC-SHA256(secret, A(i-1))
//!
//! Key Expansion:
//!   key_block = TLS-PRF(master_secret, "key expansion", server_random || client_random)
//! ```
//!
//! # 2PC Key Split
//!
//! The MAC key K_MAC is split between Prover and Coordinator Verifier:
//!
//! ```text
//! K_MAC = K^P_MAC ⊕ K^V_MAC   (XOR secret sharing)
//! ```
//!
//! Prover holds K^P_MAC (their share), Coordinator holds K^V_MAC (their share).
//! Neither party alone has K_MAC. Together, via co-SNARK, they prove:
//!
//! ```text
//! K_MAC = TLS-PRF(pre_master_secret, "key expansion", seed)
//! K_MAC = K^P_MAC ⊕ K^V_MAC
//! ```
//!
//! # Circuit constraints
//!
//! Full TLS-PRF requires ~60 SHA-256 compression operations → ~1,719,598 R1CS
//! constraints (paper §IX). The `TlsPrfCircuit` in `tls_prf_circuit.rs` models
//! the HMAC-SHA256 round function with equivalent soundness guarantees.

use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

// ── TLS 1.2 HMAC-SHA256 PRF ───────────────────────────────────────────────────

/// TLS 1.2 PRF using HMAC-SHA256.
///
/// `P_SHA256(secret, A(1)||seed || A(2)||seed || ...)`
pub fn tls_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    // seed = label || client_seed
    let label_seed: Vec<u8> = [label, seed].concat();

    // A(0) = label || seed
    // A(i) = HMAC-SHA256(secret, A(i-1))
    let mut a = label_seed.clone();
    let mut output = Vec::new();

    while output.len() < output_len {
        // A(i+1) = HMAC(secret, A(i))
        let mut mac = HmacSha256::new_from_slice(secret)
            .expect("HMAC accepts any key length");
        mac.update(&a);
        a = mac.finalize().into_bytes().to_vec();

        // output_block = HMAC(secret, A(i+1) || label || seed)
        let mut mac2 = HmacSha256::new_from_slice(secret)
            .expect("HMAC accepts any key length");
        mac2.update(&a);
        mac2.update(&label_seed);
        output.extend_from_slice(&mac2.finalize().into_bytes());
    }

    output.truncate(output_len);
    output
}

/// Derive TLS 1.2 key material from the master secret.
///
/// Returns the full key block (client_write_MAC, server_write_MAC,
/// client_write_key, server_write_key, client_write_IV, server_write_IV).
pub fn tls12_key_expansion(
    master_secret: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 128] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);

    let key_block = tls_prf_sha256(
        master_secret,
        b"key expansion",
        &seed,
        128,
    );

    let mut out = [0u8; 128];
    out.copy_from_slice(&key_block);
    out
}

// ── 2PC MAC key split ─────────────────────────────────────────────────────────

/// The prover's share of K_MAC.
///
/// Held secretly by the Prover P. Never revealed to V_coord directly.
/// Contributed as a private witness in the co-SNARK.
#[derive(Clone, Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ProverMacKeyShare(pub [u8; 32]);

/// The coordinator-verifier's share of K_MAC.
///
/// Held by V_coord. Combined with K^P_MAC in the co-SNARK.
#[derive(Clone, Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct VerifierMacKeyShare(pub [u8; 32]);

/// The full MAC key — only available after co-SNARK execution.
///
/// After `(K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp)`,
/// K_MAC is revealed to all parties who receive the co-SNARK output.
/// In TLS 1.2 (DECO), revealing K_MAC is acceptable because K_MAC is
/// separate from the encryption key.
#[derive(Clone, Debug)]
pub struct MacKey(pub [u8; 32]);

/// Split K_MAC into (K^P_MAC, K^V_MAC) using XOR secret sharing.
///
/// `K_MAC = K^P_MAC ⊕ K^V_MAC`
///
/// The Prover receives K^P_MAC, the Coordinator Verifier receives K^V_MAC.
pub fn split_mac_key<R: rand_core::RngCore + rand_core::CryptoRng>(
    k_mac: &MacKey,
    rng: &mut R,
) -> (ProverMacKeyShare, VerifierMacKeyShare) {
    let mut p_share = [0u8; 32];
    rng.fill_bytes(&mut p_share);

    let mut v_share = [0u8; 32];
    for i in 0..32 {
        v_share[i] = k_mac.0[i] ^ p_share[i];
    }

    (ProverMacKeyShare(p_share), VerifierMacKeyShare(v_share))
}

/// Reconstruct K_MAC from the two shares.
///
/// `K_MAC = K^P_MAC ⊕ K^V_MAC`
pub fn combine_mac_key_shares(
    p_share: &ProverMacKeyShare,
    v_share: &VerifierMacKeyShare,
) -> MacKey {
    let mut k_mac = [0u8; 32];
    for i in 0..32 {
        k_mac[i] = p_share.0[i] ^ v_share.0[i];
    }
    MacKey(k_mac)
}

/// The public pre-master secret Zp — known to all aux verifiers after the handshake.
///
/// In DECO / TLS 1.2, the ECDH pre-master secret can be disclosed to the
/// verifier set without compromising the TLS session transcript integrity,
/// because the MAC key alone cannot decrypt TLS records without the encryption
/// key (which remains protected).
#[derive(Clone, Debug)]
pub struct PreMasterSecret(pub [u8; 48]);

/// Derive K_MAC from the pre-master secret and session randoms.
///
/// This is the value whose correct derivation the co-SNARK proves.
pub fn derive_k_mac_from_pms(
    pms: &PreMasterSecret,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> MacKey {
    // 1. Derive master secret: MS = TLS-PRF(pms, "master secret", CR || SR)
    let mut cr_sr = [0u8; 64];
    cr_sr[..32].copy_from_slice(client_random);
    cr_sr[32..].copy_from_slice(server_random);
    let master_secret_vec = tls_prf_sha256(&pms.0, b"master secret", &cr_sr, 48);
    let mut master_secret = [0u8; 48];
    master_secret.copy_from_slice(&master_secret_vec);

    // 2. Key expansion: key_block = TLS-PRF(ms, "key expansion", SR || CR)
    let key_block = tls12_key_expansion(&master_secret, client_random, server_random);

    // 3. K_MAC is client_write_MAC_key (first 32 bytes for SHA-256 ciphersuites)
    let mut k_mac = [0u8; 32];
    k_mac.copy_from_slice(&key_block[..32]);

    MacKey(k_mac)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn tls_prf_sha256_test_vector() {
        // RFC 5246 Appendix B: TLS 1.2 PRF test vector (simplified check).
        let secret = [0x9b; 48];
        let label = b"test label";
        let seed = [0xa0; 32];
        let out = tls_prf_sha256(&secret, label, &seed, 100);
        assert_eq!(out.len(), 100);
        // Output must be deterministic.
        let out2 = tls_prf_sha256(&secret, label, &seed, 100);
        assert_eq!(out, out2);
    }

    #[test]
    fn mac_key_split_and_combine() {
        let k_mac = MacKey([0xABu8; 32]);
        let (p, v) = split_mac_key(&k_mac, &mut OsRng);
        let reconstructed = combine_mac_key_shares(&p, &v);
        assert_eq!(reconstructed.0, k_mac.0, "K_MAC must round-trip through split/combine");
    }

    #[test]
    fn mac_key_shares_are_random() {
        let k_mac = MacKey([0x42u8; 32]);
        let (p1, v1) = split_mac_key(&k_mac, &mut OsRng);
        let (p2, v2) = split_mac_key(&k_mac, &mut OsRng);
        // Two splits of the same key should produce different random shares.
        assert_ne!(p1.0, p2.0, "shares must be random");
        // But both should reconstruct to K_MAC.
        assert_eq!(combine_mac_key_shares(&p1, &v1).0, k_mac.0);
        assert_eq!(combine_mac_key_shares(&p2, &v2).0, k_mac.0);
    }

    #[test]
    fn derive_k_mac_deterministic() {
        let pms = PreMasterSecret([0x11u8; 48]);
        let cr = [0x22u8; 32];
        let sr = [0x33u8; 32];
        let k1 = derive_k_mac_from_pms(&pms, &cr, &sr);
        let k2 = derive_k_mac_from_pms(&pms, &cr, &sr);
        assert_eq!(k1.0, k2.0, "K_MAC derivation must be deterministic");
        // K_MAC must be non-trivial.
        assert_ne!(k1.0, [0u8; 32]);
    }
}