//! HMAC-SHA256 R1CS gadget for TLS-PRF circuit.
//!
//! # Paper reference — §IX
//!
//! The TLS-PRF is built from HMAC-SHA256:
//! ```text
//! HMAC-SHA256(K, data) = SHA256((K ⊕ opad) || SHA256((K ⊕ ipad) || data))
//! ```
//! where ipad = 0x36 × 64, opad = 0x5c × 64.
//!
//! # Constraint cost
//!
//! Each HMAC-SHA256 call requires exactly 2 SHA256 compressions:
//!   - inner: SHA256((K ⊕ ipad) || data)  — 1 block for 32-byte data
//!   - outer: SHA256((K ⊕ opad) || inner) — 1 block
//!
//! 2 compressions × 37,416 constraints = ~74,832 constraints per HMAC.
//!
//! TLS-PRF P_SHA256(secret, seed):
//!   A(1) = HMAC(secret, seed)                    → 2 compressions
//!   A(2) = HMAC(secret, A(1))                    → 2 compressions
//!   output1 = HMAC(secret, A(1) || seed)         → 2-3 compressions
//!   output2 = HMAC(secret, A(2) || seed)         → 2-3 compressions
//!
//! Full TLS-PRF key expansion: ~10-12 HMAC calls → ~20-24 SHA256 blocks.
//! Master secret derivation: ~6-8 HMAC calls → ~12-16 SHA256 blocks.
//! Total: ~36-40 SHA256 blocks → ~1.35-1.5M constraints (vs paper's 1.72M for 60 blocks).

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{uint8::UInt8, uint32::UInt32},
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::sha256_gadget::{
    sha256_gadget, sha256_pad, parse_block_native, state_to_bytes,
    sha256_compress, sha256_from_byte_vars, SHA256_H,
};

// ── HMAC-SHA256 gadget ────────────────────────────────────────────────────────

/// HMAC-SHA256 in R1CS.
///
/// Computes HMAC-SHA256(key, data) in-circuit, producing 32 output bytes.
///
/// # Constraints
/// 2 × SHA256_block_constraints ≈ 2 × 37,416 = ~74,832 constraints.
///
/// # Key handling
/// If key.len() > 64, key is first hashed to 32 bytes.
/// If key.len() < 64, key is zero-padded.
pub fn hmac_sha256_gadget(
    cs: ConstraintSystemRef<Fr>,
    key: &[u8],
    data: &[u8],
) -> Result<[u8; 32], SynthesisError> {
    // Normalize key to 64 bytes.
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        // Hash key if too long.
        use sha2::Digest;
        let hashed: [u8; 32] = sha2::Sha256::digest(key).into();
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    // Compute ipad and opad blocks.
    let mut ipad_key = [0u8; 64];
    let mut opad_key = [0u8; 64];
    for i in 0..64 {
        ipad_key[i] = k_block[i] ^ 0x36;
        opad_key[i] = k_block[i] ^ 0x5c;
    }

    // Inner hash: SHA256(ipad_key || data)
    let inner_msg: Vec<u8> = ipad_key.iter().chain(data.iter()).cloned().collect();
    let inner_state = sha256_gadget(cs.clone(), &inner_msg)?;
    let inner_bytes = state_to_bytes(&inner_state)?;

    // Outer hash: SHA256(opad_key || inner_hash)
    let outer_msg: Vec<u8> = opad_key.iter().chain(inner_bytes.iter()).cloned().collect();
    let outer_state = sha256_gadget(cs, &outer_msg)?;
    state_to_bytes(&outer_state)
}

// ── Constrained HMAC-SHA256 gadget (UInt8 in/out) ────────────────────────────

/// HMAC-SHA256 in R1CS with **constrained** key and data inputs.
///
/// Unlike `hmac_sha256_gadget`, this variant accepts `UInt8<Fr>` circuit
/// variables for both key and data, ensuring the entire computation is
/// enforced in the R1CS system.  The output is also constrained `UInt8<Fr>`
/// variables — callers can accumulate them into a TLS-PRF output and enforce
/// equality against a public input without losing the R1CS binding.
///
/// # Key handling
///
/// TLS-PRF secrets (PMS, master secret) are always ≤ 48 bytes, so we never
/// need in-circuit key hashing.  Keys longer than 64 bytes are unsupported
/// (returns `SynthesisError::AssignmentMissing`).  Keys shorter than 64 bytes
/// are zero-padded with constant `UInt8::constant(0)` variables.
///
/// # Constraint cost
/// 2 × SHA256_block ≈ 74,832 constraints per HMAC call.
pub fn hmac_sha256_gadget_constrained(
    cs: ConstraintSystemRef<Fr>,
    key_vars: &[UInt8<Fr>],
    data_vars: &[UInt8<Fr>],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    if key_vars.len() > 64 {
        // Keys longer than 64 bytes would need in-circuit SHA256 for normalization.
        // TLS-PRF keys are always ≤ 48 bytes so this path should never trigger.
        return Err(SynthesisError::AssignmentMissing);
    }

    // Pad key to 64 bytes with constant zeros.
    let mut k_padded: Vec<UInt8<Fr>> = key_vars.to_vec();
    while k_padded.len() < 64 {
        k_padded.push(UInt8::constant(0u8));
    }

    // XOR padded key with ipad (0x36) and opad (0x5c) using in-circuit XOR.
    let ipad_key: Vec<UInt8<Fr>> = k_padded
        .iter()
        .map(|b| b.xor(&UInt8::constant(0x36u8)))
        .collect::<Result<_, _>>()?;

    let opad_key: Vec<UInt8<Fr>> = k_padded
        .iter()
        .map(|b| b.xor(&UInt8::constant(0x5cu8)))
        .collect::<Result<_, _>>()?;

    // Inner: SHA256(ipad_key || data)
    let mut inner_msg = ipad_key;
    inner_msg.extend_from_slice(data_vars);
    let inner_hash = sha256_from_byte_vars(cs.clone(), &inner_msg)?;

    // Outer: SHA256(opad_key || inner_hash)
    let mut outer_msg = opad_key;
    outer_msg.extend(inner_hash);
    sha256_from_byte_vars(cs, &outer_msg)
}

/// Constrained TLS 1.2 PRF = P_SHA256(secret_vars, label_and_seed_vars, output_len).
///
/// Produces `output_len` constrained `UInt8<Fr>` bytes via iterated HMAC.
/// Every byte of output is R1CS-constrained to the `secret_vars` witness.
///
/// # Constraint cost
/// num_iterations × 2 × SHA256_block ≈ num_iters × 74,832 constraints.
pub fn tls_prf_p_sha256_constrained(
    cs: ConstraintSystemRef<Fr>,
    secret_vars: &[UInt8<Fr>],
    label_and_seed_vars: &[UInt8<Fr>],
    output_len: usize,
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut output: Vec<UInt8<Fr>> = Vec::new();

    // A(0) = label || seed.
    let mut a_prev: Vec<UInt8<Fr>> = label_and_seed_vars.to_vec();

    while output.len() < output_len {
        // A(i) = HMAC(secret, A(i-1))
        let a_i = hmac_sha256_gadget_constrained(cs.clone(), secret_vars, &a_prev)?;

        // HMAC(secret, A(i) || seed)
        let mut hmac_input = a_i.clone();
        hmac_input.extend_from_slice(label_and_seed_vars);
        let block_out = hmac_sha256_gadget_constrained(cs.clone(), secret_vars, &hmac_input)?;
        output.extend(block_out);

        a_prev = a_i;
    }

    output.truncate(output_len);
    Ok(output)
}

/// Constrained TLS 1.2 master secret derivation.
///
/// `pms_vars`: constrained pre-master secret bytes (the Zp witness).
/// `client_random`, `server_random`: public constants (not secret in HSP context).
///
/// Returns 48 constrained `UInt8<Fr>` bytes encoding the master secret.
pub fn tls12_master_secret_constrained(
    cs: ConstraintSystemRef<Fr>,
    pms_vars: &[UInt8<Fr>],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    // Label is a protocol constant — safe to embed as UInt8::constant.
    // CR and SR are allocated as witnesses so the CRS is session-independent:
    // UInt8::constant embeds the byte value into R1CS coefficients, making the
    // matrix (and therefore the CRS) specific to those exact byte values.
    // UInt8::new_witness keeps the structure generic — only the assignment changes.
    let label_vars: Vec<UInt8<Fr>> = b"master secret"
        .iter()
        .map(|&b| UInt8::constant(b))
        .collect();

    let cr_vars: Vec<UInt8<Fr>> = client_random
        .iter()
        .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
        .collect::<Result<_, _>>()?;

    let sr_vars: Vec<UInt8<Fr>> = server_random
        .iter()
        .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
        .collect::<Result<_, _>>()?;

    let mut label_seed_vars = label_vars;
    label_seed_vars.extend(cr_vars);
    label_seed_vars.extend(sr_vars);

    tls_prf_p_sha256_constrained(cs, pms_vars, &label_seed_vars, 48)
}

/// Constrained TLS 1.2 key expansion.
///
/// `ms_vars`: constrained master secret bytes (48 bytes).
/// `client_random`, `server_random`: public constants.
///
/// Returns 96 constrained bytes: [K^P_MAC(32) | K^V_MAC(32) | write_key(16) | write_key(16)]
pub fn tls12_key_expansion_constrained(
    cs: ConstraintSystemRef<Fr>,
    ms_vars: &[UInt8<Fr>],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    // Note: key_expansion seed reverses the random order vs master secret.
    // CR/SR allocated as witnesses (not constants) to keep CRS session-independent.
    let label_vars: Vec<UInt8<Fr>> = b"key expansion"
        .iter()
        .map(|&b| UInt8::constant(b))
        .collect();

    let sr_vars: Vec<UInt8<Fr>> = server_random
        .iter()
        .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
        .collect::<Result<_, _>>()?;

    let cr_vars: Vec<UInt8<Fr>> = client_random
        .iter()
        .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
        .collect::<Result<_, _>>()?;

    let mut label_seed_vars = label_vars;
    label_seed_vars.extend(sr_vars);
    label_seed_vars.extend(cr_vars);

    tls_prf_p_sha256_constrained(cs, ms_vars, &label_seed_vars, 96)
}

// ── TLS-PRF P_SHA256 gadget ───────────────────────────────────────────────────

/// TLS 1.2 PRF = P_SHA256(secret, label || seed)
///
/// From RFC 5246 §5:
/// ```text
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) || seed) ||
///                        HMAC_hash(secret, A(2) || seed) || ...
/// where A(0) = seed
///       A(i) = HMAC_hash(secret, A(i-1))
/// ```
///
/// Generates `output_len` bytes from the PRF.
///
/// # Constraints
/// num_iterations × 2 × SHA256_block ≈ num_iters × 74,832 constraints.
pub fn tls_prf_p_sha256_gadget(
    cs: ConstraintSystemRef<Fr>,
    secret: &[u8],
    label_and_seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, SynthesisError> {
    let mut output = Vec::new();

    // A(0) = label || seed.
    let mut a_prev = label_and_seed.to_vec();

    while output.len() < output_len {
        // A(i) = HMAC(secret, A(i-1))
        let a_i = hmac_sha256_gadget(cs.clone(), secret, &a_prev)?;

        // HMAC(secret, A(i) || seed)
        let hmac_input: Vec<u8> = a_i.iter().chain(label_and_seed.iter()).cloned().collect();
        let block_out = hmac_sha256_gadget(cs.clone(), secret, &hmac_input)?;
        output.extend_from_slice(&block_out);

        a_prev = a_i.to_vec();
    }

    output.truncate(output_len);
    Ok(output)
}

// ── TLS 1.2 master secret derivation ─────────────────────────────────────────

/// Derive TLS 1.2 master secret from pre-master secret (Zp).
///
/// RFC 5246: master_secret = PRF(pre_master_secret, "master secret",
///                                ClientHello.random + ServerHello.random)
///
/// This is the Zp input to the co-SNARK: `K_MAC = TLS-PRF(Zp, label, seed)`.
pub fn tls12_master_secret_gadget(
    cs: ConstraintSystemRef<Fr>,
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<[u8; 48], SynthesisError> {
    let label_seed: Vec<u8> = b"master secret"
        .iter()
        .chain(client_random.iter())
        .chain(server_random.iter())
        .cloned()
        .collect();

    let out = tls_prf_p_sha256_gadget(cs, pre_master_secret, &label_seed, 48)?;
    let mut result = [0u8; 48];
    result.copy_from_slice(&out);
    Ok(result)
}

/// Derive TLS 1.2 key material from master secret.
///
/// RFC 5246: key_block = PRF(master_secret, "key expansion",
///                            ServerHello.random + ClientHello.random)
///
/// For TLS_RSA_WITH_AES_128_CBC_SHA256:
///   client_write_MAC_key: 32 bytes (K_MAC for Prover)
///   server_write_MAC_key: 32 bytes (K_MAC for Coordinator)
///   client_write_key:     16 bytes
///   server_write_key:     16 bytes
///   client_write_IV:       0 bytes (TLS 1.2, implicit)
///   server_write_IV:       0 bytes
///
/// Total: 96 bytes needed.
pub fn tls12_key_expansion_gadget(
    cs: ConstraintSystemRef<Fr>,
    master_secret: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<Tls12KeyMaterial, SynthesisError> {
    // Note: key_expansion seed uses server_random || client_random (reversed).
    let label_seed: Vec<u8> = b"key expansion"
        .iter()
        .chain(server_random.iter())
        .chain(client_random.iter())
        .cloned()
        .collect();

    let key_block = tls_prf_p_sha256_gadget(cs, master_secret, &label_seed, 96)?;

    let mut km = Tls12KeyMaterial::default();
    km.client_write_mac_key.copy_from_slice(&key_block[0..32]);
    km.server_write_mac_key.copy_from_slice(&key_block[32..64]);
    km.client_write_key.copy_from_slice(&key_block[64..80]);
    km.server_write_key.copy_from_slice(&key_block[80..96]);
    Ok(km)
}

/// TLS 1.2 key material for AES-128-CBC-SHA256.
#[derive(Default, Clone, Debug)]
pub struct Tls12KeyMaterial {
    /// K^P_MAC: Prover's MAC key (32 bytes).
    pub client_write_mac_key: [u8; 32],
    /// K^V_MAC: Coordinator Verifier's MAC key (32 bytes).
    pub server_write_mac_key: [u8; 32],
    /// AES-128 write key (16 bytes).
    pub client_write_key: [u8; 16],
    /// AES-128 write key (16 bytes).
    pub server_write_key: [u8; 16],
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    fn native_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(key).unwrap();
        m.update(data);
        m.finalize().into_bytes().into()
    }

    #[test]
    fn hmac_sha256_gadget_matches_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let key  = b"super-secret-key";
        let data = b"hello world";
        let got = hmac_sha256_gadget(cs.clone(), key, data).unwrap();
        let expected = native_hmac(key, data);
        assert_eq!(got, expected, "HMAC-SHA256 gadget must match native");
        println!("HMAC-SHA256 constraints: {}", cs.num_constraints());
    }

    #[test]
    fn tls_prf_output_length() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let secret = [0x42u8; 48];
        let seed   = b"master secretABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234567890123456789";
        let out = tls_prf_p_sha256_gadget(cs.clone(), &secret, seed, 48).unwrap();
        assert_eq!(out.len(), 48);
        println!("TLS-PRF(48 bytes) constraints: {}", cs.num_constraints());
    }

    #[test]
    fn tls12_key_expansion_lengths() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let ms = [0x11u8; 48];
        let cr = [0x22u8; 32];
        let sr = [0x33u8; 32];
        let km = tls12_key_expansion_gadget(cs.clone(), &ms, &cr, &sr).unwrap();
        assert_eq!(km.client_write_mac_key.len(), 32);
        assert_eq!(km.server_write_mac_key.len(), 32);
        println!("Key expansion constraints: {}", cs.num_constraints());
    }

    #[test]
    fn tls12_master_secret_length() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pms = [0x55u8; 48];
        let cr  = [0xAAu8; 32];
        let sr  = [0xBBu8; 32];
        let ms = tls12_master_secret_gadget(cs.clone(), &pms, &cr, &sr).unwrap();
        assert_eq!(ms.len(), 48);
        println!("Master secret constraints: {}", cs.num_constraints());
    }
}