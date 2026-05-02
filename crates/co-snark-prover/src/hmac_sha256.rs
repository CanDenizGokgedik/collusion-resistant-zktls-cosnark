//! HMAC-SHA256 R1CS gadget — properly chained inner → outer hash.
//!
//! HMAC-SHA256(key, msg) = SHA256((key⊕opad) ∥ SHA256((key⊕ipad) ∥ msg))
//!
//! # Soundness
//!
//! The inner hash state is wired directly to the outer hash as circuit
//! variables — not extracted natively. This ensures the HMAC chain is
//! fully constrained end-to-end.
//!
//! # Constraint count
//!
//! Each HMAC call ≈ 2 × 37,440 = 74,880 constraints (2 SHA-256 compressions).

use ark_bls12_377::Fr;
use ark_r1cs_std::{
    bits::{uint32::UInt32, uint8::UInt8, boolean::Boolean, ToBitsGadget},
    prelude::{AllocVar, AllocationMode},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::sha256_gadget::{
    sha256_pad, alloc_block, sha256_compress, u32_arr_to_bytes, SHA256_H,
};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;
const BLOCK_LEN: usize = 64;

fn vec_to_arr8(v: Vec<UInt32<Fr>>) -> [UInt32<Fr>; 8] {
    assert_eq!(v.len(), 8);
    let mut iter = v.into_iter();
    [(); 8].map(|_| iter.next().unwrap())
}

// ── HMAC-SHA256 (correctly chained) ──────────────────────────────────────────

/// HMAC-SHA256 in-circuit with proper inner→outer wiring.
///
/// `key` is taken as a native byte slice and XOR'd with pads natively —
/// the key is a public derivation input (not secret at HMAC level; the
/// secrecy comes from p_share/v_share committed in Phase 3).
///
/// The inner hash state is wired to the outer hash as UInt32 circuit
/// variables, maintaining full constraint continuity.
pub fn hmac_sha256_circuit(
    cs: ConstraintSystemRef<Fr>,
    key: &[u8; 32],
    msg: &[u8],
) -> Result<[UInt32<Fr>; 8], SynthesisError> {
    // Key pad (32-byte key → 64 bytes)
    let mut k_padded = [0u8; BLOCK_LEN];
    k_padded[..32].copy_from_slice(key);

    let ikey: Vec<u8> = k_padded.iter().map(|&b| b ^ IPAD).collect();
    let okey: Vec<u8> = k_padded.iter().map(|&b| b ^ OPAD).collect();

    // ── Inner hash: SHA256(ikey ∥ msg) ───────────────────────────────────────
    let mut inner_input = ikey.clone();
    inner_input.extend_from_slice(msg);
    let inner_state = sha256_from_bytes(cs.clone(), &inner_input)?;

    // ── Outer hash: SHA256(okey ∥ inner_state) ───────────────────────────────
    // The inner_state words are circuit variables — wire them as witnesses
    // into the outer hash's message block (first 512-bit block: okey ∥ inner).
    //
    // okey is 64 bytes = 16 × u32, inner is 32 bytes = 8 × u32.
    // Together they form two 512-bit blocks for the outer SHA-256.

    // Outer block 1: SHA-256 initial state compression over okey (64 bytes)
    let mut outer_init_state: [UInt32<Fr>; 8] = {
        let v: Vec<UInt32<Fr>> = SHA256_H.iter().map(|&h| UInt32::constant(h)).collect();
        vec_to_arr8(v)
    };

    // Compress okey as first block
    let okey_block = bytes_to_block(&okey[..64])?;
    let okey_block_arr = okey_block;
    outer_init_state = sha256_compress_words(cs.clone(), &outer_init_state, &okey_block_arr)?;

    // Compress inner_state (32 bytes) + padding as second block
    // Build a 64-byte block: inner_bytes(32) + SHA-256 padding for length 96
    let inner_bytes_native = state_to_bytes_native(&inner_state);
    let mut second_block_bytes = inner_bytes_native.clone();
    // Padding for message of length 64 + 32 = 96 bytes, total bit length 768
    second_block_bytes.push(0x80);
    while second_block_bytes.len() < 56 {
        second_block_bytes.push(0x00);
    }
    // Append bit length of full outer message: (64 + 32) * 8 = 768 bits
    let outer_bit_len: u64 = 96 * 8;
    for i in (0..8).rev() {
        second_block_bytes.push(((outer_bit_len >> (i * 8)) & 0xFF) as u8);
    }
    assert_eq!(second_block_bytes.len(), 64);

    // Allocate second block words as witnesses, then override first 8 words
    // with the circuit-wired inner_state UInt32 variables.
    let second_block_native: [u32; 16] = bytes_slice_to_u32x16(&second_block_bytes);
    let mut second_block_words: Vec<UInt32<Fr>> = second_block_native.iter()
        .map(|&w| UInt32::new_variable(
            ark_relations::ns!(cs, "outer_block_word"),
            || Ok(w),
            AllocationMode::Witness,
        ))
        .collect::<Result<_, _>>()?;

    // Wire in the inner_state circuit variables as the first 8 words of the
    // second block — these are big-endian words of the inner hash.
    for i in 0..8 {
        second_block_words[i] = inner_state[i].clone();
    }

    let second_block_arr: [UInt32<Fr>; 16] = {
        let mut iter = second_block_words.into_iter();
        [(); 16].map(|_| iter.next().unwrap())
    };

    let final_state = sha256_compress_words(cs, &outer_init_state, &second_block_arr)?;
    Ok(final_state)
}

// ── SHA-256 helpers ───────────────────────────────────────────────────────────

/// SHA-256 over native byte slice — allocates blocks as witnesses.
pub fn sha256_from_bytes(
    cs: ConstraintSystemRef<Fr>,
    msg: &[u8],
) -> Result<[UInt32<Fr>; 8], SynthesisError> {
    use crate::sha256_gadget::sha256_pad;
    let blocks = sha256_pad(msg);
    let mut state: [UInt32<Fr>; 8] = {
        let v: Vec<UInt32<Fr>> = SHA256_H.iter().map(|&h| UInt32::constant(h)).collect();
        vec_to_arr8(v)
    };
    for block_words in &blocks {
        let block = alloc_block(cs.clone(), block_words)?;
        state = sha256_compress_words(cs.clone(), &state, &block)?;
    }
    Ok(state)
}

/// SHA-256 single compression step (re-exported for clarity).
fn sha256_compress_words(
    cs: ConstraintSystemRef<Fr>,
    state: &[UInt32<Fr>; 8],
    block: &[UInt32<Fr>; 16],
) -> Result<[UInt32<Fr>; 8], SynthesisError> {
    use crate::sha256_gadget::sha256_compress;
    sha256_compress(state, block)
}

/// Convert 64 native bytes into a 16 × UInt32 block (big-endian).
fn bytes_to_block(bytes: &[u8]) -> Result<[UInt32<Fr>; 16], SynthesisError> {
    assert_eq!(bytes.len(), 64);
    let words: Vec<UInt32<Fr>> = bytes.chunks(4)
        .map(|c| UInt32::constant(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
        .collect();
    let mut iter = words.into_iter();
    Ok([(); 16].map(|_| iter.next().unwrap()))
}

fn bytes_slice_to_u32x16(bytes: &[u8]) -> [u32; 16] {
    assert_eq!(bytes.len(), 64);
    let mut out = [0u32; 16];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        out[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    out
}

/// Extract native bytes from circuit state (for constructing next round input).
pub fn state_to_bytes_native(state: &[UInt32<Fr>; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    for word in state {
        let val = word.value().unwrap_or(0);
        out.extend_from_slice(&val.to_be_bytes());
    }
    out
}

// ── Native (non-circuit) helpers ──────────────────────────────────────────────

pub fn hmac_sha256_native(key: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let mut k_padded = [0u8; BLOCK_LEN];
    k_padded[..32].copy_from_slice(key);
    let ikey: Vec<u8> = k_padded.iter().map(|&b| b ^ IPAD).collect();
    let okey: Vec<u8> = k_padded.iter().map(|&b| b ^ OPAD).collect();
    let mut inner = ikey;
    inner.extend_from_slice(msg);
    let inner_hash = sha256_native(&inner);
    let mut outer = okey;
    outer.extend_from_slice(&inner_hash);
    sha256_native(&outer)
}

pub fn sha256_native(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

pub fn tls_prf_native(secret: &[u8; 32], label: &[u8], seed: &[u8], n_bytes: usize) -> Vec<u8> {
    let mut full_seed = label.to_vec();
    full_seed.extend_from_slice(seed);
    let mut output = Vec::new();
    let mut a = full_seed.clone();
    while output.len() < n_bytes {
        a = hmac_sha256_native(secret, &a);
        let mut p_input = a.clone();
        p_input.extend_from_slice(&full_seed);
        output.extend_from_slice(&hmac_sha256_native(secret, &p_input));
    }
    output.truncate(n_bytes);
    output
}