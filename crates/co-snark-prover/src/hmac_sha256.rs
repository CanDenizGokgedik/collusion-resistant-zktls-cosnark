//! HMAC-SHA256 R1CS gadget — generic over field F.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::{uint32::UInt32, ToBitsGadget},
    prelude::{AllocVar, AllocationMode},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::sha256_gadget::{
    sha256_pad, alloc_block, sha256_compress, u32_arr_to_bytes, SHA256_H, vec_to_arr8,
};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;
const BLOCK_LEN: usize = 64;

pub fn hmac_sha256_circuit<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    key: &[u8; 32],
    msg: &[u8],
) -> Result<[UInt32<F>; 8], SynthesisError> {
    let mut k_padded = [0u8; BLOCK_LEN];
    k_padded[..32].copy_from_slice(key);
    let ikey: Vec<u8> = k_padded.iter().map(|&b| b ^ IPAD).collect();
    let okey: Vec<u8> = k_padded.iter().map(|&b| b ^ OPAD).collect();

    let mut inner_input = ikey.clone();
    inner_input.extend_from_slice(msg);
    let inner_state = sha256_from_bytes::<F>(cs.clone(), &inner_input)?;

    let mut outer_init_state: [UInt32<F>; 8] = {
        let v: Vec<UInt32<F>> = SHA256_H.iter().map(|&h| UInt32::constant(h)).collect();
        vec_to_arr8(v)
    };

    let okey_block = bytes_to_block::<F>(&okey[..64])?;
    outer_init_state = sha256_compress(&outer_init_state, &okey_block)?;

    let inner_bytes_native = state_to_bytes_native(&inner_state);
    let mut second_block_bytes = inner_bytes_native.clone();
    second_block_bytes.push(0x80);
    while second_block_bytes.len() < 56 { second_block_bytes.push(0x00); }
    let outer_bit_len: u64 = 96 * 8;
    for i in (0..8).rev() {
        second_block_bytes.push(((outer_bit_len >> (i * 8)) & 0xFF) as u8);
    }
    assert_eq!(second_block_bytes.len(), 64);

    let second_block_native: [u32; 16] = bytes_slice_to_u32x16(&second_block_bytes);
    let mut second_block_words: Vec<UInt32<F>> = second_block_native.iter()
        .map(|&w| UInt32::new_variable(
            ark_relations::ns!(cs, "outer_block_word"),
            || Ok(w),
            AllocationMode::Witness,
        ))
        .collect::<Result<_, _>>()?;

    for i in 0..8 {
        second_block_words[i] = inner_state[i].clone();
    }

    let second_block_arr: [UInt32<F>; 16] = {
        let mut iter = second_block_words.into_iter();
        [(); 16].map(|_| iter.next().unwrap())
    };

    let final_state = sha256_compress(&outer_init_state, &second_block_arr)?;
    Ok(final_state)
}

pub fn sha256_from_bytes<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    msg: &[u8],
) -> Result<[UInt32<F>; 8], SynthesisError> {
    let blocks = sha256_pad(msg);
    let mut state: [UInt32<F>; 8] = {
        let v: Vec<UInt32<F>> = SHA256_H.iter().map(|&h| UInt32::constant(h)).collect();
        vec_to_arr8(v)
    };
    for block_words in &blocks {
        let block = alloc_block::<F>(cs.clone(), block_words)?;
        state = sha256_compress(&state, &block)?;
    }
    Ok(state)
}

fn bytes_to_block<F: PrimeField>(bytes: &[u8]) -> Result<[UInt32<F>; 16], SynthesisError> {
    assert_eq!(bytes.len(), 64);
    let words: Vec<UInt32<F>> = bytes.chunks(4)
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

pub fn state_to_bytes_native<F: PrimeField>(state: &[UInt32<F>; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    for word in state {
        let val = word.value().unwrap_or(0);
        out.extend_from_slice(&val.to_be_bytes());
    }
    out
}

// ── Native helpers (no constraint system) ────────────────────────────────────

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