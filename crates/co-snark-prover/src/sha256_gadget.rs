//! SHA-256 R1CS gadget for ark 0.2 + BLS12-377.
//!
//! # Key API differences from ark 0.4
//!
//! - `to_bits_le()` returns `Vec<Boolean<F>>` directly (no Result)
//! - Namespace: `ark_relations::ns!(cs, "name")` not `r1cs::ns!`
//! - No `try_into()` for Vec→array — use manual conversion helper

use ark_bls12_377::Fr;
use ark_r1cs_std::{
    bits::{boolean::Boolean, uint8::UInt8, uint32::UInt32, ToBitsGadget},
    prelude::{AllocVar, AllocationMode},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// ── SHA-256 constants ─────────────────────────────────────────────────────────

pub const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// ── Vec → array helper ────────────────────────────────────────────────────────

fn vec_to_arr16(v: Vec<UInt32<Fr>>) -> [UInt32<Fr>; 16] {
    assert_eq!(v.len(), 16);
    let mut iter = v.into_iter();
    [(); 16].map(|_| iter.next().unwrap())
}

fn vec_to_arr8(v: Vec<UInt32<Fr>>) -> [UInt32<Fr>; 8] {
    assert_eq!(v.len(), 8);
    let mut iter = v.into_iter();
    [(); 8].map(|_| iter.next().unwrap())
}

// ── Bit-level helpers ─────────────────────────────────────────────────────────

/// Logical right-shift of a UInt32 by `n` bits (zero-fill). No constraints.
/// NOTE: `to_bits_le()` returns `Vec` directly in ark 0.2 (not Result).
pub fn shr32(x: &UInt32<Fr>, n: usize) -> UInt32<Fr> {
    assert!(n < 32);
    let bits = x.to_bits_le();  // no ? in ark 0.2
    let zero = Boolean::<Fr>::constant(false);
    let mut new_bits = vec![zero; 32];
    for i in 0..(32 - n) {
        new_bits[i] = bits[i + n].clone();
    }
    UInt32::from_bits_le(&new_bits)
}

/// Bitwise AND of two UInt32 values. 32 constraints.
pub fn and32(a: &UInt32<Fr>, b: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    let a_bits: Vec<Boolean<Fr>> = a.to_bits_le();
    let b_bits: Vec<Boolean<Fr>> = b.to_bits_le();
    let result: Vec<Boolean<Fr>> = a_bits.iter().zip(b_bits.iter())
        .map(|(ai, bi)| ai.and(bi))
        .collect::<Result<_, _>>()?;
    Ok(UInt32::from_bits_le(&result))
}

/// Bitwise NOT of a UInt32. No constraints.
pub fn not32(x: &UInt32<Fr>) -> UInt32<Fr> {
    let bits: Vec<Boolean<Fr>> = x.to_bits_le();
    let result: Vec<Boolean<Fr>> = bits.iter().map(|b| b.not()).collect();
    UInt32::from_bits_le(&result)
}

/// SHA-256 Ch function: (a AND b) XOR (NOT a AND c). 96 constraints.
pub fn ch32(a: &UInt32<Fr>, b: &UInt32<Fr>, c: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    let a_bits: Vec<Boolean<Fr>> = a.to_bits_le();
    let b_bits: Vec<Boolean<Fr>> = b.to_bits_le();
    let c_bits: Vec<Boolean<Fr>> = c.to_bits_le();
    let result: Vec<Boolean<Fr>> = (0..32)
        .map(|i| {
            let ab  = a_bits[i].and(&b_bits[i])?;
            let nac = a_bits[i].not().and(&c_bits[i])?;
            ab.xor(&nac)
        })
        .collect::<Result<_, _>>()?;
    Ok(UInt32::from_bits_le(&result))
}

/// SHA-256 Maj function: (a AND b) XOR (a AND c) XOR (b AND c). 128 constraints.
pub fn maj32(a: &UInt32<Fr>, b: &UInt32<Fr>, c: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    let a_bits: Vec<Boolean<Fr>> = a.to_bits_le();
    let b_bits: Vec<Boolean<Fr>> = b.to_bits_le();
    let c_bits: Vec<Boolean<Fr>> = c.to_bits_le();
    let result: Vec<Boolean<Fr>> = (0..32)
        .map(|i| {
            let ab = a_bits[i].and(&b_bits[i])?;
            let ac = a_bits[i].and(&c_bits[i])?;
            let bc = b_bits[i].and(&c_bits[i])?;
            ab.xor(&ac)?.xor(&bc)
        })
        .collect::<Result<_, _>>()?;
    Ok(UInt32::from_bits_le(&result))
}

/// Σ0(a) = ROTR(2,a) XOR ROTR(13,a) XOR ROTR(22,a). 64 constraints.
pub fn sigma0_big(a: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    a.rotr(2).xor(&a.rotr(13))?.xor(&a.rotr(22))
}

/// Σ1(e) = ROTR(6,e) XOR ROTR(11,e) XOR ROTR(25,e). 64 constraints.
pub fn sigma1_big(e: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    e.rotr(6).xor(&e.rotr(11))?.xor(&e.rotr(25))
}

/// σ0(x) = ROTR(7,x) XOR ROTR(18,x) XOR SHR(3,x). ~96 constraints.
pub fn sigma0_small(x: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    x.rotr(7).xor(&x.rotr(18))?.xor(&shr32(x, 3))
}

/// σ1(x) = ROTR(17,x) XOR ROTR(19,x) XOR SHR(10,x). ~96 constraints.
pub fn sigma1_small(x: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    x.rotr(17).xor(&x.rotr(19))?.xor(&shr32(x, 10))
}

// ── SHA-256 compression ───────────────────────────────────────────────────────

/// One SHA-256 compression block. ~37,440 constraints.
pub fn sha256_compress(
    state: &[UInt32<Fr>; 8],
    block: &[UInt32<Fr>; 16],
) -> Result<[UInt32<Fr>; 8], SynthesisError> {
    // Message schedule W[0..64]
    let mut w: Vec<UInt32<Fr>> = block.iter().cloned().collect();
    for i in 16..64 {
        let s1 = sigma1_small(&w[i - 2])?;
        let s0 = sigma0_small(&w[i - 15])?;
        let wi = UInt32::addmany(&[s1, w[i - 7].clone(), s0, w[i - 16].clone()])?;
        w.push(wi);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0].clone(), state[1].clone(), state[2].clone(), state[3].clone(),
        state[4].clone(), state[5].clone(), state[6].clone(), state[7].clone(),
    );

    for i in 0..64 {
        let s1  = sigma1_big(&e)?;
        let ch  = ch32(&e, &f, &g)?;
        let k_i = UInt32::constant(SHA256_K[i]);
        let t1  = UInt32::addmany(&[h.clone(), s1, ch, k_i, w[i].clone()])?;

        let s0  = sigma0_big(&a)?;
        let maj = maj32(&a, &b, &c)?;
        let t2  = UInt32::addmany(&[s0, maj])?;

        h = g;
        g = f;
        f = e;
        e = UInt32::addmany(&[d.clone(), t1.clone()])?;
        d = c;
        c = b;
        b = a;
        a = UInt32::addmany(&[t1, t2])?;
    }

    Ok([
        UInt32::addmany(&[a, state[0].clone()])?,
        UInt32::addmany(&[b, state[1].clone()])?,
        UInt32::addmany(&[c, state[2].clone()])?,
        UInt32::addmany(&[d, state[3].clone()])?,
        UInt32::addmany(&[e, state[4].clone()])?,
        UInt32::addmany(&[f, state[5].clone()])?,
        UInt32::addmany(&[g, state[6].clone()])?,
        UInt32::addmany(&[h, state[7].clone()])?,
    ])
}

// ── Padding + full hash ───────────────────────────────────────────────────────

/// SHA-256 padding: returns 512-bit blocks as 16 × u32 (big-endian).
pub fn sha256_pad(msg: &[u8]) -> Vec<[u32; 16]> {
    let mut padded = msg.to_vec();
    let bit_len = msg.len() * 8;
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    for i in (0..8).rev() {
        padded.push(((bit_len >> (i * 8)) & 0xFF) as u8);
    }
    padded.chunks(64).map(|chunk| {
        let mut block = [0u32; 16];
        for (i, w) in chunk.chunks(4).enumerate() {
            block[i] = u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
        }
        block
    }).collect()
}

/// Allocate a 512-bit block as 16 × UInt32 witnesses.
pub fn alloc_block(
    cs: ConstraintSystemRef<Fr>,
    block: &[u32; 16],
) -> Result<[UInt32<Fr>; 16], SynthesisError> {
    let words: Vec<UInt32<Fr>> = block.iter()
        .map(|&w| UInt32::new_variable(
            ark_relations::ns!(cs, "block_word"),
            || Ok(w),
            AllocationMode::Witness,
        ))
        .collect::<Result<_, _>>()?;
    Ok(vec_to_arr16(words))
}

/// Full SHA-256 of `msg` in-circuit. Returns 8 × UInt32 state.
pub fn sha256_circuit(
    cs: ConstraintSystemRef<Fr>,
    msg: &[u8],
) -> Result<[UInt32<Fr>; 8], SynthesisError> {
    let blocks = sha256_pad(msg);
    let mut state: [UInt32<Fr>; 8] = {
        let v: Vec<UInt32<Fr>> = SHA256_H.iter().map(|&h| UInt32::constant(h)).collect();
        vec_to_arr8(v)
    };
    for block_words in &blocks {
        let block = alloc_block(cs.clone(), block_words)?;
        state = sha256_compress(&state, &block)?;
    }
    Ok(state)
}

/// Extract native u32 values from circuit state (for chaining inner → outer).
pub fn state_to_u32_native(state: &[UInt32<Fr>; 8]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, word) in state.iter().enumerate() {
        out[i] = word.value().unwrap_or(0);
    }
    out
}

/// Serialize 8 × u32 to 32 bytes big-endian.
pub fn u32_arr_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, &w) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}