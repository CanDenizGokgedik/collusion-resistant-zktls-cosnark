//! SHA256 R1CS gadget for TLS-PRF circuit.
//!
//! # Paper reference — §IX
//!
//! > "This 2PC-HMAC evaluates the TLS-PRF of TLS 1.2, which requires
//! >  approximately 60 SHA256 compression operations and results in
//! >  1,719,598 R1CS constraints."
//!
//! Reference [19]: U. Sen, "TLS PRF simulation (gnark)" — written in gnark (Go).
//! This module is the arkworks (Rust/BN254) equivalent.
//!
//! # Constraint estimate
//!
//! Per SHA256 compression block (512-bit message, 256-bit state):
//! - Message schedule (W[16..63]): 48 × (2 sigma + 3 XOR + 1 ADD) ≈ 48 × 200 = 9,600
//! - Compression rounds (64):      64 × (Ch + Maj + 2 Sigma + T1 + T2) ≈ 64 × 430 = 27,520
//! - Final additions (8):          8 × addmany ≈ 320
//! Total per block: ~37,440 constraints
//!
//! TLS-PRF uses ~60 SHA256 compression calls → ~2,246,400 constraints (arkworks BN254).
//! [19] reported 1,719,598 for gnark (BLS12-381) — gnark's SHA256 gadget is more compact.
//!
//! # Operations
//!
//! - ROTR(n, x): 0 constraints (bit rewiring via `UInt32::rotr`)
//! - SHR(n, x):  0 constraints (bit rewiring with constant-false padding)
//! - XOR (32-bit): 32 constraints
//! - AND (32-bit): 32 constraints (1 per Boolean)
//! - addmany (k operands, 32-bit): ~37k constraints

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{boolean::Boolean, uint8::UInt8, uint32::UInt32, ToBitsGadget},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// ── SHA256 initial hash values (H0..H7) ──────────────────────────────────────

pub const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// ── SHA256 round constants (K[0..63]) ────────────────────────────────────────

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

// ── Bit-level helpers ─────────────────────────────────────────────────────────

/// Logical right-shift of a UInt32 by `n` bits (zero-fill from left).
/// No constraints — pure bit rewiring.
pub fn shr32(x: &UInt32<Fr>, n: usize) -> UInt32<Fr> {
    assert!(n < 32);
    let bits = x.to_bits_le();           // bits[0] = LSB
    let zero = Boolean::<Fr>::constant(false);
    let mut new_bits = vec![zero; 32];
    // In LE layout, SHR by n means: new_bits[i] = old_bits[i+n] for i < 32-n
    for i in 0..(32 - n) {
        new_bits[i] = bits[i + n].clone();
    }
    UInt32::from_bits_le(&new_bits)
}

/// AND of two UInt32 values at the bit level.
/// 32 constraints.
pub fn and32(
    a: &UInt32<Fr>,
    b: &UInt32<Fr>,
) -> Result<UInt32<Fr>, SynthesisError> {
    let a_bits = a.to_bits_le();
    let b_bits = b.to_bits_le();
    let result: Vec<Boolean<Fr>> = a_bits
        .iter()
        .zip(b_bits.iter())
        .map(|(ai, bi)| ai.and(bi))
        .collect::<Result<_, _>>()?;
    Ok(UInt32::from_bits_le(&result))
}

/// NOT of a UInt32 (bitwise complement). No constraints.
pub fn not32(x: &UInt32<Fr>) -> UInt32<Fr> {
    let bits = x.to_bits_le();
    let result: Vec<Boolean<Fr>> = bits.iter().map(|b| b.not()).collect();
    UInt32::from_bits_le(&result)
}

// ── SHA256 helper functions ───────────────────────────────────────────────────

/// Ch(e, f, g) = (e AND f) XOR (NOT e AND g)
/// Constraints: 32 (AND ef) + 32 (AND ~e g) + 32 (XOR) = 96
pub fn ch(
    e: &UInt32<Fr>, f: &UInt32<Fr>, g: &UInt32<Fr>,
) -> Result<UInt32<Fr>, SynthesisError> {
    let ef   = and32(e, f)?;
    let ne_g = and32(&not32(e), g)?;
    ef.xor(&ne_g)
}

/// Maj(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)
/// Constraints: 3×32 (AND) + 2×32 (XOR) = 160
pub fn maj(
    a: &UInt32<Fr>, b: &UInt32<Fr>, c: &UInt32<Fr>,
) -> Result<UInt32<Fr>, SynthesisError> {
    let ab = and32(a, b)?;
    let ac = and32(a, c)?;
    let bc = and32(b, c)?;
    ab.xor(&ac)?.xor(&bc)
}

/// Σ0(a) = ROTR(2, a) XOR ROTR(13, a) XOR ROTR(22, a)
/// Constraints: 0 (ROTR) + 2×32 (XOR) = 64
pub fn sigma_upper_0(a: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    a.rotr(2).xor(&a.rotr(13))?.xor(&a.rotr(22))
}

/// Σ1(e) = ROTR(6, e) XOR ROTR(11, e) XOR ROTR(25, e)
/// Constraints: 0 (ROTR) + 2×32 (XOR) = 64
pub fn sigma_upper_1(e: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    e.rotr(6).xor(&e.rotr(11))?.xor(&e.rotr(25))
}

/// σ0(x) = ROTR(7, x) XOR ROTR(18, x) XOR SHR(3, x)  [message schedule]
/// Constraints: 0 (ROTR/SHR) + 2×32 (XOR) = 64
pub fn sigma_lower_0(x: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    x.rotr(7).xor(&x.rotr(18))?.xor(&shr32(x, 3))
}

/// σ1(x) = ROTR(17, x) XOR ROTR(19, x) XOR SHR(10, x)  [message schedule]
/// Constraints: 0 (ROTR/SHR) + 2×32 (XOR) = 64
pub fn sigma_lower_1(x: &UInt32<Fr>) -> Result<UInt32<Fr>, SynthesisError> {
    x.rotr(17).xor(&x.rotr(19))?.xor(&shr32(x, 10))
}

// ── SHA256 compression function ───────────────────────────────────────────────

/// One SHA256 compression: processes a 512-bit block and updates 256-bit state.
///
/// # Inputs
/// - `state`: 8 × UInt32 (the current SHA256 hash values)
/// - `block`: 16 × UInt32 (the 512-bit message block, big-endian words)
///
/// # Returns
/// - Updated `state` after compression.
///
/// # Constraints (estimated)
/// - Message schedule extension (W[16..63]): 48 × ~200 = ~9,600
/// - Compression rounds (64): 64 × ~430 = ~27,520
/// - Final state update (8 ADD): 8 × 37 = ~296
/// - Total: ~37,416 per block
pub fn sha256_compress(
    state: [UInt32<Fr>; 8],
    block: [UInt32<Fr>; 16],
) -> Result<[UInt32<Fr>; 8], SynthesisError> {
    // ── Message schedule W[0..63] ─────────────────────────────────────────────
    let mut w: Vec<UInt32<Fr>> = Vec::with_capacity(64);
    for i in 0..16 {
        w.push(block[i].clone());
    }
    for i in 16..64 {
        // W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
        let s1 = sigma_lower_1(&w[i - 2])?;
        let s0 = sigma_lower_0(&w[i - 15])?;
        let wi = UInt32::addmany(&[s1, w[i - 7].clone(), s0, w[i - 16].clone()])?;
        w.push(wi);
    }

    // ── Working variables ─────────────────────────────────────────────────────
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state.clone();

    // ── 64 rounds ─────────────────────────────────────────────────────────────
    for i in 0..64 {
        let ki = UInt32::constant(SHA256_K[i]);

        // T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
        let s1  = sigma_upper_1(&e)?;
        let ch_ = ch(&e, &f, &g)?;
        let t1  = UInt32::addmany(&[h, s1, ch_, ki, w[i].clone()])?;

        // T2 = Σ0(a) + Maj(a,b,c)
        let s0  = sigma_upper_0(&a)?;
        let maj_ = maj(&a, &b, &c)?;
        let t2  = UInt32::addmany(&[s0, maj_])?;

        h = g;
        g = f;
        f = e;
        e = UInt32::addmany(&[d, t1.clone()])?;
        d = c;
        c = b;
        b = a;
        a = UInt32::addmany(&[t1, t2])?;
    }

    // ── Update state ──────────────────────────────────────────────────────────
    Ok([
        UInt32::addmany(&[state[0].clone(), a])?,
        UInt32::addmany(&[state[1].clone(), b])?,
        UInt32::addmany(&[state[2].clone(), c])?,
        UInt32::addmany(&[state[3].clone(), d])?,
        UInt32::addmany(&[state[4].clone(), e])?,
        UInt32::addmany(&[state[5].clone(), f])?,
        UInt32::addmany(&[state[6].clone(), g])?,
        UInt32::addmany(&[state[7].clone(), h])?,
    ])
}

// ── SHA256 padding helper ─────────────────────────────────────────────────────

/// SHA256 padding: appends 0x80, zeros, and 64-bit big-endian length.
/// Returns padded bytes (always a multiple of 64).
pub fn sha256_pad(msg: &[u8]) -> Vec<u8> {
    let bit_len = msg.len() * 8;
    let mut padded = msg.to_vec();
    padded.push(0x80);
    // Pad to 56 mod 64.
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    // Append 64-bit big-endian length.
    padded.extend_from_slice(&(bit_len as u64).to_be_bytes());
    padded
}

/// Parse a 64-byte block into 16 × big-endian u32 words.
pub fn parse_block_native(block: &[u8; 64]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, w) in words.iter_mut().enumerate() {
        *w = u32::from_be_bytes(block[4*i..4*i+4].try_into().unwrap());
    }
    words
}

// ── SHA256 in R1CS (full message) ────────────────────────────────────────────

/// SHA256 hash of `msg` in R1CS.
///
/// Allocates all inputs as witnesses. Returns 8 UInt32 output words.
///
/// # Constraints: ~37,416 × num_blocks
pub fn sha256_gadget(
    cs: ConstraintSystemRef<Fr>,
    msg: &[u8],
) -> Result<[UInt32<Fr>; 8], SynthesisError> {
    let padded = sha256_pad(msg);
    let num_blocks = padded.len() / 64;

    // Initial state H0..H7.
    let mut state: [UInt32<Fr>; 8] = SHA256_H
        .iter()
        .map(|&h| UInt32::constant(*&h))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    for b in 0..num_blocks {
        let block_bytes: &[u8; 64] = padded[b*64..(b+1)*64].try_into().unwrap();
        let native_words = parse_block_native(block_bytes);

        // Allocate block as witnesses.
        let block_vars: [UInt32<Fr>; 16] = native_words
            .iter()
            .map(|&w| UInt32::new_witness(cs.clone(), || Ok(w)))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();

        state = sha256_compress(state, block_vars)?;
    }

    Ok(state)
}

/// Produce native SHA256 output bytes from UInt32 state.
pub fn state_to_bytes(state: &[UInt32<Fr>; 8]) -> Result<[u8; 32], SynthesisError> {
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        let val = w.value()?;
        out[4*i..4*i+4].copy_from_slice(&val.to_be_bytes());
    }
    Ok(out)
}

/// Convert SHA256 UInt32 output state into 32 constrained `UInt8<Fr>` byte variables.
///
/// SHA256 state words are big-endian: word[i] contributes bytes
/// `[bits 24..31, bits 16..23, bits 8..15, bits 0..7]` in that order.
///
/// The returned UInt8 variables carry the same R1CS constraints as the input
/// UInt32 state — callers can pack these into an FpVar and enforce equality
/// against a public input to bind the hash output inside the circuit.
pub fn state_to_byte_vars(
    state: &[UInt32<Fr>; 8],
) -> Vec<UInt8<Fr>> {
    let mut bytes = Vec::with_capacity(32);
    for word in state.iter() {
        // to_bits_le(): bits[0] = LSB (2^0), bits[31] = MSB (2^31).
        // SHA256 is big-endian: the most-significant byte is output first.
        // Byte 0 (MSB) = bits 24..31, Byte 1 = bits 16..23, etc.
        let bits = word.to_bits_le();
        for byte_idx in [3usize, 2, 1, 0] {
            // Extract bits[byte_idx*8 .. byte_idx*8+8] in LE order for UInt8.
            let byte_bits: Vec<Boolean<Fr>> = (0..8)
                .map(|bit| bits[byte_idx * 8 + bit].clone())
                .collect();
            bytes.push(UInt8::from_bits_le(&byte_bits));
        }
    }
    bytes
}

/// SHA256 of constrained byte inputs, returning a constrained byte output.
///
/// Takes `input_vars` (constrained UInt8 variables) and computes SHA256 by:
/// 1. Extracting the native byte values for padding computation.
/// 2. Applying standard SHA256 padding (same as `sha256_pad`).
/// 3. Building constrained UInt32 block words from the padded byte vars.
/// 4. Running `sha256_compress` on the constrained words.
/// 5. Returning constrained byte output via `state_to_byte_vars`.
///
/// The SHA256 output is fully constrained — a cheating prover cannot supply
/// a different pre-image without falsifying the compression constraints.
///
/// # Constraint cost
/// Same as `sha256_gadget`: ~37,416 constraints per 512-bit (64-byte) block.
pub fn sha256_from_byte_vars(
    cs: ConstraintSystemRef<Fr>,
    input_vars: &[UInt8<Fr>],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    // Extract native values for padding — safe since this only affects the
    // deterministic padding bytes, not the secret witness content.
    let native_bytes: Vec<u8> = input_vars
        .iter()
        .map(|b| b.value().unwrap_or(0))
        .collect();
    let padded = sha256_pad(&native_bytes);
    let num_blocks = padded.len() / 64;

    // Build a padded var array: real bytes as constrained vars, padding as constants.
    let n_real = input_vars.len();
    let mut padded_vars: Vec<UInt8<Fr>> = input_vars.to_vec();
    for i in n_real..padded.len() {
        padded_vars.push(UInt8::constant(padded[i]));
    }

    // Initial SHA256 state.
    let mut state: [UInt32<Fr>; 8] = SHA256_H
        .iter()
        .map(|&h| UInt32::constant(h))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    for b in 0..num_blocks {
        let block_byte_vars = &padded_vars[b * 64..(b + 1) * 64];

        // Reconstruct constrained UInt32 words from big-endian byte variables.
        // Word i = (byte[4i] << 24) | (byte[4i+1] << 16) | (byte[4i+2] << 8) | byte[4i+3]
        // In LE bit layout: byte[4i+3] occupies bits 0..7 (LSB), byte[4i] bits 24..31 (MSB).
        let block_vars: [UInt32<Fr>; 16] = (0..16)
            .map(|w| {
                // Gather 32 bits in LE order: LSB byte last, MSB byte first.
                let b0 = block_byte_vars[4 * w].to_bits_le()?;     // MSB byte
                let b1 = block_byte_vars[4 * w + 1].to_bits_le()?;
                let b2 = block_byte_vars[4 * w + 2].to_bits_le()?;
                let b3 = block_byte_vars[4 * w + 3].to_bits_le()?; // LSB byte

                // LE layout: [b3 bits 0..7, b2 bits 8..15, b1 bits 16..23, b0 bits 24..31]
                let mut bits_le = Vec::with_capacity(32);
                bits_le.extend_from_slice(&b3);
                bits_le.extend_from_slice(&b2);
                bits_le.extend_from_slice(&b1);
                bits_le.extend_from_slice(&b0);

                Ok(UInt32::from_bits_le(&bits_le))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?
            .try_into()
            .unwrap();

        state = sha256_compress(state, block_vars)?;
    }

    Ok(state_to_byte_vars(&state))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use sha2::Digest;

    #[test]
    fn sha256_compress_empty_block() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        // Use SHA256 of empty message — one 512-bit padded block.
        let state = SHA256_H.iter().map(|&h| UInt32::constant(h)).collect::<Vec<_>>()
            .try_into().unwrap();
        // Known padded block for empty message.
        let padded = sha256_pad(b"");
        let native = parse_block_native(padded[0..64].try_into().unwrap());
        let block: [UInt32<Fr>; 16] = native.iter()
            .map(|&w| UInt32::constant(w))
            .collect::<Vec<_>>().try_into().unwrap();
        let new_state = sha256_compress(state, block).unwrap();
        let got = state_to_bytes(&new_state).unwrap();
        // Expected: SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected: [u8; 32] = sha2::Sha256::digest(b"").into();
        assert_eq!(got, expected, "SHA256 gadget output must match sha2 crate");
    }

    #[test]
    fn sha256_gadget_known_vector() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let msg = b"abc";
        let out = sha256_gadget(cs.clone(), msg).unwrap();
        let got = state_to_bytes(&out).unwrap();
        let expected: [u8; 32] = sha2::Sha256::digest(msg).into();
        assert_eq!(got, expected, "SHA256 gadget must match sha2::Sha256 for 'abc'");
        println!("SHA256('abc') constraints: {}", cs.num_constraints());
    }

    #[test]
    fn sha256_gadget_55_byte_msg() {
        // 55 bytes: fits in one block with padding.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let msg = [0xAAu8; 55];
        let out = sha256_gadget(cs.clone(), &msg).unwrap();
        let got = state_to_bytes(&out).unwrap();
        let expected: [u8; 32] = sha2::Sha256::digest(&msg[..]).into();
        assert_eq!(got, expected);
        println!("SHA256(55×0xAA) constraints: {}", cs.num_constraints());
    }

    #[test]
    fn ch_maj_correct() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let e = UInt32::constant(0x9b05688c_u32);
        let f = UInt32::constant(0x1f83d9ab_u32);
        let g = UInt32::constant(0x5be0cd19_u32);
        let ch_out = ch(&e, &f, &g).unwrap();
        let expected = (0x9b05688c_u32 & 0x1f83d9ab_u32) ^ (!0x9b05688c_u32 & 0x5be0cd19_u32);
        assert_eq!(ch_out.value().unwrap(), expected);
    }

    #[test]
    fn sigma_functions_correct() {
        let x = UInt32::constant(0xABCD1234_u32);
        let s0 = sigma_lower_0(&x).unwrap();
        let s1 = sigma_lower_1(&x).unwrap();
        let s0_expected = x.value().unwrap().rotate_right(7)
            ^ x.value().unwrap().rotate_right(18)
            ^ (x.value().unwrap() >> 3);
        let s1_expected = x.value().unwrap().rotate_right(17)
            ^ x.value().unwrap().rotate_right(19)
            ^ (x.value().unwrap() >> 10);
        assert_eq!(s0.value().unwrap(), s0_expected);
        assert_eq!(s1.value().unwrap(), s1_expected);
    }
}