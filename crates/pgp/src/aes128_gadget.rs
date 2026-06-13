//! AES-128 R1CS gadget (encryption only), structured like gnark's `std/aes`:
//! full SubBytes / ShiftRows / MixColumns / AddRoundKey rounds plus the AES-128
//! key schedule, then CBC chaining over a fixed number of blocks.
//!
//! # What this is for
//!
//! Completes the **mac-then-encrypt** PGP statement for TLS 1.2 CBC cipher
//! suites (`TLS_RSA_WITH_AES_128_CBC_SHA256`): the prover demonstrates, in
//! zero knowledge, that
//!
//! ```text
//!   ciphertext = AES-128-CBC_Enc( key = K_ENC, iv = IV,
//!                                 plaintext ‖ MAC ‖ pad )
//! ```
//!
//! i.e. that the committed ciphertext is the genuine encryption of the
//! plaintext concatenated with the HMAC tag (mac-then-encrypt) under the TLS
//! record key. Combined with the existing HMAC constraint in
//! `tls_session_binding`, the full record-protection step is now in-circuit.
//!
//! # Design (matches gnark `std/aes` shape)
//!
//! - **State**: 16 `UInt8<Fr>` (AES operates on a 4×4 column-major byte matrix).
//! - **SubBytes**: each byte goes through the AES S-box implemented as a
//!   256-entry constrained lookup driven by the byte's 8 bits (one
//!   `conditionally_select` reduction), exactly the byte-oriented S-box gnark
//!   uses rather than a polynomial inverse over GF(2^8).
//! - **ShiftRows**: a fixed byte permutation (free — just rewiring).
//! - **MixColumns**: GF(2^8) multiply-by-2 (`xtime`) and multiply-by-3,
//!   combined with XORs.
//! - **AddRoundKey**: byte-wise XOR with the round key.
//! - **Key schedule**: 10-round AES-128 expansion (RotWord, SubWord, Rcon).
//! - **CBC**: `C_i = AES_Enc(P_i XOR C_{i-1})`, `C_0` chained from the IV.
//!
//! # Constraint cost (BN254)
//!
//! The S-box lookup dominates. Per byte: 8 bit-decomposition booleans + a
//! 255-step `conditionally_select` fold ≈ a few hundred constraints. One AES
//! block = 16 SubBytes × 10 rounds = 160 S-box evaluations. Three CBC blocks
//! ≈ 480 S-box evaluations. This is heavier than a SHA256 block but fixed and
//! small for the 3-block TLS record sizes used here.

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{boolean::Boolean, uint8::UInt8, ToBitsGadget},
    eq::EqGadget,
    select::CondSelectGadget,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// AES-128 forward S-box (FIPS-197, Figure 7).
#[rustfmt::skip]
pub const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

/// AES round constants (Rcon), first byte only (rest are zero).
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// ── Native AES-128 (used by callers to compute the expected ciphertext) ───────

fn xtime(x: u8) -> u8 {
    let hi = x & 0x80;
    let mut r = x << 1;
    if hi != 0 {
        r ^= 0x1b;
    }
    r
}

fn gmul(a: u8, b: u8) -> u8 {
    // GF(2^8) multiply (used only for native reference; circuit uses xtime).
    let (mut a, mut b, mut p) = (a, b, 0u8);
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Native AES-128 key expansion → 11 round keys (176 bytes).
pub fn aes128_key_expansion(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            // RotWord
            temp = [temp[1], temp[2], temp[3], temp[0]];
            // SubWord
            for t in temp.iter_mut() {
                *t = SBOX[*t as usize];
            }
            // Rcon
            temp[0] ^= RCON[i / 4 - 1];
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ temp[j];
        }
    }
    let mut round_keys = [[0u8; 16]; 11];
    for r in 0..11 {
        for c in 0..4 {
            for j in 0..4 {
                round_keys[r][4 * c + j] = w[4 * r + c][j];
            }
        }
    }
    round_keys
}

fn aes128_encrypt_block(block: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = *block;
    // Initial AddRoundKey
    for i in 0..16 {
        state[i] ^= round_keys[0][i];
    }
    for round in 1..10 {
        // SubBytes
        for s in state.iter_mut() {
            *s = SBOX[*s as usize];
        }
        // ShiftRows
        state = shift_rows_native(&state);
        // MixColumns
        state = mix_columns_native(&state);
        // AddRoundKey
        for i in 0..16 {
            state[i] ^= round_keys[round][i];
        }
    }
    // Final round (no MixColumns)
    for s in state.iter_mut() {
        *s = SBOX[*s as usize];
    }
    state = shift_rows_native(&state);
    for i in 0..16 {
        state[i] ^= round_keys[10][i];
    }
    state
}

fn shift_rows_native(s: &[u8; 16]) -> [u8; 16] {
    // Column-major: byte index = 4*col + row.
    let mut o = [0u8; 16];
    for row in 0..4 {
        for col in 0..4 {
            let src_col = (col + row) % 4;
            o[4 * col + row] = s[4 * src_col + row];
        }
    }
    o
}

fn mix_columns_native(s: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for c in 0..4 {
        let i = 4 * c;
        let a0 = s[i];
        let a1 = s[i + 1];
        let a2 = s[i + 2];
        let a3 = s[i + 3];
        o[i] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        o[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        o[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        o[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
    o
}

/// Native AES-128-CBC encryption (PKCS#7-free; caller supplies padded input).
/// Used to compute the expected ciphertext witness.
pub fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    assert!(plaintext.len() % 16 == 0, "plaintext must be block-aligned");
    let rks = aes128_key_expansion(key);
    let mut prev = *iv;
    let mut out = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks(16) {
        let mut blk = [0u8; 16];
        for i in 0..16 {
            blk[i] = chunk[i] ^ prev[i];
        }
        let ct = aes128_encrypt_block(&blk, &rks);
        out.extend_from_slice(&ct);
        prev = ct;
    }
    out
}

// ── In-circuit AES-128 ────────────────────────────────────────────────────────

/// XOR two byte vars.
fn xor8(a: &UInt8<Fr>, b: &UInt8<Fr>) -> Result<UInt8<Fr>, SynthesisError> {
    a.xor(b)
}

/// In-circuit S-box: select SBOX[x] using x's 8 bits as the index.
///
/// Builds the constant table once, then folds it with `conditionally_select`
/// down to one byte using each bit of `x`. 255 selects per byte — the same
/// byte-oriented S-box gnark uses.
fn sbox_gadget(
    cs: ConstraintSystemRef<Fr>,
    x: &UInt8<Fr>,
) -> Result<UInt8<Fr>, SynthesisError> {
    // Constant table of 256 byte-vars.
    let table: Vec<UInt8<Fr>> = SBOX
        .iter()
        .map(|&b| UInt8::constant(b))
        .collect();

    let bits = x.to_bits_le()?; // 8 booleans, LSB first

    // Fold: at level k, halve the table by selecting on bit k.
    let mut layer = table;
    for bit in bits.iter() {
        let mut next = Vec::with_capacity(layer.len() / 2);
        let mut i = 0;
        while i < layer.len() {
            let lo = &layer[i];
            let hi = &layer[i + 1];
            // bit == 0 → lo, bit == 1 → hi
            next.push(UInt8::conditionally_select(bit, hi, lo)?);
            i += 2;
        }
        layer = next;
    }
    debug_assert_eq!(layer.len(), 1);
    // Tie to cs so the table is materialized in this constraint system.
    let _ = cs;
    Ok(layer.into_iter().next().unwrap())
}

/// In-circuit xtime (multiply by 2 in GF(2^8)).
/// xtime(x) = (x << 1) XOR (0x1b if msb(x) else 0).
fn xtime_gadget(x: &UInt8<Fr>) -> Result<UInt8<Fr>, SynthesisError> {
    let bits = x.to_bits_le()?; // b0..b7, LSB first
    let msb = bits[7].clone();
    // shifted = x << 1  → new bits: [0, b0, b1, ..., b6]
    let mut shifted_bits = Vec::with_capacity(8);
    shifted_bits.push(Boolean::constant(false));
    for i in 0..7 {
        shifted_bits.push(bits[i].clone());
    }
    let shifted = UInt8::from_bits_le(&shifted_bits);
    // reduction polynomial 0x1b, applied iff msb == 1
    let zero = UInt8::constant(0u8);
    let poly = UInt8::constant(0x1b);
    let red = UInt8::conditionally_select(&msb, &poly, &zero)?;
    xor8(&shifted, &red)
}

/// MixColumns on one 4-byte column (in place semantics, returns new column).
fn mix_one_column(col: &[UInt8<Fr>; 4]) -> Result<[UInt8<Fr>; 4], SynthesisError> {
    // o0 = 2·a0 ^ 3·a1 ^ a2 ^ a3, with 3·a = (2·a) ^ a
    let m0 = xtime_gadget(&col[0])?;
    let m1 = xtime_gadget(&col[1])?;
    let m2 = xtime_gadget(&col[2])?;
    let m3 = xtime_gadget(&col[3])?;

    let three0 = xor8(&m0, &col[0])?;
    let three1 = xor8(&m1, &col[1])?;
    let three2 = xor8(&m2, &col[2])?;
    let three3 = xor8(&m3, &col[3])?;

    // o0 = 2a0 ^ 3a1 ^ a2 ^ a3
    let o0 = xor8(&xor8(&m0, &three1)?, &xor8(&col[2], &col[3])?)?;
    // o1 = a0 ^ 2a1 ^ 3a2 ^ a3
    let o1 = xor8(&xor8(&col[0], &m1)?, &xor8(&three2, &col[3])?)?;
    // o2 = a0 ^ a1 ^ 2a2 ^ 3a3
    let o2 = xor8(&xor8(&col[0], &col[1])?, &xor8(&m2, &three3)?)?;
    // o3 = 3a0 ^ a1 ^ a2 ^ 2a3
    let o3 = xor8(&xor8(&three0, &col[1])?, &xor8(&col[2], &m3)?)?;

    Ok([o0, o1, o2, o3])
}

/// In-circuit ShiftRows (pure rewiring, no constraints).
fn shift_rows_gadget(state: &[UInt8<Fr>; 16]) -> [UInt8<Fr>; 16] {
    let mut o: Vec<UInt8<Fr>> = vec![UInt8::constant(0); 16];
    for row in 0..4 {
        for col in 0..4 {
            let src_col = (col + row) % 4;
            o[4 * col + row] = state[4 * src_col + row].clone();
        }
    }
    o.try_into().unwrap()
}

/// One in-circuit AES-128 block encryption against pre-expanded round-key vars.
fn aes_encrypt_block_gadget(
    cs: ConstraintSystemRef<Fr>,
    block: &[UInt8<Fr>; 16],
    round_keys: &[[UInt8<Fr>; 16]; 11],
) -> Result<[UInt8<Fr>; 16], SynthesisError> {
    // Initial AddRoundKey
    let mut state: Vec<UInt8<Fr>> = (0..16)
        .map(|i| xor8(&block[i], &round_keys[0][i]))
        .collect::<Result<_, _>>()?;

    for round in 1..10 {
        // SubBytes
        let subbed: Vec<UInt8<Fr>> = state
            .iter()
            .map(|b| sbox_gadget(cs.clone(), b))
            .collect::<Result<_, _>>()?;
        let s_arr: [UInt8<Fr>; 16] = subbed.try_into().unwrap();
        // ShiftRows
        let shifted = shift_rows_gadget(&s_arr);
        // MixColumns (per column)
        let mut mixed: Vec<UInt8<Fr>> = Vec::with_capacity(16);
        for c in 0..4 {
            let col = [
                shifted[4 * c].clone(),
                shifted[4 * c + 1].clone(),
                shifted[4 * c + 2].clone(),
                shifted[4 * c + 3].clone(),
            ];
            let m = mix_one_column(&col)?;
            mixed.extend(m);
        }
        // AddRoundKey
        state = (0..16)
            .map(|i| xor8(&mixed[i], &round_keys[round][i]))
            .collect::<Result<_, _>>()?;
    }

    // Final round (no MixColumns)
    let subbed: Vec<UInt8<Fr>> = state
        .iter()
        .map(|b| sbox_gadget(cs.clone(), b))
        .collect::<Result<_, _>>()?;
    let s_arr: [UInt8<Fr>; 16] = subbed.try_into().unwrap();
    let shifted = shift_rows_gadget(&s_arr);
    let final_state: Vec<UInt8<Fr>> = (0..16)
        .map(|i| xor8(&shifted[i], &round_keys[10][i]))
        .collect::<Result<_, _>>()?;

    Ok(final_state.try_into().unwrap())
}

/// In-circuit AES-128 key expansion from a 16-byte key var.
fn key_expansion_gadget(
    key: &[UInt8<Fr>; 16],
) -> Result<[[UInt8<Fr>; 16]; 11], SynthesisError> {
    // Work on 44 4-byte words.
    let mut w: Vec<[UInt8<Fr>; 4]> = Vec::with_capacity(44);
    for i in 0..4 {
        w.push([
            key[4 * i].clone(),
            key[4 * i + 1].clone(),
            key[4 * i + 2].clone(),
            key[4 * i + 3].clone(),
        ]);
    }
    let cs = key[0].cs();
    for i in 4..44 {
        let prev = w[i - 1].clone();
        let mut temp = prev;
        if i % 4 == 0 {
            // RotWord
            temp = [temp[1].clone(), temp[2].clone(), temp[3].clone(), temp[0].clone()];
            // SubWord
            for t in temp.iter_mut() {
                *t = sbox_gadget(cs.clone(), t)?;
            }
            // Rcon XOR on first byte
            let rcon = UInt8::constant(RCON[i / 4 - 1]);
            temp[0] = xor8(&temp[0], &rcon)?;
        }
        let wi4 = w[i - 4].clone();
        let new_word = [
            xor8(&wi4[0], &temp[0])?,
            xor8(&wi4[1], &temp[1])?,
            xor8(&wi4[2], &temp[2])?,
            xor8(&wi4[3], &temp[3])?,
        ];
        w.push(new_word);
    }
    // Reassemble into 11 round keys (column-major bytes).
    let mut round_keys: Vec<[UInt8<Fr>; 16]> = Vec::with_capacity(11);
    for r in 0..11 {
        let mut rk: Vec<UInt8<Fr>> = Vec::with_capacity(16);
        for c in 0..4 {
            for j in 0..4 {
                rk.push(w[4 * r + c][j].clone());
            }
        }
        round_keys.push(rk.try_into().unwrap());
    }
    Ok(round_keys.try_into().unwrap())
}

/// In-circuit AES-128-CBC encryption over `num_blocks` blocks.
///
/// Enforces `ciphertext == AES-128-CBC(key, iv, plaintext)` by recomputing the
/// cipher in-circuit and equating against the provided ciphertext bytes.
///
/// All inputs are byte vars already allocated in `cs`. `plaintext` and
/// `ciphertext` lengths must equal `16 * num_blocks`.
pub fn aes128_cbc_encrypt_constrained(
    cs: ConstraintSystemRef<Fr>,
    key: &[UInt8<Fr>; 16],
    iv: &[UInt8<Fr>; 16],
    plaintext: &[UInt8<Fr>],
    ciphertext: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    assert_eq!(plaintext.len() % 16, 0, "plaintext must be block-aligned");
    assert_eq!(plaintext.len(), ciphertext.len(), "pt/ct length mismatch");

    let round_keys = key_expansion_gadget(key)?;

    let mut prev: [UInt8<Fr>; 16] = iv.clone();
    let num_blocks = plaintext.len() / 16;
    for b in 0..num_blocks {
        // P_i XOR prev
        let mut xored: Vec<UInt8<Fr>> = Vec::with_capacity(16);
        for i in 0..16 {
            xored.push(xor8(&plaintext[16 * b + i], &prev[i])?);
        }
        let blk: [UInt8<Fr>; 16] = xored.try_into().unwrap();
        let ct = aes_encrypt_block_gadget(cs.clone(), &blk, &round_keys)?;
        // Enforce ct == ciphertext[b]
        for i in 0..16 {
            ct[i].enforce_equal(&ciphertext[16 * b + i])?;
        }
        prev = ct;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn fips197_appendix_b_vector() {
        // FIPS-197 Appendix B single-block test vector.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let pt = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];
        let expected = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ];
        let rks = aes128_key_expansion(&key);
        let ct = aes128_encrypt_block(&pt, &rks);
        assert_eq!(ct, expected, "native AES block must match FIPS-197");
    }

    #[test]
    fn native_cbc_matches_aes_crate_shape() {
        // CBC of 3 blocks with a known key/iv reduces to per-block ECB of the
        // XORed input; we just check determinism + block alignment here.
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let pt = [0xABu8; 48];
        let ct = aes128_cbc_encrypt(&key, &iv, &pt);
        assert_eq!(ct.len(), 48);
        // Re-encrypting the same input is deterministic.
        let ct2 = aes128_cbc_encrypt(&key, &iv, &pt);
        assert_eq!(ct, ct2);
    }

    #[test]
    fn circuit_matches_native_single_block() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let key = [0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                   0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0u8; 16];
        let pt = [0x32u8, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                  0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        // CBC with zero IV over one block = ECB of pt.
        let ct = aes128_cbc_encrypt(&key, &iv, &pt);

        let key_vars: [UInt8<Fr>; 16] =
            key.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
               .collect::<Vec<_>>().try_into().unwrap();
        let iv_vars: [UInt8<Fr>; 16] =
            iv.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
               .collect::<Vec<_>>().try_into().unwrap();
        let pt_vars: Vec<UInt8<Fr>> =
            pt.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap()).collect();
        let ct_vars: Vec<UInt8<Fr>> =
            ct.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap()).collect();

        aes128_cbc_encrypt_constrained(cs.clone(), &key_vars, &iv_vars, &pt_vars, &ct_vars)
            .unwrap();
        assert!(cs.is_satisfied().unwrap(), "circuit must be satisfied by correct ct");
    }

    #[test]
    fn circuit_rejects_wrong_ciphertext() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let pt = [0xABu8; 48]; // 3 blocks
        let mut ct = aes128_cbc_encrypt(&key, &iv, &pt);
        ct[0] ^= 1; // corrupt one byte

        let key_vars: [UInt8<Fr>; 16] =
            key.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
               .collect::<Vec<_>>().try_into().unwrap();
        let iv_vars: [UInt8<Fr>; 16] =
            iv.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
               .collect::<Vec<_>>().try_into().unwrap();
        let pt_vars: Vec<UInt8<Fr>> =
            pt.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap()).collect();
        let ct_vars: Vec<UInt8<Fr>> =
            ct.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap()).collect();

        aes128_cbc_encrypt_constrained(cs.clone(), &key_vars, &iv_vars, &pt_vars, &ct_vars)
            .unwrap();
        assert!(!cs.is_satisfied().unwrap(), "corrupted ciphertext must fail");
    }

    #[test]
    fn circuit_three_blocks_satisfiable() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let key = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let iv = [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let pt: Vec<u8> = (0..48u8).collect();
        let ct = aes128_cbc_encrypt(&key, &iv, &pt);

        let key_vars: [UInt8<Fr>; 16] =
            key.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
               .collect::<Vec<_>>().try_into().unwrap();
        let iv_vars: [UInt8<Fr>; 16] =
            iv.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
               .collect::<Vec<_>>().try_into().unwrap();
        let pt_vars: Vec<UInt8<Fr>> =
            pt.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap()).collect();
        let ct_vars: Vec<UInt8<Fr>> =
            ct.iter().map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap()).collect();

        aes128_cbc_encrypt_constrained(cs.clone(), &key_vars, &iv_vars, &pt_vars, &ct_vars)
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("3-block AES-CBC constraints: {}", cs.num_constraints());
    }
}
