//! Test vector generator for FrostVerifier.t.sol.
//!
//! Generates a secp256k1 Schnorr signature using the EXACT challenge hash
//! formula used by FrostVerifier.sol:
//!
//!   e = keccak256(R_x || pk_x || msg) mod N
//!   s = k + e * sk  (mod N)
//!
//! Run with:
//!   cargo run --bin gen-test-vectors --features frost,tcp,secp256k1 --release

use k256::{
    elliptic_curve::{
        point::AffineCoordinates,
        sec1::ToEncodedPoint,
        Field,
        ops::Reduce,
    },
    NonZeroScalar, ProjectivePoint, Scalar, U256,
};
use sha3::{Digest as _, Keccak256};

fn main() {
    let mut rng = rand::rngs::OsRng;

    // ── Fixed test message ─────────────────────────────────────────────────
    let msg_bytes: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(b"test attestation for dx-DCTLS").into()
    };

    // ── Key generation ─────────────────────────────────────────────────────
    // sk: random secret key
    let sk = NonZeroScalar::random(&mut rng);
    let pk_proj = ProjectivePoint::GENERATOR * sk.as_ref();
    let pk_aff = k256::AffinePoint::from(pk_proj);
    let pk_uncompressed = pk_aff.to_encoded_point(false);
    let pk_x_bytes: [u8; 32] = pk_uncompressed.x().unwrap().as_slice().try_into().unwrap();
    let pk_y_bytes: [u8; 32] = pk_uncompressed.y().unwrap().as_slice().try_into().unwrap();

    // ── Nonce generation ───────────────────────────────────────────────────
    // k: ephemeral nonce
    let k = NonZeroScalar::random(&mut rng);
    let r_proj = ProjectivePoint::GENERATOR * k.as_ref();
    let r_aff = k256::AffinePoint::from(r_proj);
    let r_encoded = r_aff.to_encoded_point(false);
    let r_x_bytes: [u8; 32] = r_encoded.x().unwrap().as_slice().try_into().unwrap();
    let r_y_bytes: [u8; 32] = r_encoded.y().unwrap().as_slice().try_into().unwrap();

    // FROST even-y convention: if R_y is odd, negate k (and R).
    let r_y_odd = r_y_bytes[31] & 1 == 1;
    let (k_final, r_x_final) = if r_y_odd {
        // negate k → R becomes -R which has even y
        (-k.as_ref(), r_x_bytes)
    } else {
        (*k.as_ref(), r_x_bytes)
    };

    // ── Challenge: keccak256(R_x || pk_x || msg) % N ──────────────────────
    let mut hasher = Keccak256::new();
    hasher.update(&r_x_final);
    hasher.update(&pk_x_bytes);
    hasher.update(&msg_bytes);
    let hash_bytes: [u8; 32] = hasher.finalize().into();

    // Reduce hash mod N (secp256k1 scalar field)
    let e = <Scalar as Reduce<U256>>::reduce_bytes(&hash_bytes.into());

    // ── Schnorr signature: s = k + e * sk ─────────────────────────────────
    let sig_s = k_final + e * sk.as_ref();

    let mut sig_s_bytes = [0u8; 32];
    sig_s_bytes.copy_from_slice(&sig_s.to_bytes());

    // ── Print test vectors ─────────────────────────────────────────────────
    println!("// ── FrostVerifier.t.sol test vectors ─────────────────────────────────────");
    println!("// Source: gen-test-vectors (keccak256-Schnorr, matches FrostVerifier.sol)");
    println!("// Threshold: standalone 1-of-1 key pair (same verification logic as FROST)");
    println!("//");
    println!("bytes32 constant MSG_HASH = 0x{};", hex::encode(msg_bytes));
    println!("uint256 constant PK_X     = 0x{};", hex::encode(pk_x_bytes));
    println!("uint256 constant PK_Y     = 0x{};", hex::encode(pk_y_bytes));
    println!("uint256 constant SIG_R_X  = 0x{};", hex::encode(r_x_final));
    println!("uint256 constant SIG_S    = 0x{};", hex::encode(sig_s_bytes));
    println!();
    println!("// Sanity: R_y parity (should be even for valid FROST sig):");
    let r_y_final = if r_y_odd {
        // R was negated, R_y = p - r_y_bytes
        let p_hex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
        println!("// R_y: negated (was odd), new R_y = P - old_R_y (even)");
        println!("// original R_y = 0x{}", hex::encode(r_y_bytes));
        p_hex.to_string()
    } else {
        println!("// R_y = 0x{} (even ✓)", hex::encode(r_y_bytes));
        hex::encode(r_y_bytes)
    };
    let _ = r_y_final;

    println!();
    println!("// Challenge e = keccak256(R_x || pk_x || msg) % N:");
    println!("// e = 0x{}", hex::encode(e.to_bytes().as_slice()));
}