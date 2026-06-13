//! K_MAC ↔ commitment binding helpers (extracted from the original
//! `tls_prf_circuit`). These tie the MAC key produced by the 2PC HSP to the
//! public commitment that the PGP Groth16 proof opens, so the verifier is
//! assured the proof used the genuine session key.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_ff::{One, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Pack a 32-byte K_MAC into a single BN254 field element (little-endian),
/// clearing the top 2 bits so the value never wraps the 254-bit modulus.
pub fn bytes32_to_fr(bytes: &[u8; 32]) -> Fr {
    let mut b = *bytes;
    b[31] &= 0x3F; // clear bits 254-255 (top 2 bits of the LE 256-bit value)
    Fr::from_le_bytes_mod_order(&b)
}

/// Public commitment binding the MAC key: `pack(K_MAC) + rand_binding`.
/// `rand_binding` here is the verifier's sampled randomness from the 2PC HSP
/// (in the original construction it came from the DVRF; removed now).
pub fn k_mac_commitment(k_mac: &[u8; 32], rand_binding_fe: Fr) -> Fr {
    bytes32_to_fr(k_mac) + rand_binding_fe
}

/// In-circuit version of `bytes32_to_fr`: accumulate Σ bit[i]·2^i over the
/// first 254 bits of the byte vars.
pub fn pack_bytes_to_fpvar(
    cs: ConstraintSystemRef<Fr>,
    bytes: &[UInt8<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut result = FpVar::<Fr>::new_constant(cs.clone(), Fr::zero())?;
    let mut coeff = Fr::one();
    let mut bit_count = 0usize;

    for byte_var in bytes {
        let bits = byte_var.to_bits_le()?; // LSB first, 8 bits
        for bit in bits {
            if bit_count >= 254 {
                break;
            }
            let bit_fe: FpVar<Fr> = FpVar::from(bit);
            let coeff_var = FpVar::<Fr>::new_constant(cs.clone(), coeff)?;
            result += bit_fe * coeff_var;
            coeff = coeff + coeff;
            bit_count += 1;
        }
    }

    Ok(result)
}
