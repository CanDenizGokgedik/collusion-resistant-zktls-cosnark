//! Verifying key exporter — arkworks BN254 → Solidity DctlsVerifier format.
//!
//! # Paper reference — §IX On-Chain Attestation
//!
//! The on-chain Groth16 verifier (`DctlsVerifier.sol`) requires the verifying
//! key registered as BN254 affine coordinates.  This module converts arkworks'
//! internal representation to the ABI-encoded format expected by Solidity.

use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{PreparedVerifyingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{:02x}", b)); }
    s
}
use serde::Serialize;

// ── Output types ───────────────────────────────────────────────────────────────

/// G1 point in Solidity-compatible hex uint256 strings.
#[derive(Debug, Clone, Serialize)]
pub struct G1Point {
    pub x: String,
    pub y: String,
}

/// G2 point in Solidity-compatible hex uint256 strings.
///
/// BN254 G2 elements live in Fq2 = Fq[u]/(u²+1).
/// EIP-197 byte ordering: (x.c1, x.c0, y.c1, y.c0).
#[derive(Debug, Clone, Serialize)]
pub struct G2Point {
    pub x0: String, // x.c1
    pub x1: String, // x.c0
    pub y0: String, // y.c1
    pub y1: String, // y.c0
}

/// Full verifying key in Solidity ABI format.
#[derive(Debug, Clone, Serialize)]
pub struct SolidityVK {
    pub circuit: String,
    pub num_public_inputs: usize,
    /// α (G1) — negated for the pairing product formula.
    pub alpha_neg: G1Point,
    /// β (G2)
    pub beta: G2Point,
    /// γ (G2)
    pub gamma: G2Point,
    /// δ (G2)
    pub delta: G2Point,
    /// IC[0] (constant) + IC[1..n] (one per public input).
    pub ic: Vec<G1Point>,
}

// ── Conversion helpers ─────────────────────────────────────────────────────────

fn fq_to_hex(f: &Fq) -> String {
    // Serialize to 32 bytes (big-endian) then hex-encode.
    let mut bytes = Vec::with_capacity(32);
    f.serialize_uncompressed(&mut bytes).expect("Fq serialize");
    // ark serializes in little-endian — reverse to big-endian for Solidity.
    bytes.reverse();
    format!("0x{}", bytes_to_hex(&bytes))
}

fn g1_to_solidity(p: &G1Affine) -> G1Point {
    let (x, y) = p.xy().expect("G1 point must not be infinity");
    G1Point { x: fq_to_hex(x), y: fq_to_hex(y) }
}

fn g1_neg(p: &G1Affine) -> G1Affine {
    // Negate a G1 affine point: (x, y) → (x, -y)
    use ark_ff::Field;
    if p.is_zero() { return *p; }
    let (x, y) = p.xy().unwrap();
    G1Affine::new(*x, -*y)
}

fn g2_to_solidity(p: &G2Affine) -> G2Point {
    let (x, y) = p.xy().expect("G2 point must not be infinity");
    G2Point {
        x0: fq_to_hex(&x.c1),
        x1: fq_to_hex(&x.c0),
        y0: fq_to_hex(&y.c1),
        y1: fq_to_hex(&y.c0),
    }
}

// ── Main export function ───────────────────────────────────────────────────────

/// Convert an arkworks `PreparedVerifyingKey<Bn254>` to Solidity format.
pub fn export_vk(
    pvk: &PreparedVerifyingKey<Bn254>,
    circuit: &str,
    num_public_inputs: usize,
) -> SolidityVK {
    // PreparedVerifyingKey<Bn254> implements Into<VerifyingKey<Bn254>>.
    let vk: VerifyingKey<Bn254> = pvk.clone().into();

    let ic = vk
        .gamma_abc_g1
        .iter()
        .map(|p| g1_to_solidity(p))
        .collect::<Vec<_>>();

    SolidityVK {
        circuit: circuit.to_string(),
        num_public_inputs,
        alpha_neg: g1_to_solidity(&g1_neg(&vk.alpha_g1)),
        beta:  g2_to_solidity(&vk.beta_g2),
        gamma: g2_to_solidity(&vk.gamma_g2),
        delta: g2_to_solidity(&vk.delta_g2),
        ic,
    }
}

/// Serialize a `SolidityVK` to JSON.
pub fn vk_to_json(vk: &SolidityVK) -> String {
    serde_json::to_string_pretty(vk).expect("VK JSON serialization")
}

/// Produce a human-readable calldata comment for copy-paste into deployment scripts.
pub fn vk_to_solidity_calldata(vk: &SolidityVK) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "// Circuit: {} ({} public inputs)\n",
        vk.circuit, vk.num_public_inputs
    ));
    out.push_str(&format!(
        "//   alpha_neg: ({}, {})\n",
        vk.alpha_neg.x, vk.alpha_neg.y
    ));
    out.push_str(&format!(
        "//   beta:  ({}, {}, {}, {})\n",
        vk.beta.x0, vk.beta.x1, vk.beta.y0, vk.beta.y1
    ));
    out.push_str(&format!(
        "//   gamma: ({}, {}, {}, {})\n",
        vk.gamma.x0, vk.gamma.x1, vk.gamma.y0, vk.gamma.y1
    ));
    out.push_str(&format!(
        "//   delta: ({}, {}, {}, {})\n",
        vk.delta.x0, vk.delta.x1, vk.delta.y0, vk.delta.y1
    ));
    for (i, pt) in vk.ic.iter().enumerate() {
        out.push_str(&format!("//   IC[{}]: ({}, {})\n", i, pt.x, pt.y));
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::co_snark::CoSnarkCrs;
    use crate::tls_session_binding::SessionBindingCrs;

    #[test]
    fn export_hsp_mode1_vk() {
        let crs = CoSnarkCrs::setup().expect("CRS setup");
        let vk = export_vk(&crs.pvk, "hsp_mode1", 2);
        let json = vk_to_json(&vk);

        assert!(json.contains("hsp_mode1"));
        assert!(json.contains("alpha_neg"));
        assert_eq!(vk.ic.len(), 3, "IC[0] + 2 public inputs");

        // All hex values must start with 0x and be 66 chars (0x + 64 hex digits).
        assert!(vk.alpha_neg.x.starts_with("0x"), "must be hex");
        assert_eq!(vk.alpha_neg.x.len(), 66, "must be 32-byte hex");

        println!("HSP Mode 1 calldata:\n{}", vk_to_solidity_calldata(&vk));
    }

    #[test]
    fn export_session_binding_vk() {
        let crs = SessionBindingCrs::setup().expect("CRS setup");
        let vk = export_vk(&crs.pvk, "session_binding", 4);

        assert_eq!(vk.ic.len(), 5, "IC[0] + 4 public inputs");

        let calldata = vk_to_solidity_calldata(&vk);
        assert!(calldata.contains("IC[4]"), "must have 5 IC points");
        println!("{}", calldata);
    }
}
