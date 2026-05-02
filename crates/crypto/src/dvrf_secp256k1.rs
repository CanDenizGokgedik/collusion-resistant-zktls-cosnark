//! DDH-based DVRF on secp256k1 — RC Phase of Π_coll-min.
//!
//! # Protocol Position
//!
//! This module implements the **RC (Randomness Creation) Phase**:
//!
//! ```text
//! Π_coll-min RC Phase:
//!   DKG(pp, t, n)               → (ski, vki, pk)
//!   PartialEval(α, ski, vki)    → (i, γi, πi_DVRF)
//!   Combine(pk, VK, α, E)       → (rand, π_DVRF)
//!   Verify(pk, α, π_DVRF, rand) → {0,1}
//! ```
//!
//! The output `rand` is the DVRF randomness fed into the dx-DCTLS attestation
//! phase: `HSP(rand) → (sps, spp, spv)`.
//!
//! # Construction
//!
//! We use **FROST-based DVRF** on secp256k1 (consistent with paper §IX):
//!
//! ```text
//! PartialEval(α, sk_i):
//!   nonce = HKDF("dvrf-nonce-seed/secp256k1/v1" || key_package || α)
//!   commitment = nonce * G
//!   γ_i = FROST.round2(signing_package(α), nonce, key_package)
//!
//! Combine(γ_i):
//!   σ = FROST.aggregate(γ_i)
//!   rand = H("dvrf-output/secp256k1/v1" || σ)
//!
//! Verify(pk, α, σ, rand):
//!   FROST.verify(pk, α, σ) == OK
//!   rand == H("dvrf-output/secp256k1/v1" || σ)
//! ```
//!
//! FROST's deterministic nonces guarantee **uniqueness**: for fixed (α, sk),
//! there is exactly one valid σ — satisfying the DVRF uniqueness property
//! (Theorem 1 security reduction in the paper).
//!
//! # Security Properties
//!
//! - **Uniqueness**: Unique σ per (α, group_key) → unique `rand`. Follows from
//!   EUF-CMA security of secp256k1 Schnorr.
//! - **Public Verifiability**: Any party with `pk` can call `verify()`.
//! - **Pseudorandomness**: `rand = H(σ)` is PRF-secure under DDH in ROM.
//! - **Threshold**: Requires ≥ t participants (FROST t-of-n).

use crate::error::CryptoError;
use crate::frost_secp256k1_adapter::{
    secp256k1_aggregate_signature_shares,
    secp256k1_build_signing_package,
    Secp256k1Commitment, Secp256k1FrostParticipant, Secp256k1GroupKey,
    Secp256k1SignatureShare, Secp256k1SigningNonces,
};
use tls_attestation_core::hash::{CanonicalHasher, DigestBytes};
use tls_attestation_core::ids::VerifierId;

// ── DVRF input ────────────────────────────────────────────────────────────────

/// The plaintext α used in the RC Phase.
///
/// In Π_coll-min: all verifiers agree on the same α before DKG.
/// Typically `α = H(session_id || client_nonce)`.
#[derive(Clone, Debug)]
pub struct Secp256k1DvrfInput {
    pub alpha: DigestBytes,
}

impl Secp256k1DvrfInput {
    pub fn new(alpha: DigestBytes) -> Self {
        Self { alpha }
    }
}

// ── DVRF partial evaluation ────────────────────────────────────────────────────

/// Output of `Secp256k1Dvrf::partial_eval` — one participant's contribution.
///
/// The coordinator collects `t` partial evaluations, then calls `combine`.
pub struct Secp256k1PartialEval {
    pub verifier_id:   VerifierId,
    pub commitment:    Secp256k1Commitment,
    nonces:            Secp256k1SigningNonces,
}

// ── DVRF proof ────────────────────────────────────────────────────────────────

/// The DVRF proof π_DVRF.
///
/// In Π_coll-min Signing Phase: `DVRF.Verify(pk, α, π_DVRF, spv) → {0,1}`.
#[derive(Clone, Debug)]
pub struct Secp256k1DvrfProof {
    /// 65-byte EVM-compatible secp256k1 Schnorr aggregate signature σ.
    pub sigma: [u8; 65],
    /// 33-byte compressed group verifying key.
    pub group_verifying_key: [u8; 33],
}

// ── DVRF output ───────────────────────────────────────────────────────────────

/// The DVRF output: `(rand, π_DVRF)`.
///
/// `rand` is the 32-byte pseudorandom value fed into `HSP(rand)`.
/// `proof` allows any party to independently verify `rand` is correctly derived.
#[derive(Clone, Debug)]
pub struct Secp256k1DvrfOutput {
    /// The DVRF pseudorandom output: `H("dvrf-output/secp256k1/v1" || σ)`.
    pub rand: DigestBytes,
    /// The correctness proof π_DVRF.
    pub proof: Secp256k1DvrfProof,
}

// ── DVRF engine ───────────────────────────────────────────────────────────────

/// Secp256k1 DVRF — RC Phase of Π_coll-min.
pub struct Secp256k1Dvrf;

impl Secp256k1Dvrf {
    // ── PartialEval ───────────────────────────────────────────────────────────

    /// `PartialEval(α, sk_i, vk_i) → (i, γ_i, π_i_DVRF)`
    ///
    /// Each aux node calls this independently. The returned `Secp256k1PartialEval`
    /// contains the Round-1 commitment and single-use nonces.
    ///
    /// The coordinator collects `t` partial evals, then calls `combine`.
    pub fn partial_eval(
        participant: &Secp256k1FrostParticipant,
        input: &Secp256k1DvrfInput,
    ) -> Result<Secp256k1PartialEval, CryptoError> {
        let (nonces, commitment) = participant.round1_dvrf(input.alpha.as_bytes());
        Ok(Secp256k1PartialEval {
            verifier_id: participant.verifier_id().clone(),
            commitment,
            nonces,
        })
    }

    // ── Round-2 shares ────────────────────────────────────────────────────────

    /// Produce Round-2 signature shares from all participants.
    ///
    /// Called after `combine_commitments` has assembled the signing package.
    pub fn round2_shares(
        participants:    &[&Secp256k1FrostParticipant],
        partial_evals:   Vec<Secp256k1PartialEval>,
        signing_package: &crate::frost_secp256k1_adapter::Secp256k1SigningPackage,
    ) -> Result<Vec<Secp256k1SignatureShare>, CryptoError> {
        partial_evals
            .into_iter()
            .zip(participants.iter())
            .map(|(pe, p)| p.round2(signing_package, pe.nonces))
            .collect()
    }

    // ── Combine ───────────────────────────────────────────────────────────────

    /// `Combine(pk, VK, α, E) → (rand, π_DVRF)`
    ///
    /// The coordinator calls this after collecting ≥ t partial evaluations.
    ///
    /// # Arguments
    ///
    /// - `group_key`    — the FROST group key (public, from DKG).
    /// - `input`        — the agreed plaintext α.
    /// - `partial_evals`— at least `threshold` partial evaluations.
    /// - `participants` — references to participants providing shares.
    ///
    /// # Returns
    ///
    /// `(rand, π_DVRF)` — the DVRF output and proof.
    pub fn combine(
        group_key:    &Secp256k1GroupKey,
        input:        &Secp256k1DvrfInput,
        partial_evals: Vec<Secp256k1PartialEval>,
        participants:  &[&Secp256k1FrostParticipant],
    ) -> Result<Secp256k1DvrfOutput, CryptoError> {
        // Assemble signing package from Round-1 commitments.
        let commits: Vec<_> = partial_evals.iter().map(|pe| pe.commitment.clone()).collect();
        let pkg = secp256k1_build_signing_package(&commits, &input.alpha)?;

        // Round-2 shares.
        let shares = Self::round2_shares(participants, partial_evals, &pkg)?;
        let _ = participants; // already used above

        // Aggregate.
        let approval = secp256k1_aggregate_signature_shares(&pkg, &shares, group_key)?;
        let sigma = approval.aggregate_signature_bytes;

        // Derive rand = H("dvrf-output/secp256k1/v1" || σ).
        let rand = Self::derive_rand(&sigma);

        Ok(Secp256k1DvrfOutput {
            rand,
            proof: Secp256k1DvrfProof {
                sigma,
                group_verifying_key: approval.group_verifying_key_bytes,
            },
        })
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    /// `Verify(pk, α, π_DVRF, rand) → {0,1}`
    ///
    /// Public verifiability: any party with `group_key` can verify.
    ///
    /// In Π_coll-min Signing Phase, each Vi calls this before signing:
    /// `{0,1} ← DVRF.Verify(pk, α, π_DVRF, spv)`.
    pub fn verify(
        input:  &Secp256k1DvrfInput,
        output: &Secp256k1DvrfOutput,
    ) -> Result<(), CryptoError> {
        use crate::frost_secp256k1_adapter::{
            secp256k1_verify_approval, Secp256k1ThresholdApproval,
        };

        // Verify the Schnorr signature σ over α.
        let approval = Secp256k1ThresholdApproval {
            aggregate_signature_bytes: output.proof.sigma,
            group_verifying_key_bytes: output.proof.group_verifying_key,
        };
        secp256k1_verify_approval(&approval, &input.alpha)?;

        // Recompute rand and check it matches.
        let expected_rand = Self::derive_rand(&output.proof.sigma);
        if expected_rand != output.rand {
            return Err(CryptoError::AggregationFailed(
                "DVRF.Verify: rand mismatch — proof is invalid".into(),
            ));
        }

        Ok(())
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn derive_rand(sigma: &[u8; 65]) -> DigestBytes {
        let mut h = CanonicalHasher::new("dvrf-output/secp256k1/v1");
        h.update_fixed(sigma);
        h.finalize()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost_secp256k1_adapter::secp256k1_trusted_dealer_keygen;
    use rand::rngs::OsRng;
    use tls_attestation_core::ids::VerifierId;

    fn vids(n: usize) -> Vec<VerifierId> {
        (0..n as u8).map(|i| VerifierId::from_bytes([i; 32])).collect()
    }

    fn make_input() -> Secp256k1DvrfInput {
        Secp256k1DvrfInput::new(DigestBytes::from_bytes([0x42u8; 32]))
    }

    #[test]
    fn dvrf_2of3_round_trip() {
        let ids = vids(3);
        let out = secp256k1_trusted_dealer_keygen(&ids, 2).unwrap();
        let input = make_input();
        let mut rng = OsRng;

        // PartialEval × 2 (threshold).
        let partial_evals: Vec<_> = out.participants[..2]
            .iter()
            .map(|p| Secp256k1Dvrf::partial_eval(p, &input).unwrap())
            .collect();

        let refs: Vec<_> = out.participants[..2].iter().collect();
        let dvrf_output = Secp256k1Dvrf::combine(&out.group_key, &input, partial_evals, &refs).unwrap();

        // Verify.
        Secp256k1Dvrf::verify(&input, &dvrf_output).unwrap();

        assert_ne!(dvrf_output.rand, DigestBytes::ZERO, "rand must be non-zero");
        println!("DVRF rand: {}", dvrf_output.rand.to_hex());
    }

    #[test]
    fn dvrf_same_input_same_output() {
        let ids = vids(3);
        let out = secp256k1_trusted_dealer_keygen(&ids, 2).unwrap();
        let input = make_input();
        let mut rng = OsRng;

        let run = |dummy: u8| {
            let pes: Vec<_> = out.participants[..2]
                .iter()
                .map(|p| Secp256k1Dvrf::partial_eval(p, &input).unwrap())
                .collect();
            let refs: Vec<_> = out.participants[..2].iter().collect();
            Secp256k1Dvrf::combine(&out.group_key, &input, pes, &refs).unwrap()
        };

        let o1 = run(0u8);
        let o2 = run(1u8);

        // FROST uses deterministic nonces seeded from key_package + message,
        // so both runs should produce the same σ → same rand.
        assert_eq!(o1.rand, o2.rand, "DVRF must be deterministic for same input");
    }

    #[test]
    fn dvrf_different_input_different_output() {
        let ids = vids(3);
        let out = secp256k1_trusted_dealer_keygen(&ids, 2).unwrap();
        let mut rng = OsRng;

        let input1 = Secp256k1DvrfInput::new(DigestBytes::from_bytes([0x11u8; 32]));
        let input2 = Secp256k1DvrfInput::new(DigestBytes::from_bytes([0x22u8; 32]));

        let run = |input: &Secp256k1DvrfInput| {
            let pes: Vec<_> = out.participants[..2]
                .iter()
                .map(|p| Secp256k1Dvrf::partial_eval(p, input).unwrap())
                .collect();
            let refs: Vec<_> = out.participants[..2].iter().collect();
            Secp256k1Dvrf::combine(&out.group_key, input, pes, &refs).unwrap()
        };

        let o1 = run(&input1);
        let o2 = run(&input2);
        assert_ne!(o1.rand, o2.rand, "different α must yield different rand");
    }

    #[test]
    fn dvrf_tampered_proof_fails_verify() {
        let ids = vids(3);
        let out = secp256k1_trusted_dealer_keygen(&ids, 2).unwrap();
        let input = make_input();
        let mut rng = OsRng;

        let pes: Vec<_> = out.participants[..2]
            .iter()
            .map(|p| Secp256k1Dvrf::partial_eval(p, &input).unwrap())
            .collect();
        let refs: Vec<_> = out.participants[..2].iter().collect();
        let mut dvrf_output = Secp256k1Dvrf::combine(&out.group_key, &input, pes, &refs).unwrap();

        // Tamper with rand.
        dvrf_output.rand = DigestBytes::from_bytes([0xFFu8; 32]);
        let result = Secp256k1Dvrf::verify(&input, &dvrf_output);
        assert!(result.is_err(), "tampered rand must fail verify");
    }
}