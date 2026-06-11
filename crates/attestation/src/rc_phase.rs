//! RC (Randomness Creation) Phase — Π_coll-min §VIII.B.
//!
//! Implements the first phase of the paper's protocol exactly:
//!
//! ```text
//! Π_coll-min RC Phase (paper Fig. 8):
//!
//!   Setup(1^λ) → pp
//!     pp includes security parameters and plaintext α for all parties.
//!
//!   Among V_coord and V_i:
//!     (ski, vki, pk)     ← DKG(pp, t, n)
//!     (i, Vi, π_DVRF_i) ← PartialEval(α, ski, vki)
//!     (rand, π_DVRF)     ← Combine(pk, VK, α, E)
//! ```
//!
//! The output `rand` is fed into the dx-DCTLS Attestation Phase:
//! `HSP(pp, rand) → (sps, spp, spv)`.
//!
//! # Participants
//!
//! - **Coordinator** (`V_coord`): orchestrates the ceremony, calls `combine`.
//! - **Auxiliary verifiers** (`V_i`): each calls `partial_eval` independently.
//!
//! # Security guarantees
//!
//! - **Uniqueness** (DVRF): For fixed (α, group_key), only one valid `rand` exists.
//! - **Public verifiability**: Any party with `pk` can call `Verify(pk, α, π_DVRF, rand)`.
//! - **Threshold**: At least `t` of `n` participants needed to produce `rand`.
//! - **No single-party bias**: No participant can predict or bias `rand` in advance.
//!
//! # Relationship to Theorem 1
//!
//! The security reduction in the paper (TAU ≤ Adv_DVRF + Adv_dx-DCTLS) requires
//! that `rand` is the DVRF output and that the attestation uses exactly this `rand`.
//! `RcPhaseOutput::rand` is the value passed to `HSP(rand)`.

use crate::error::AttestationError;
use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};

#[cfg(feature = "secp256k1")]
use tls_attestation_crypto::{
    dkg_secp256k1::{run_secp256k1_dkg, Secp256k1DkgParticipantOutput},
    dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput, Secp256k1DvrfOutput, Secp256k1PartialEval},
    frost_secp256k1_adapter::{Secp256k1FrostParticipant, Secp256k1GroupKey},
};

// ── Setup output ──────────────────────────────────────────────────────────────

/// Public parameters (pp) from `Setup(1^λ)`.
///
/// Contains the agreed plaintext α used by all parties in the ceremony.
/// α should be a fresh, session-specific value (e.g., commitment to a
/// session identifier, timestamp, or challenge).
#[derive(Clone, Debug)]
pub struct RcPhaseParams {
    /// The agreed plaintext α for the DVRF evaluation.
    pub alpha: DigestBytes,
}

impl RcPhaseParams {
    /// Create parameters from a 32-byte digest.
    pub fn new(alpha: DigestBytes) -> Self {
        Self { alpha }
    }

    /// Derive α from a session ID and a nonce, domain-separated.
    pub fn from_session(session_id: &[u8], nonce: &[u8]) -> Self {
        use tls_attestation_core::hash::CanonicalHasher;
        let mut h = CanonicalHasher::new("tls-attestation/rc-phase/alpha/v1");
        h.update_bytes(session_id);
        h.update_bytes(nonce);
        Self { alpha: h.finalize() }
    }
}

// ── RC Phase output ───────────────────────────────────────────────────────────

/// Output of the RC Phase: the DVRF randomness and its correctness proof.
///
/// `rand` is the 32-byte pseudorandom value used in `HSP(pp, rand)`.
/// `dvrf_proof` allows any party with `group_key` to independently verify
/// that `rand = DVRF(α)` was correctly produced by ≥ t participants.
#[derive(Clone, Debug)]
pub struct RcPhaseOutput {
    /// The DVRF pseudorandom output: `rand = H("dvrf-output/secp256k1/v1" || σ)`.
    ///
    /// This is fed into `HSP(pp, rand)` in the Attestation Phase.
    pub rand: DigestBytes,

    /// The DVRF π_DVRF proof, used in the Signing Phase:
    /// `{0,1} ← DVRF.Verify(pk, α, π_DVRF, spv)`.
    #[cfg(feature = "secp256k1")]
    pub dvrf_output: Secp256k1DvrfOutput,

    /// The agreed α that was evaluated.
    pub alpha: DigestBytes,
}

// ── Partial evaluation (per aux node) ─────────────────────────────────────────

/// A partial DVRF evaluation from one auxiliary verifier.
///
/// In the paper: `(i, Vi, π_DVRF_i) ← PartialEval(α, sk_i, vk_i)`.
#[cfg(feature = "secp256k1")]
pub struct RcPartialEval {
    pub verifier_id: VerifierId,
    pub(crate) inner: Secp256k1PartialEval,
}

// ── RC Phase orchestrator ─────────────────────────────────────────────────────

/// Orchestrates the full RC Phase in-process (for tests and single-machine demos).
///
/// In production, `DKG` runs across separate machines; `PartialEval` is called
/// by each aux node independently; `Combine` is called by the coordinator.
/// This struct bundles all three steps for integration tests and benchmarks.
#[cfg(feature = "secp256k1")]
pub struct RcPhaseOrchestrator {
    /// DKG outputs, one per participant.
    pub dkg_outputs: Vec<Secp256k1DkgParticipantOutput>,
    /// Participant IDs, in the same order as `dkg_outputs`.
    pub verifier_ids: Vec<VerifierId>,
    /// Threshold (minimum participants required).
    pub threshold: usize,
}

#[cfg(feature = "secp256k1")]
impl RcPhaseOrchestrator {
    /// Run the full DKG ceremony and return an orchestrator ready for DVRF.
    ///
    /// In Π_coll-min: this is `DKG(pp, t, n) → (ski, vki, pk)`.
    pub fn run_dkg(
        verifier_ids: Vec<VerifierId>,
        threshold: usize,
    ) -> Result<Self, AttestationError> {
        let dkg_outputs = run_secp256k1_dkg(&verifier_ids, threshold)
            .map_err(|e| AttestationError::Crypto(e.to_string()))?;
        Ok(Self { dkg_outputs, verifier_ids, threshold })
    }

    /// The shared group public key `pk`, identical for all participants.
    pub fn group_key(&self) -> &Secp256k1GroupKey {
        &self.dkg_outputs[0].group_key
    }

    // ── PartialEval ───────────────────────────────────────────────────────────

    /// `PartialEval(α, sk_i, vk_i) → (i, γ_i, π_i_DVRF)`
    ///
    /// Each auxiliary verifier calls this independently with their own key share.
    /// Typically called by index 0..threshold (or any t-subset).
    pub fn partial_eval(
        &self,
        participant_index: usize,
        params: &RcPhaseParams,
    ) -> Result<RcPartialEval, AttestationError> {
        let participant = &self.dkg_outputs[participant_index].participant;
        let input = Secp256k1DvrfInput::new(params.alpha.clone());
        let inner = Secp256k1Dvrf::partial_eval(participant, &input)
            .map_err(|e| AttestationError::Crypto(e.to_string()))?;
        Ok(RcPartialEval {
            verifier_id: self.verifier_ids[participant_index].clone(),
            inner,
        })
    }

    // ── Combine ───────────────────────────────────────────────────────────────

    /// `Combine(pk, VK, α, E) → (rand, π_DVRF)`
    ///
    /// The coordinator calls this after collecting ≥ `threshold` partial evals.
    ///
    /// In Π_coll-min: the output `rand` is passed to `HSP(pp, rand)`.
    pub fn combine(
        &self,
        params: &RcPhaseParams,
        partial_evals: Vec<RcPartialEval>,
    ) -> Result<RcPhaseOutput, AttestationError> {
        if partial_evals.len() < self.threshold {
            return Err(AttestationError::Crypto(format!(
                "RC Phase Combine: need {t} partial evals, got {n}",
                t = self.threshold,
                n = partial_evals.len(),
            )));
        }

        let input = Secp256k1DvrfInput::new(params.alpha.clone());
        let group_key = self.group_key();

        // Collect participants references matching the partial evals.
        let participant_refs: Vec<&Secp256k1FrostParticipant> = partial_evals
            .iter()
            .filter_map(|pe| {
                self.verifier_ids
                    .iter()
                    .position(|vid| *vid == pe.verifier_id)
                    .map(|i| &self.dkg_outputs[i].participant)
            })
            .collect();

        let inner_evals: Vec<_> = partial_evals.into_iter().map(|pe| pe.inner).collect();

        let dvrf_output =
            Secp256k1Dvrf::combine(group_key, &input, inner_evals, &participant_refs)
                .map_err(|e| AttestationError::Crypto(e.to_string()))?;

        Ok(RcPhaseOutput {
            rand: dvrf_output.rand.clone(),
            dvrf_output,
            alpha: params.alpha.clone(),
        })
    }

    // ── Convenience: full RC Phase in one call ────────────────────────────────

    /// Run the full RC Phase: PartialEval × threshold + Combine.
    ///
    /// Uses the first `threshold` participants. For production, each participant
    /// calls `partial_eval` independently on a separate machine.
    pub fn run_rc_phase(
        &self,
        params: &RcPhaseParams,
    ) -> Result<RcPhaseOutput, AttestationError> {
        let partial_evals: Vec<_> = (0..self.threshold)
            .map(|i| self.partial_eval(i, params))
            .collect::<Result<_, _>>()?;
        self.combine(params, partial_evals)
    }
}

// ── DVRF Verify (public) ──────────────────────────────────────────────────────

/// `DVRF.Verify(pk, α, π_DVRF, rand) → {0,1}`
///
/// Used in the Signing Phase by each aux verifier V_i:
/// `{0,1} ← DVRF.Verify(pk, α, π_DVRF, spv)`
///
/// Any party with `pk` can call this — no secret material required.
#[cfg(feature = "secp256k1")]
pub fn rc_phase_verify(output: &RcPhaseOutput) -> Result<(), AttestationError> {
    let input = Secp256k1DvrfInput::new(output.alpha.clone());
    Secp256k1Dvrf::verify(&input, &output.dvrf_output)
        .map_err(|e| AttestationError::Crypto(format!("DVRF.Verify failed: {e}")))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "secp256k1")]
mod tests {
    use super::*;
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};

    fn vids(n: usize) -> Vec<VerifierId> {
        (0..n as u8).map(|i| VerifierId::from_bytes([i; 32])).collect()
    }

    #[test]
    fn rc_phase_2of3_full() {
        let ids = vids(3);
        let orc = RcPhaseOrchestrator::run_dkg(ids, 2).unwrap();

        let params = RcPhaseParams::from_session(b"session-001", b"nonce-abc");
        let output = orc.run_rc_phase(&params).unwrap();

        // Verify rand is correct.
        rc_phase_verify(&output).unwrap();

        assert_ne!(output.rand, DigestBytes::ZERO);
        println!("RC Phase rand: {}", output.rand.to_hex());
    }

    #[test]
    fn rc_phase_deterministic() {
        let ids = vids(3);
        let orc = RcPhaseOrchestrator::run_dkg(ids, 2).unwrap();
        let params = RcPhaseParams::from_session(b"sess", b"nonce");

        let o1 = orc.run_rc_phase(&params).unwrap();
        let o2 = orc.run_rc_phase(&params).unwrap();

        assert_eq!(o1.rand, o2.rand, "RC Phase must be deterministic for same (keys, α)");
    }

    #[test]
    fn rc_phase_different_alpha_different_rand() {
        let ids = vids(3);
        let orc = RcPhaseOrchestrator::run_dkg(ids, 2).unwrap();

        let p1 = RcPhaseParams::from_session(b"sess1", b"nonce");
        let p2 = RcPhaseParams::from_session(b"sess2", b"nonce");

        let o1 = orc.run_rc_phase(&p1).unwrap();
        let o2 = orc.run_rc_phase(&p2).unwrap();

        assert_ne!(o1.rand, o2.rand, "Different α must produce different rand");
    }

    #[test]
    fn rc_phase_insufficient_evals_fails() {
        let ids = vids(3);
        let orc = RcPhaseOrchestrator::run_dkg(ids, 2).unwrap();
        let params = RcPhaseParams::from_session(b"sess", b"nonce");

        // Only 1 eval (need 2).
        let pe = orc.partial_eval(0, &params).unwrap();
        let result = orc.combine(&params, vec![pe]);
        assert!(result.is_err(), "combine with < threshold evals must fail");
    }

    #[test]
    fn rc_phase_3of5() {
        let ids = vids(5);
        let orc = RcPhaseOrchestrator::run_dkg(ids, 3).unwrap();
        let params = RcPhaseParams::from_session(b"large-session", b"nonce-xyz");
        let output = orc.run_rc_phase(&params).unwrap();
        rc_phase_verify(&output).unwrap();
        println!("3-of-5 RC Phase rand: {}", output.rand.to_hex());
    }
}