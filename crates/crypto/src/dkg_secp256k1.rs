//! Pedersen DKG adapter for FROST(secp256k1-EVM, Keccak256).
//!
//! Mirrors `dkg.rs` exactly, replacing `frost-ed25519` with
//! `frost-secp256k1-evm` to produce `Secp256k1FrostParticipant` and
//! `Secp256k1GroupKey` — the production key material for Π_coll-min.
//!
//! # Protocol summary (RFC 9591 / FROST paper §6)
//!
//! ```text
//! Part 1 — each participant independently:
//!   • Generates a random secret polynomial + ZK proof of knowledge.
//!   • Returns a Round-1 secret state (in memory) and
//!     a Round-1 broadcast package (sent to ALL other participants).
//!
//! Part 2 — each participant, after receiving all Round-1 packages:
//!   • Verifies every received Round-1 package.
//!   • Produces one Round-2 package per OTHER participant (unicast).
//!   ⚠ Round-2 packages MUST travel on confidential + authenticated channels.
//!
//! Part 3 — each participant, after receiving its Round-2 packages:
//!   • Derives its own long-term key share (KeyPackage).
//!   • Derives the shared group public key (identical for all).
//!   • The full group secret key is NEVER assembled anywhere.
//! ```
//!
//! # Output compatibility
//!
//! `secp256k1_dkg_part3` returns `Secp256k1DkgParticipantOutput` containing a
//! `Secp256k1FrostParticipant` and `Secp256k1GroupKey` that are structurally
//! identical to those produced by `secp256k1_trusted_dealer_keygen`.
//! All existing signing/runtime infrastructure accepts them unchanged.
//!
//! # Identifier assignment
//!
//! The ceremony coordinator assigns FROST identifiers before Part 1:
//! `participant at position i in all_participant_ids → Identifier(i + 1)`

use crate::error::CryptoError;
use crate::frost_secp256k1_adapter::{Secp256k1FrostParticipant, Secp256k1GroupKey};
use frost_secp256k1_evm as frost;
use std::collections::{BTreeMap, HashMap};
use tls_attestation_core::ids::VerifierId;

pub use frost::Identifier;

use frost::keys::dkg as frost_dkg;

// ── Secret state wrappers ─────────────────────────────────────────────────────

/// Secret state held between `secp256k1_dkg_part1` and `secp256k1_dkg_part2`.
///
/// MUST NOT be transmitted to any other party.
pub struct Secp256k1DkgRound1State(frost_dkg::round1::SecretPackage);

/// Secret state held between `secp256k1_dkg_part2` and `secp256k1_dkg_part3`.
///
/// MUST NOT be transmitted to any other party.
pub struct Secp256k1DkgRound2State(frost_dkg::round2::SecretPackage);

// ── Wire package wrappers ─────────────────────────────────────────────────────

/// Round-1 broadcast package — sent to every other participant.
///
/// Public — safe to route through an untrusted coordinator.
#[derive(Clone, Debug)]
pub struct Secp256k1DkgRound1Package(pub(crate) frost_dkg::round1::Package);

impl Secp256k1DkgRound1Package {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0)
            .expect("Secp256k1DkgRound1Package serialization must not fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        serde_json::from_slice(bytes).map(Secp256k1DkgRound1Package).map_err(|e| {
            CryptoError::InvalidKeyMaterial(format!(
                "Secp256k1DkgRound1Package deserialization failed: {e}"
            ))
        })
    }
}

/// Round-2 unicast package — addressed to ONE specific recipient.
///
/// # ⚠ CONFIDENTIALITY REQUIREMENT (RFC 9591)
///
/// **MUST be routed on a confidential + authenticated channel.**
/// An adversary who reads this package learns partial information about the
/// recipient's key share.
#[derive(Clone, Debug)]
pub struct Secp256k1DkgRound2Package(pub(crate) frost_dkg::round2::Package);

impl Secp256k1DkgRound2Package {
    /// Serialize to plaintext bytes for in-process or already-encrypted use.
    ///
    /// # ⚠ Do NOT send over a network without encryption.
    /// Use `crate::dkg_encrypt` for authenticated network transmission.
    pub fn to_plaintext_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0)
            .expect("Secp256k1DkgRound2Package serialization must not fail")
    }

    /// Deserialize from plaintext bytes (in-process or post-decryption).
    pub fn from_plaintext_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        serde_json::from_slice(bytes).map(Secp256k1DkgRound2Package).map_err(|e| {
            CryptoError::InvalidKeyMaterial(format!(
                "Secp256k1DkgRound2Package deserialization failed: {e}"
            ))
        })
    }
}

// ── Output ────────────────────────────────────────────────────────────────────

/// Output of a completed Pedersen DKG ceremony for one participant.
///
/// Drop-in replacement for the per-participant view of `Secp256k1KeygenOutput`
/// from `secp256k1_trusted_dealer_keygen`, but **without a trusted dealer**.
pub struct Secp256k1DkgParticipantOutput {
    /// This participant's secret key share.
    pub participant: Secp256k1FrostParticipant,
    /// Shared group public key. Safe to share widely.
    pub group_key: Secp256k1GroupKey,
}

// ── Part 1 ────────────────────────────────────────────────────────────────────

/// Execute DKG Part 1 for one secp256k1 participant.
///
/// `identifier` must be unique within the ceremony:
/// `all_participant_ids[i]` → `Identifier::try_from(i + 1)`.
pub fn secp256k1_dkg_part1(
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
) -> Result<(Secp256k1DkgRound1State, Secp256k1DkgRound1Package), CryptoError> {
    use rand::rngs::OsRng;

    let (secret_pkg, round1_pkg) =
        frost_dkg::part1(identifier, max_signers, min_signers, OsRng)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("secp256k1 DKG part1 failed: {e}")))?;

    Ok((Secp256k1DkgRound1State(secret_pkg), Secp256k1DkgRound1Package(round1_pkg)))
}

// ── Part 2 ────────────────────────────────────────────────────────────────────

/// Execute DKG Part 2 for one secp256k1 participant.
///
/// `round1_packages` must contain exactly one entry per OTHER participant.
/// Returns one `Secp256k1DkgRound2Package` per other participant — each MUST
/// be sent on a confidential + authenticated channel.
pub fn secp256k1_dkg_part2(
    round1_state: Secp256k1DkgRound1State,
    round1_packages: &BTreeMap<Identifier, Secp256k1DkgRound1Package>,
) -> Result<
    (Secp256k1DkgRound2State, BTreeMap<Identifier, Secp256k1DkgRound2Package>),
    CryptoError,
> {
    let inner_r1: BTreeMap<Identifier, frost_dkg::round1::Package> =
        round1_packages.iter().map(|(id, pkg)| (*id, pkg.0.clone())).collect();

    let (round2_secret, outbound) =
        frost_dkg::part2(round1_state.0, &inner_r1)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("secp256k1 DKG part2 failed: {e}")))?;

    let wrapped = outbound
        .into_iter()
        .map(|(id, pkg)| (id, Secp256k1DkgRound2Package(pkg)))
        .collect();

    Ok((Secp256k1DkgRound2State(round2_secret), wrapped))
}

// ── Part 3 ────────────────────────────────────────────────────────────────────

/// Execute DKG Part 3 (final) for one secp256k1 participant.
///
/// Derives the participant's long-term key share and the group public key.
///
/// `all_verifier_ids_in_order` must be the same ordered list used by every
/// participant — it determines the `VerifierId → Identifier` mapping.
pub fn secp256k1_dkg_part3(
    my_verifier_id: &VerifierId,
    my_identifier: Identifier,
    round2_state: &Secp256k1DkgRound2State,
    round1_packages: &BTreeMap<Identifier, Secp256k1DkgRound1Package>,
    round2_packages: &BTreeMap<Identifier, Secp256k1DkgRound2Package>,
    all_verifier_ids_in_order: &[VerifierId],
) -> Result<Secp256k1DkgParticipantOutput, CryptoError> {
    let inner_r1: BTreeMap<Identifier, frost_dkg::round1::Package> =
        round1_packages.iter().map(|(id, pkg)| (*id, pkg.0.clone())).collect();

    let inner_r2: BTreeMap<Identifier, frost_dkg::round2::Package> =
        round2_packages.iter().map(|(id, pkg)| (*id, pkg.0.clone())).collect();

    let (key_package, pub_key_package) =
        frost_dkg::part3(&round2_state.0, &inner_r1, &inner_r2)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("secp256k1 DKG part3 failed: {e}")))?;

    // Build the VerifierId → Identifier mapping.
    let identifiers: Vec<Identifier> = {
        let mut v: Vec<Identifier> = inner_r1.keys().cloned().collect();
        v.push(my_identifier);
        v.sort();
        v
    };

    let mut verifier_to_id: HashMap<VerifierId, Identifier> = HashMap::new();
    for (i, vid) in all_verifier_ids_in_order.iter().enumerate() {
        if let Some(&id) = identifiers.get(i) {
            verifier_to_id.insert(vid.clone(), id);
        }
    }

    let group_key = Secp256k1GroupKey::new_from_parts(pub_key_package, verifier_to_id);
    // Build a SecretShare from the KeyPackage fields for the participant constructor.
    // We pass the KeyPackage directly via from_key_package (see below).
    let participant =
        Secp256k1FrostParticipant::from_key_package(key_package, my_verifier_id.clone())?;

    Ok(Secp256k1DkgParticipantOutput { participant, group_key })
}

// ── Ceremony orchestrator (in-process, for tests) ─────────────────────────────

/// Run a full Pedersen DKG ceremony in-process (for tests and integration).
///
/// Returns one `Secp256k1DkgParticipantOutput` per participant, all sharing
/// the same `Secp256k1GroupKey` (the group public key).
///
/// In production, participants run on separate machines. The `round1` packages
/// are broadcast; the `round2` packages are unicasted on encrypted channels.
pub fn run_secp256k1_dkg(
    verifier_ids: &[VerifierId],
    threshold: usize,
) -> Result<Vec<Secp256k1DkgParticipantOutput>, CryptoError> {
    let n = verifier_ids.len() as u16;
    let t = threshold as u16;

    // Assign identifiers: position i → Identifier(i+1).
    let identifiers: Vec<Identifier> = (1..=n as u16)
        .map(|i| Identifier::try_from(i).expect("valid identifier"))
        .collect();

    // Part 1: all participants generate their Round-1 packages.
    let mut round1_states: Vec<Secp256k1DkgRound1State> = Vec::new();
    let mut round1_packages_map: BTreeMap<Identifier, Secp256k1DkgRound1Package> = BTreeMap::new();

    for &id in &identifiers {
        let (state, pkg) = secp256k1_dkg_part1(id, n, t)?;
        round1_states.push(state);
        round1_packages_map.insert(id, pkg);
    }

    // Part 2: each participant processes others' Round-1 packages.
    let mut round2_states: Vec<Secp256k1DkgRound2State> = Vec::new();
    // round2_outbound[sender_idx][recipient_id] = package
    let mut round2_outbound: Vec<BTreeMap<Identifier, Secp256k1DkgRound2Package>> = Vec::new();

    for (i, state) in round1_states.into_iter().enumerate() {
        let my_id = identifiers[i];
        let others: BTreeMap<_, _> = round1_packages_map
            .iter()
            .filter(|(id, _)| **id != my_id)
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();
        let (r2_state, outbound) = secp256k1_dkg_part2(state, &others)?;
        round2_states.push(r2_state);
        round2_outbound.push(outbound);
    }

    // Part 3: each participant collects Round-2 packages addressed to it.
    let mut outputs: Vec<Secp256k1DkgParticipantOutput> = Vec::new();

    for (i, r2_state) in round2_states.iter().enumerate() {
        let my_id = identifiers[i];
        let my_vid = &verifier_ids[i];

        // Collect Round-2 packages from all OTHER participants addressed to me.
        let mut inbound_r2: BTreeMap<Identifier, Secp256k1DkgRound2Package> = BTreeMap::new();
        for (j, outbound) in round2_outbound.iter().enumerate() {
            if j == i {
                continue;
            }
            let sender_id = identifiers[j];
            if let Some(pkg) = outbound.get(&my_id) {
                inbound_r2.insert(sender_id, pkg.clone());
            }
        }

        // Round-1 packages from all OTHER participants.
        let others_r1: BTreeMap<_, _> = round1_packages_map
            .iter()
            .filter(|(id, _)| **id != my_id)
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();

        let output = secp256k1_dkg_part3(
            my_vid,
            my_id,
            r2_state,
            &others_r1,
            &inbound_r2,
            verifier_ids,
        )?;

        outputs.push(output);
    }

    Ok(outputs)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput};
    use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};

    fn vids(n: usize) -> Vec<VerifierId> {
        (0..n as u8).map(|i| VerifierId::from_bytes([i; 32])).collect()
    }

    #[test]
    fn dkg_2of3_produces_valid_group_key() {
        let ids = vids(3);
        let outputs = run_secp256k1_dkg(&ids, 2).unwrap();

        assert_eq!(outputs.len(), 3);

        // All participants must have the same group verifying key.
        let gk0 = outputs[0].group_key.verifying_key_bytes();
        for out in &outputs[1..] {
            assert_eq!(
                out.group_key.verifying_key_bytes(),
                gk0,
                "group key must be identical across all participants"
            );
        }

        println!("DKG 2-of-3 group key: {}", hex::encode(gk0));
    }

    #[test]
    fn dkg_then_dvrf_2of3() {
        let ids = vids(3);
        let outputs = run_secp256k1_dkg(&ids, 2).unwrap();

        let input = Secp256k1DvrfInput::new(DigestBytes::from_bytes([0x42u8; 32]));
        let participants: Vec<_> = outputs.iter().map(|o| &o.participant).collect();
        let group_key = &outputs[0].group_key;

        // Use first 2 participants (threshold).
        let pes: Vec<_> = participants[..2]
            .iter()
            .map(|p| Secp256k1Dvrf::partial_eval(p, &input).unwrap())
            .collect();

        let dvrf_output = Secp256k1Dvrf::combine(group_key, &input, pes, &participants[..2]).unwrap();
        Secp256k1Dvrf::verify(&input, &dvrf_output).unwrap();

        println!("DKG + DVRF 2-of-3 rand: {}", dvrf_output.rand.to_hex());
    }

    #[test]
    fn dkg_3of5_signing() {
        let ids = vids(5);
        let outputs = run_secp256k1_dkg(&ids, 3).unwrap();

        use crate::frost_secp256k1_adapter::{
            secp256k1_aggregate_signature_shares, secp256k1_build_signing_package,
            secp256k1_verify_approval,
        };
        use rand::rngs::OsRng;

        let message = DigestBytes::from_bytes([0xBEu8; 32]);
        let mut rng = OsRng;

        let nc: Vec<_> = outputs[..3]
            .iter()
            .map(|o| o.participant.round1(&mut rng).unwrap())
            .collect();
        let (nonces, commits): (Vec<_>, Vec<_>) = nc.into_iter().unzip();
        let pkg = secp256k1_build_signing_package(&commits, &message).unwrap();
        let shares: Vec<_> = outputs[..3]
            .iter()
            .zip(nonces)
            .map(|(o, n)| o.participant.round2(&pkg, n).unwrap())
            .collect();
        let approval =
            secp256k1_aggregate_signature_shares(&pkg, &shares, &outputs[0].group_key).unwrap();
        secp256k1_verify_approval(&approval, &message).unwrap();
        println!("DKG 3-of-5 signing OK");
    }
}