//! Deterministic test fixtures for the attestation protocol.
//!
//! The `TestHarness` wires together coordinator + aux verifiers + storage
//! with deterministic key material so tests are fully reproducible.

use std::collections::HashMap;
use tls_attestation_attestation::engine::PrototypeAttestationEngine;
use tls_attestation_core::{
    ids::VerifierId,
    types::{Epoch, QuorumSpec},
};
use tls_attestation_crypto::{
    randomness::PrototypeDvrf,
    threshold::{PrototypeThresholdSigner, VerifierKeyPair},
};
use tls_attestation_node::{
    auxiliary::AuxiliaryVerifierNode,
    coordinator::{CoordinatorConfig, CoordinatorNode},
};
use tls_attestation_storage::memory::InMemorySessionStore;
use tls_attestation_attestation::verify::VerificationPolicy;

/// Configuration for the test harness.
pub struct TestHarnessConfig {
    pub num_aux_verifiers: usize,
    pub threshold: usize,
    pub ttl_secs: u64,
}

impl Default for TestHarnessConfig {
    fn default() -> Self {
        Self {
            num_aux_verifiers: 3,
            threshold: 2,
            ttl_secs: 3600,
        }
    }
}

/// A fully wired test harness with deterministic key material.
///
/// Coordinator seed: [0u8; 32]
/// Aux verifier seeds: [1u8; 32], [2u8; 32], ..., [n; 32]
pub struct TestHarness {
    pub coordinator: CoordinatorNode<InMemorySessionStore, PrototypeDvrf, PrototypeAttestationEngine>,
    pub aux_nodes: Vec<AuxiliaryVerifierNode>,
    /// The quorum used for this harness (aux verifier IDs + threshold).
    ///
    /// Stored separately so tests can pass the exact quorum verifier IDs to
    /// out-of-band operations (e.g. FROST keygen) without accessing
    /// `CoordinatorNode`'s private config.
    quorum: tls_attestation_core::types::QuorumSpec,
}

impl TestHarness {
    pub fn new(config: TestHarnessConfig) -> Self {
        assert!(config.num_aux_verifiers <= 254, "max 254 aux verifiers");

        // Coordinator key pair (seed 0).
        let coordinator_kp = VerifierKeyPair::from_seed([0u8; 32]);
        let coordinator_id = coordinator_kp.verifier_id.clone();

        // Aux verifier key pairs (seeds 1..=n).
        let aux_kps: Vec<VerifierKeyPair> = (1u8..=(config.num_aux_verifiers as u8))
            .map(|seed| VerifierKeyPair::from_seed([seed; 32]))
            .collect();

        let aux_ids: Vec<VerifierId> = aux_kps.iter().map(|kp| kp.verifier_id.clone()).collect();

        // Build quorum from aux verifier IDs.
        // Clone retained separately so FROST tests can access the verifier ID
        // order without going through the coordinator's private config.
        let quorum = QuorumSpec::new(aux_ids.clone(), config.threshold)
            .expect("invalid quorum in test harness config");
        let quorum_for_harness = quorum.clone();

        // Build DVRF secrets: each verifier uses their ID bytes as secret.
        // Deterministic and unique per verifier.
        let dvrf_secrets: HashMap<VerifierId, [u8; 32]> = aux_ids
            .iter()
            .map(|id| (id.clone(), *id.as_bytes()))
            .collect();

        // Also include coordinator in DVRF participants if desired.
        // For this harness, only aux verifiers participate in DVRF.
        let dvrf = PrototypeDvrf::new(dvrf_secrets);

        // Verifier public keys for approval verification.
        let verifier_public_keys: Vec<_> = aux_kps
            .iter()
            .map(|kp| (kp.verifier_id.clone(), kp.verifying_key()))
            .collect();

        let coord_config = CoordinatorConfig {
            coordinator_id: coordinator_id.clone(),
            epoch: Epoch::GENESIS,
            quorum,
            default_ttl_secs: config.ttl_secs,
            verifier_public_keys,
        };

        let coordinator = CoordinatorNode::new(
            coord_config,
            InMemorySessionStore::new(),
            dvrf,
            PrototypeAttestationEngine,
        );

        // Build aux verifier nodes.
        let aux_nodes: Vec<AuxiliaryVerifierNode> = aux_kps
            .into_iter()
            .map(|kp| {
                let signer = PrototypeThresholdSigner::new(kp);
                AuxiliaryVerifierNode::new(signer, VerificationPolicy::permissive())
            })
            .collect();

        Self {
            coordinator,
            aux_nodes,
            quorum: quorum_for_harness,
        }
    }

    /// Return references to aux nodes as `ThresholdSigner` trait objects.
    pub fn aux_signers(&self) -> Vec<&dyn tls_attestation_crypto::threshold::ThresholdSigner> {
        self.aux_nodes
            .iter()
            .map(|n| n as &dyn tls_attestation_crypto::threshold::ThresholdSigner)
            .collect()
    }

    /// Return the verifier IDs that form this harness's quorum, in the order
    /// they were registered at construction time.
    ///
    /// FROST keygen assigns identifiers in this exact order, so passing these
    /// IDs to `frost_trusted_dealer_keygen` produces participants whose
    /// `verifier_id` fields match the coordinator's `config.quorum.verifiers`.
    pub fn coordinator_quorum_verifiers(&self) -> Vec<tls_attestation_core::ids::VerifierId> {
        self.quorum.verifiers.clone()
    }
}
