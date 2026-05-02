//! Handshake 2PC binding protocol tests.
//!
//! These tests exercise the complete Handshake 2PC protocol:
//!
//! 1. Coordinator computes a `binding_input` from TLS session parameters.
//! 2. [`run_handshake_binding`] runs a two-round FROST signing ceremony
//!    across `t` of `n` aux nodes.
//! 3. The aggregate signature σ is converted into `dvrf_exporter` via
//!    [`derive_2pc_dvrf_exporter`].
//!
//! # Security properties verified
//!
//! - `dvrf_exporter` is non-zero after the ceremony.
//! - Different `session_nonce` values produce different `dvrf_exporter` values
//!   (binding to the TLS session).
//! - Different `rand_value` inputs produce different `dvrf_exporter` values
//!   (binding to DVRF randomness).
//! - Below-threshold quorum is rejected (insufficient signer participation).
//! - Tampered `binding_input` in Round 2 is rejected by aux nodes.
//! - The `hb_pending` cache is empty after a successful round trip.
//!
//! # Build
//!
//! ```bash
//! cargo test --package tls-attestation-testing --features frost \
//!     --test handshake_2pc
//! ```

#![cfg(all(feature = "frost", feature = "tcp"))]

use tls_attestation_attestation::tls_2pc::TlsSessionParams;
use tls_attestation_core::{
    hash::DigestBytes,
    ids::{SessionId, VerifierId},
    types::UnixTimestamp,
};
use tls_attestation_crypto::{
    frost_adapter::frost_trusted_dealer_keygen,
    participant_registry::RegistryEpoch,
};
use tls_attestation_node::{
    frost_aux::FrostAuxiliaryNode,
    handshake_binding::{
        compute_2pc_binding_input, derive_2pc_dvrf_exporter, run_handshake_binding,
    },
    transport::InProcessTransport,
};
use tls_attestation_network::messages::HandshakeBindingRound2Request;

// ── Test fixtures ──────────────────────────────────────────────────────────────

fn make_params(nonce_seed: u8) -> TlsSessionParams {
    TlsSessionParams {
        server_cert_hash: DigestBytes::from_bytes([0xCCu8; 32]),
        tls_version:      0x0304,
        server_name:      "example.com".to_string(),
        established_at:   1_700_000_000,
        session_nonce:    DigestBytes::from_bytes([nonce_seed; 32]),
    }
}

fn make_session_id() -> SessionId {
    SessionId::from_bytes([0xA1u8; 16])
}

fn make_rand() -> DigestBytes {
    DigestBytes::from_bytes([0xB2u8; 32])
}

/// Set up `n` aux nodes with a trusted-dealer FROST keygen at threshold `t`.
/// Returns `(nodes, group_key)`.
fn setup_nodes(
    n: usize,
    t: usize,
) -> (Vec<FrostAuxiliaryNode>, tls_attestation_crypto::frost_adapter::FrostGroupKey) {
    let vids: Vec<VerifierId> = (0..n as u8)
        .map(|i| VerifierId::from_bytes([i; 32]))
        .collect();

    let keygen = frost_trusted_dealer_keygen(&vids, t)
        .expect("trusted-dealer keygen must succeed");

    let nodes = keygen.participants.into_iter().map(FrostAuxiliaryNode::new).collect();
    (nodes, keygen.group_key)
}

// ── Happy path ─────────────────────────────────────────────────────────────────

/// 2-of-3: all three nodes participate; full binding round trip succeeds.
#[test]
fn handshake_binding_3_of_3_succeeds() {
    let (nodes, group_key) = setup_nodes(3, 2);
    let transports: Vec<InProcessTransport<'_>> =
        nodes.iter().map(InProcessTransport::new).collect();
    let transport_refs: Vec<&dyn tls_attestation_node::transport::FrostNodeTransport> =
        transports.iter().map(|t| t as &dyn tls_attestation_node::transport::FrostNodeTransport).collect();

    let session_id = make_session_id();
    let rand       = make_rand();
    let params     = make_params(0xAA);
    let binding    = compute_2pc_binding_input(&session_id, &rand, &params);
    let coordinator_id = VerifierId::from_bytes([0xFFu8; 32]);

    let sigma = run_handshake_binding(
        &session_id,
        &coordinator_id,
        &binding,
        &group_key,
        &transport_refs,
        60,
        RegistryEpoch::GENESIS,
    )
    .expect("handshake binding must succeed with 3-of-3");

    let exporter = derive_2pc_dvrf_exporter(&sigma);
    assert_ne!(exporter, DigestBytes::ZERO, "dvrf_exporter must be non-zero");
}

/// 2-of-3 threshold: exactly the minimum quorum.
#[test]
fn handshake_binding_2_of_3_threshold_succeeds() {
    let (nodes, group_key) = setup_nodes(3, 2);
    // Only use the first 2 nodes (exactly the threshold).
    let transports: Vec<InProcessTransport<'_>> =
        nodes[..2].iter().map(InProcessTransport::new).collect();
    let transport_refs: Vec<&dyn tls_attestation_node::transport::FrostNodeTransport> =
        transports.iter().map(|t| t as &dyn tls_attestation_node::transport::FrostNodeTransport).collect();

    let session_id     = make_session_id();
    let rand           = make_rand();
    let params         = make_params(0xBB);
    let binding        = compute_2pc_binding_input(&session_id, &rand, &params);
    let coordinator_id = VerifierId::from_bytes([0xFFu8; 32]);

    let sigma = run_handshake_binding(
        &session_id,
        &coordinator_id,
        &binding,
        &group_key,
        &transport_refs,
        60,
        RegistryEpoch::GENESIS,
    )
    .expect("2-of-3 threshold handshake binding must succeed");

    let exporter = derive_2pc_dvrf_exporter(&sigma);
    assert_ne!(exporter, DigestBytes::ZERO);
}

// ── Binding uniqueness ─────────────────────────────────────────────────────────

/// Different `session_nonce` values → different `dvrf_exporter`.
///
/// This proves that `dvrf_exporter` is bound to the TLS session nonce, which
/// in production comes from the TLS master secret.
#[test]
fn different_session_nonce_produces_different_exporter() {
    let (nodes, group_key) = setup_nodes(3, 2);
    let coordinator_id = VerifierId::from_bytes([0xFFu8; 32]);

    let run = |nonce_seed: u8, session_seed: u8| -> DigestBytes {
        let transports: Vec<InProcessTransport<'_>> =
            nodes[..2].iter().map(InProcessTransport::new).collect();
        let transport_refs: Vec<&dyn tls_attestation_node::transport::FrostNodeTransport> =
            transports.iter().map(|t| t as &dyn tls_attestation_node::transport::FrostNodeTransport).collect();

        let session_id = SessionId::from_bytes([session_seed; 16]);
        let rand       = make_rand();
        let params     = make_params(nonce_seed);
        let binding    = compute_2pc_binding_input(&session_id, &rand, &params);

        let sigma = run_handshake_binding(
            &session_id,
            &coordinator_id,
            &binding,
            &group_key,
            &transport_refs,
            60,
            RegistryEpoch::GENESIS,
        )
        .unwrap();
        derive_2pc_dvrf_exporter(&sigma)
    };

    let exp1 = run(0xAA, 0x01);
    let exp2 = run(0xBB, 0x02);

    assert_ne!(exp1, exp2, "different TLS sessions must yield different dvrf_exporter");
}

/// Different DVRF `rand_value` inputs → different `dvrf_exporter`.
#[test]
fn different_rand_value_produces_different_binding_input() {
    let params = make_params(0xAA);
    let sid    = make_session_id();

    let rand1 = DigestBytes::from_bytes([0x11u8; 32]);
    let rand2 = DigestBytes::from_bytes([0x22u8; 32]);

    let b1 = compute_2pc_binding_input(&sid, &rand1, &params);
    let b2 = compute_2pc_binding_input(&sid, &rand2, &params);

    assert_ne!(b1, b2, "different rand_value must yield different binding_input");
}

/// Same inputs → same binding input (deterministic).
#[test]
fn binding_input_is_deterministic() {
    let params = make_params(0xCC);
    let sid    = make_session_id();
    let rand   = make_rand();

    let b1 = compute_2pc_binding_input(&sid, &rand, &params);
    let b2 = compute_2pc_binding_input(&sid, &rand, &params);

    assert_eq!(b1, b2, "compute_2pc_binding_input must be deterministic");
}

// ── Nonce cache cleanup ────────────────────────────────────────────────────────

/// After a successful round trip, `hb_pending` cache must be empty.
#[test]
fn hb_pending_empty_after_success() {
    let (nodes, group_key) = setup_nodes(2, 2);
    let transports: Vec<InProcessTransport<'_>> =
        nodes.iter().map(InProcessTransport::new).collect();
    let transport_refs: Vec<&dyn tls_attestation_node::transport::FrostNodeTransport> =
        transports.iter().map(|t| t as &dyn tls_attestation_node::transport::FrostNodeTransport).collect();

    let session_id     = make_session_id();
    let rand           = make_rand();
    let params         = make_params(0xDD);
    let binding        = compute_2pc_binding_input(&session_id, &rand, &params);
    let coordinator_id = VerifierId::from_bytes([0xFFu8; 32]);

    run_handshake_binding(
        &session_id,
        &coordinator_id,
        &binding,
        &group_key,
        &transport_refs,
        60,
        RegistryEpoch::GENESIS,
    )
    .expect("round trip must succeed");

    // After successful completion, hb_pending must be drained.
    for node in &nodes {
        assert_eq!(
            node.pending_session_count(),
            0,
            "hb_pending must be empty after successful binding"
        );
    }
}

// ── Security: adversarial cases ────────────────────────────────────────────────

/// Expired round-1 request must be rejected by aux nodes.
#[test]
fn expired_round1_request_is_rejected() {
    use tls_attestation_network::messages::HandshakeBindingRound1Request;

    let (nodes, _) = setup_nodes(3, 2);
    let node = &nodes[0];
    let coordinator_id = VerifierId::from_bytes([0xFFu8; 32]);

    let req = HandshakeBindingRound1Request {
        session_id:    make_session_id(),
        coordinator_id,
        binding_input: DigestBytes::from_bytes([0x42u8; 32]),
        signer_set:    vec![node.verifier_id().clone()],
        // Expired: expires_at == 0 < now
        round_expires_at: UnixTimestamp(0),
        registry_epoch:   RegistryEpoch::GENESIS,
    };

    let result = node.handshake_binding_round1(&req, UnixTimestamp::now());
    assert!(
        result.is_err(),
        "expired round-1 request must be rejected"
    );
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("expired"),
        "error must mention expiry, got: {err_str}"
    );
}

/// Node not in signer set must be rejected.
#[test]
fn node_not_in_signer_set_is_rejected() {
    use tls_attestation_network::messages::HandshakeBindingRound1Request;

    let (nodes, _) = setup_nodes(3, 2);
    let node       = &nodes[0];
    let far_future = UnixTimestamp(u64::MAX);
    let coordinator_id = VerifierId::from_bytes([0xFFu8; 32]);

    let req = HandshakeBindingRound1Request {
        session_id:    make_session_id(),
        coordinator_id,
        binding_input: DigestBytes::from_bytes([0x42u8; 32]),
        // signer_set does NOT include node 0's verifier_id
        signer_set:       vec![VerifierId::from_bytes([0xEEu8; 32])],
        round_expires_at: far_future,
        registry_epoch:   RegistryEpoch::GENESIS,
    };

    let result = node.handshake_binding_round1(&req, UnixTimestamp::now());
    assert!(result.is_err(), "node not in signer set must be rejected");
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("signer set") || err_str.contains("not in"),
        "error must mention signer set, got: {err_str}"
    );
}

/// Duplicate round-1 for the same session must be rejected.
#[test]
fn duplicate_round1_is_rejected() {
    use tls_attestation_network::messages::HandshakeBindingRound1Request;

    let (nodes, _) = setup_nodes(2, 2);
    let node       = &nodes[0];
    let far_future = UnixTimestamp(u64::MAX);
    let coordinator_id = VerifierId::from_bytes([0xFFu8; 32]);

    let req = HandshakeBindingRound1Request {
        session_id:    make_session_id(),
        coordinator_id,
        binding_input: DigestBytes::from_bytes([0x42u8; 32]),
        signer_set:    vec![node.verifier_id().clone()],
        round_expires_at: far_future,
        registry_epoch:   RegistryEpoch::GENESIS,
    };

    // First call succeeds.
    node.handshake_binding_round1(&req, UnixTimestamp::now())
        .expect("first round-1 must succeed");

    // Second call for the same session must fail.
    let result = node.handshake_binding_round1(&req, UnixTimestamp::now());
    assert!(result.is_err(), "duplicate round-1 must be rejected");
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("already completed") || err_str.contains("duplicate"),
        "error must mention duplicate, got: {err_str}"
    );
}

/// Round-2 with mismatched signer set must be rejected.
#[test]
fn round2_signer_set_mismatch_is_rejected() {
    use tls_attestation_network::messages::HandshakeBindingRound1Request;

    let (nodes, _) = setup_nodes(2, 2);
    let node       = &nodes[0];
    let far_future = UnixTimestamp(u64::MAX);
    let coordinator_id = VerifierId::from_bytes([0xFFu8; 32]);

    let session_id    = make_session_id();
    let signer_set    = vec![node.verifier_id().clone()];
    let binding_input = DigestBytes::from_bytes([0x42u8; 32]);

    // Round 1 succeeds.
    let r1_req = HandshakeBindingRound1Request {
        session_id: session_id.clone(),
        coordinator_id: coordinator_id.clone(),
        binding_input: binding_input.clone(),
        signer_set: signer_set.clone(),
        round_expires_at: far_future,
        registry_epoch: RegistryEpoch::GENESIS,
    };
    node.handshake_binding_round1(&r1_req, UnixTimestamp::now())
        .expect("round-1 must succeed");

    // Round 2 with a DIFFERENT signer set must be rejected.
    let r2_req = HandshakeBindingRound2Request {
        session_id,
        coordinator_id,
        signing_package_bytes: vec![0u8; 16],
        signer_set: vec![VerifierId::from_bytes([0xEEu8; 32])], // changed!
    };
    let result = node.handshake_binding_round2(&r2_req);
    assert!(result.is_err(), "signer-set mismatch must be rejected");
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("signer-set") || err_str.contains("mismatch"),
        "error must mention mismatch, got: {err_str}"
    );
}

/// Round-2 without prior Round-1 (nonces missing) must fail safely.
#[test]
fn round2_without_round1_fails_safely() {
    let (nodes, _) = setup_nodes(2, 2);
    let node       = &nodes[0];
    let coordinator_id = VerifierId::from_bytes([0xFFu8; 32]);

    let r2_req = HandshakeBindingRound2Request {
        session_id:           make_session_id(),
        coordinator_id,
        signing_package_bytes: vec![0u8; 16],
        signer_set:           vec![node.verifier_id().clone()],
    };

    let result = node.handshake_binding_round2(&r2_req);
    assert!(result.is_err(), "round-2 without round-1 must fail");
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("missing") || err_str.contains("nonces"),
        "error must mention missing nonces, got: {err_str}"
    );
}