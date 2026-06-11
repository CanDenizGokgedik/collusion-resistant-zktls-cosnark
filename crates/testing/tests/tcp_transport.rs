//! Layer 2 end-to-end tests: distributed FROST over real TCP loopback.
//!
//! These tests start real `TcpAuxServer` instances on ephemeral ports, connect
//! to them with `TcpNodeTransport`, and run the full FROST two-round signing
//! protocol over the local loopback interface. No mocking — actual TCP sockets,
//! real JSON serialization, and genuine FROST cryptography.
//!
//! # What this validates
//!
//! - `TcpAuxServer` correctly deserializes `NodeRequest::FrostRound1/2` from
//!   the wire, dispatches to `FrostAuxiliaryNode`, and sends back
//!   `NodeResponse::FrostRound1/2`.
//! - `TcpNodeTransport` correctly serializes requests and deserializes responses.
//! - `CoordinatorNode::attest_frost_distributed_over_transport` produces the
//!   same valid `FrostAttestationEnvelope` as the in-process path.
//! - `InProcessTransport` is a drop-in replacement — same coordinator method,
//!   same result, zero network overhead.
//!
//! # Build
//!
//! ```bash
//! cargo test --package tls-attestation-testing --features tcp --test tcp_transport
//! ```

#![cfg(feature = "tcp")]

use std::sync::Arc;
use std::time::Duration;

use tls_attestation_core::{ids::ProverId, types::Nonce};
use tls_attestation_crypto::frost_adapter::{frost_trusted_dealer_keygen, FrostGroupKey};
use tls_attestation_network::messages::AttestationRequest;
use tls_attestation_node::{FrostAuxiliaryNode, TcpAuxServer, TcpNodeTransport};
use tls_attestation_node::transport::{FrostNodeTransport, InProcessTransport};
use tls_attestation_testing::fixtures::{TestHarness, TestHarnessConfig};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_request(tag: &str, query: &[u8]) -> AttestationRequest {
    AttestationRequest {
        prover_id: ProverId::from_bytes([0xAAu8; 32]),
        client_nonce: Nonce::from_bytes([0xBBu8; 32]),
        statement_tag: tag.to_string(),
        query: query.to_vec(),
        requested_ttl_secs: 3600,
    }
}

/// Build harness + aux nodes + group key for n-of-n distributed tests.
fn setup(
    n: usize,
    threshold: usize,
) -> (TestHarness, Vec<FrostAuxiliaryNode>, FrostGroupKey) {
    let harness = TestHarness::new(TestHarnessConfig {
        num_aux_verifiers: n,
        threshold,
        ttl_secs: 3600,
    });
    let vids = harness.coordinator_quorum_verifiers();
    let keygen = frost_trusted_dealer_keygen(&vids, threshold)
        .expect("trusted-dealer keygen should succeed");

    let nodes: Vec<FrostAuxiliaryNode> = keygen
        .participants
        .into_iter()
        .map(FrostAuxiliaryNode::new)
        .collect();

    (harness, nodes, keygen.group_key)
}

// ── Happy-path TCP tests ──────────────────────────────────────────────────────

/// 2-of-3 FROST over TCP loopback — threshold signing.
#[test]
fn tcp_frost_2_of_3_succeeds() {
    let (harness, nodes, group_key) = setup(3, 2);

    // Start TCP servers for the first 2 nodes (we only need the threshold).
    let arc_nodes: Vec<Arc<FrostAuxiliaryNode>> = nodes.into_iter().map(Arc::new).collect();

    let servers: Vec<TcpAuxServer> = arc_nodes[..2]
        .iter()
        .map(|n| TcpAuxServer::bind("127.0.0.1:0", Arc::clone(n)).expect("bind failed"))
        .collect();

    // Build TcpNodeTransport for each server, using the correct verifier ID.
    let transports: Vec<TcpNodeTransport> = servers
        .iter()
        .zip(arc_nodes[..2].iter())
        .map(|(srv, node)| {
            TcpNodeTransport::new(node.verifier_id().clone(), srv.local_addr())
                .unwrap()
                .with_timeout(Duration::from_secs(10))
        })
        .collect();

    let transport_refs: Vec<&dyn FrostNodeTransport> =
        transports.iter().map(|t| t as &dyn FrostNodeTransport).collect();

    let request = make_request("tcp/v1", b"SELECT balance FROM accounts WHERE id = 42");
    let response = b"[{\"balance\": 1337}]";

    let envelope = harness
        .coordinator
        .attest_frost_distributed_over_transport(
            request,
            response,
            &transport_refs,
            &group_key,
        )
        .expect("TCP FROST attestation should succeed");

    // Verify the aggregate Schnorr signature.
    envelope.frost_approval.verify_signature().expect("signature must be valid");
    envelope
        .frost_approval
        .verify_binding(&envelope.envelope_digest)
        .expect("approval must be bound to envelope");

    // Envelope digest must be non-zero.
    assert_ne!(
        envelope.envelope_digest,
        tls_attestation_core::hash::DigestBytes::ZERO
    );

    // Shut down servers cleanly.
    for srv in &servers {
        srv.shutdown();
    }
}

/// 3-of-3 FROST over TCP — all nodes must participate.
#[test]
fn tcp_frost_3_of_3_succeeds() {
    let (harness, nodes, group_key) = setup(3, 3);

    let arc_nodes: Vec<Arc<FrostAuxiliaryNode>> = nodes.into_iter().map(Arc::new).collect();

    let servers: Vec<TcpAuxServer> = arc_nodes
        .iter()
        .map(|n| TcpAuxServer::bind("127.0.0.1:0", Arc::clone(n)).expect("bind failed"))
        .collect();

    let transports: Vec<TcpNodeTransport> = servers
        .iter()
        .zip(arc_nodes.iter())
        .map(|(srv, node)| {
            TcpNodeTransport::new(node.verifier_id().clone(), srv.local_addr())
                .unwrap()
                .with_timeout(Duration::from_secs(10))
        })
        .collect();

    let transport_refs: Vec<&dyn FrostNodeTransport> =
        transports.iter().map(|t| t as &dyn FrostNodeTransport).collect();

    let envelope = harness
        .coordinator
        .attest_frost_distributed_over_transport(
            make_request("tcp/v1", b"query"),
            b"response",
            &transport_refs,
            &group_key,
        )
        .expect("3-of-3 TCP FROST should succeed");

    envelope.frost_approval.verify_signature().expect("valid signature");

    for srv in &servers {
        srv.shutdown();
    }
}

// ── InProcessTransport parity tests ──────────────────────────────────────────

/// `InProcessTransport` must produce identical structural results to the TCP path.
#[test]
fn in_process_transport_produces_valid_envelope() {
    let (harness, nodes, group_key) = setup(3, 2);

    // Use InProcessTransport — no servers, no network.
    let transports: Vec<InProcessTransport<'_>> =
        nodes[..2].iter().map(InProcessTransport::new).collect();

    let transport_refs: Vec<&dyn FrostNodeTransport> =
        transports.iter().map(|t| t as &dyn FrostNodeTransport).collect();

    let envelope = harness
        .coordinator
        .attest_frost_distributed_over_transport(
            make_request("inproc/v1", b"SELECT * FROM logs"),
            b"[]",
            &transport_refs,
            &group_key,
        )
        .expect("in-process transport should succeed");

    envelope.frost_approval.verify_signature().expect("valid signature");
    envelope
        .frost_approval
        .verify_binding(&envelope.envelope_digest)
        .expect("valid binding");
}

// ── Error path tests ──────────────────────────────────────────────────────────

/// Quorum not met: coordinator has fewer transports than threshold.
#[test]
fn tcp_frost_quorum_not_met_returns_error() {
    let (harness, nodes, group_key) = setup(3, 2);

    let arc_nodes: Vec<Arc<FrostAuxiliaryNode>> = nodes.into_iter().map(Arc::new).collect();

    let server =
        TcpAuxServer::bind("127.0.0.1:0", Arc::clone(&arc_nodes[0])).expect("bind failed");

    // Only 1 transport, but threshold is 2.
    let transport = TcpNodeTransport::new(arc_nodes[0].verifier_id().clone(), server.local_addr())
        .unwrap()
        .with_timeout(Duration::from_secs(10));

    let transport_refs: Vec<&dyn FrostNodeTransport> =
        vec![&transport as &dyn FrostNodeTransport];

    let result = harness.coordinator.attest_frost_distributed_over_transport(
        make_request("qcheck", b"q"),
        b"r",
        &transport_refs,
        &group_key,
    );

    assert!(
        matches!(
            result,
            Err(tls_attestation_node::NodeError::QuorumNotMet { .. })
        ),
        "expected QuorumNotMet, got: {result:?}"
    );

    server.shutdown();
}

/// TCP transport with wrong verifier ID produces a FROST protocol error
/// (the node rejects Round 1 because the impersonated verifier is not in the signer set).
#[test]
fn tcp_wrong_verifier_id_rejected_in_round1() {
    let (harness, nodes, group_key) = setup(3, 2);

    let arc_nodes: Vec<Arc<FrostAuxiliaryNode>> = nodes.into_iter().map(Arc::new).collect();

    let servers: Vec<TcpAuxServer> = arc_nodes[..2]
        .iter()
        .map(|n| TcpAuxServer::bind("127.0.0.1:0", Arc::clone(n)).expect("bind"))
        .collect();

    // First transport has the correct verifier ID for node 0.
    // Second transport uses node 0's verifier ID but connects to node 1's server.
    // Node 1 will reject because the wrong verifier ID appears twice in the signer set.
    let t0 = TcpNodeTransport::new(
        arc_nodes[0].verifier_id().clone(),
        servers[0].local_addr(),
    )
    .unwrap()
    .with_timeout(Duration::from_secs(5));

    let t1_wrong_id = TcpNodeTransport::new(
        arc_nodes[0].verifier_id().clone(), // deliberately wrong — node 1's ID
        servers[1].local_addr(),
    )
    .unwrap()
    .with_timeout(Duration::from_secs(5));

    let transport_refs: Vec<&dyn FrostNodeTransport> = vec![&t0, &t1_wrong_id];

    let result = harness.coordinator.attest_frost_distributed_over_transport(
        make_request("badid", b"q"),
        b"r",
        &transport_refs,
        &group_key,
    );

    assert!(result.is_err(), "mismatched verifier ID should be rejected");

    for srv in &servers {
        srv.shutdown();
    }
}

// ── Codec-level tests ─────────────────────────────────────────────────────────

/// Verify that the codec handles multiple sequential connections on the same server.
///
/// A real deployment makes one connection per round — the server must handle
/// many short-lived connections without state bleed.
#[test]
fn tcp_server_handles_multiple_sequential_connections() {
    let (harness, nodes, group_key) = setup(3, 2);
    let arc_nodes: Vec<Arc<FrostAuxiliaryNode>> = nodes.into_iter().map(Arc::new).collect();

    let servers: Vec<TcpAuxServer> = arc_nodes[..2]
        .iter()
        .map(|n| TcpAuxServer::bind("127.0.0.1:0", Arc::clone(n)).expect("bind"))
        .collect();

    let transports: Vec<TcpNodeTransport> = servers
        .iter()
        .zip(arc_nodes[..2].iter())
        .map(|(srv, node)| {
            TcpNodeTransport::new(node.verifier_id().clone(), srv.local_addr())
                .unwrap()
                .with_timeout(Duration::from_secs(10))
        })
        .collect();

    let transport_refs: Vec<&dyn FrostNodeTransport> =
        transports.iter().map(|t| t as &dyn FrostNodeTransport).collect();

    // Run two attestations sequentially on the same servers.
    for i in 0..2u8 {
        let query = format!("SELECT * FROM table_{i}");
        let envelope = harness
            .coordinator
            .attest_frost_distributed_over_transport(
                make_request("seq", query.as_bytes()),
                b"rows",
                &transport_refs,
                &group_key,
            )
            .expect("sequential attestation should succeed");

        envelope.frost_approval.verify_signature().unwrap();
    }

    for srv in &servers {
        srv.shutdown();
    }
}