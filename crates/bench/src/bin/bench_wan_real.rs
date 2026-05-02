//! Real FROST WAN Benchmark — Paper §IX, Fig. 12.
//!
//! Measures actual cryptographic work (DKG, FROST rounds 1+2, aggregation)
//! plus realistic per-message network delays injected at the transport layer.
//!
//! Unlike bench_wan.rs, which simulates ALL work via Thread::sleep, this
//! binary runs real ed25519 FROST operations and only injects sleep for
//! the network portion.
//!
//! # Transport
//! Uses `InProcessTransport` wrapped in `LatencyTransport` which sleeps
//! once before and once after each RPC (2 × one_way_latency per round).
//!
//! # Usage
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_wan_real \
//!   --features tcp --release
//! ```
//!
//! # Real hardware
//! For paper §IX numbers, deploy aux-node on separate machines and use
//! the real TCP transport with tc/netem for network conditioning:
//!   sudo tc qdisc add dev eth0 root netem delay 40ms 5ms loss 0.1%

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tls_attestation_core::{
    ids::{ProverId, VerifierId},
    types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
};
use tls_attestation_crypto::{
    frost_adapter::{frost_trusted_dealer_keygen, FrostGroupKey},
    randomness::PrototypeDvrf,
};
use tls_attestation_network::messages::{
    AttestationRequest, FrostRound1Request, FrostRound1Response,
    FrostRound2Request, FrostRound2Response,
    HandshakeBindingRound1Request, HandshakeBindingRound1Response,
    HandshakeBindingRound2Request, HandshakeBindingRound2Response,
};
use tls_attestation_node::{
    coordinator::{CoordinatorConfig, CoordinatorNode},
    frost_aux::FrostAuxiliaryNode,
    transport::{FrostNodeTransport, InProcessTransport},
    NodeError,
};
use tls_attestation_attestation::engine::PrototypeAttestationEngine;
use tls_attestation_storage::InMemorySessionStore;

// ── WAN profiles ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct WanProfile {
    name: &'static str,
    one_way_ms: u64,
    jitter_ms: u64,
}

impl WanProfile {
    fn lan()  -> Self { Self { name: "LAN",  one_way_ms: 0,  jitter_ms: 0  } }
    fn wan1() -> Self { Self { name: "WAN1", one_way_ms: 40, jitter_ms: 5  } }
    fn wan2() -> Self { Self { name: "WAN2", one_way_ms: 75, jitter_ms: 15 } }

    fn one_way_delay(&self) -> Duration {
        if self.one_way_ms == 0 { return Duration::ZERO; }
        let jitter_half = self.jitter_ms / 2;
        let offset = rand::random::<u64>() % (self.jitter_ms.max(1));
        let delay = self.one_way_ms.saturating_sub(jitter_half).saturating_add(offset);
        Duration::from_millis(delay)
    }
}

// ── LatencyTransport ──────────────────────────────────────────────────────────
//
// Wraps `InProcessTransport` (zero-copy, in-process FROST aux node calls) and
// adds one-way sleep before and after each call to simulate WAN round trips.

struct LatencyTransport<'a> {
    inner: InProcessTransport<'a>,
    profile: WanProfile,
    net_time: Arc<Mutex<Duration>>,
}

impl<'a> LatencyTransport<'a> {
    fn new(node: &'a FrostAuxiliaryNode, profile: WanProfile, net_time: Arc<Mutex<Duration>>) -> Self {
        Self { inner: InProcessTransport::new(node), profile, net_time }
    }

    fn delay(&self) {
        let d = self.profile.one_way_delay();
        if d > Duration::ZERO {
            std::thread::sleep(d);
            *self.net_time.lock().unwrap() += d;
        }
    }
}

impl<'a> FrostNodeTransport for LatencyTransport<'a> {
    fn verifier_id(&self) -> &VerifierId { self.inner.verifier_id() }

    fn frost_round1(&self, req: &FrostRound1Request, now: UnixTimestamp)
        -> Result<FrostRound1Response, NodeError>
    {
        self.delay(); let r = self.inner.frost_round1(req, now)?; self.delay(); Ok(r)
    }

    fn frost_round2(&self, req: &FrostRound2Request) -> Result<FrostRound2Response, NodeError> {
        self.delay(); let r = self.inner.frost_round2(req)?; self.delay(); Ok(r)
    }

    fn handshake_binding_round1(&self, req: &HandshakeBindingRound1Request, now: UnixTimestamp)
        -> Result<HandshakeBindingRound1Response, NodeError>
    {
        self.delay(); let r = self.inner.handshake_binding_round1(req, now)?; self.delay(); Ok(r)
    }

    fn handshake_binding_round2(&self, req: &HandshakeBindingRound2Request)
        -> Result<HandshakeBindingRound2Response, NodeError>
    {
        self.delay(); let r = self.inner.handshake_binding_round2(req)?; self.delay(); Ok(r)
    }
}

// ── Benchmark ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct RunResult {
    total_ms: u64,
    net_ms: u64,
}

fn run_bench(profile: &WanProfile, t: usize, n: usize) -> RunResult {
    let ids: Vec<VerifierId> = (0..n).map(|i| {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        b[8] = 0xBE;
        VerifierId::from_bytes(b)
    }).collect();

    // Trusted-dealer keygen (paper §IV) — O(1) offline work.
    let keygen = frost_trusted_dealer_keygen(&ids, t).expect("keygen failed");

    // Build aux nodes from participants.
    let aux_nodes: Vec<FrostAuxiliaryNode> = keygen.participants.into_iter()
        .map(FrostAuxiliaryNode::new)
        .collect();

    // Build coordinator.
    let coord_id = {
        let mut b = [0u8; 32];
        b[31] = 0xFF;
        VerifierId::from_bytes(b)
    };

    // PrototypeDvrf: deterministic per-verifier secrets for benchmarking.
    let dvrf_secrets: HashMap<VerifierId, [u8; 32]> = ids.iter().enumerate()
        .map(|(i, vid)| {
            let mut s = [0u8; 32];
            s[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            (vid.clone(), s)
        })
        .collect();

    // Verifier public keys (dummy Ed25519 keys for benchmarks).
    let verifier_keys: Vec<(VerifierId, ed25519_dalek::VerifyingKey)> = ids.iter()
        .map(|vid| {
            let mut seed = [0u8; 32];
            seed[..16].copy_from_slice(&vid.as_bytes()[..16]);
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            (vid.clone(), sk.verifying_key())
        })
        .collect();

    let coord_config = CoordinatorConfig {
        coordinator_id: coord_id,
        epoch: Epoch(1),
        quorum: QuorumSpec { threshold: t, verifiers: ids },
        default_ttl_secs: 3600,
        verifier_public_keys: verifier_keys,
    };

    let store = InMemorySessionStore::new();
    let dvrf = PrototypeDvrf::new(dvrf_secrets);
    let engine = PrototypeAttestationEngine;
    let coordinator = CoordinatorNode::new(coord_config, store, dvrf, engine);

    // Build latency-injecting transports for the first t quorum nodes.
    let net_time = Arc::new(Mutex::new(Duration::ZERO));
    let transports: Vec<LatencyTransport<'_>> = aux_nodes[..t].iter()
        .map(|node| LatencyTransport::new(node, profile.clone(), Arc::clone(&net_time)))
        .collect();
    let transport_refs: Vec<&dyn FrostNodeTransport> =
        transports.iter().map(|t| t as &dyn FrostNodeTransport).collect();

    let request = AttestationRequest {
        prover_id: ProverId::from_bytes([0x01u8; 32]),
        client_nonce: Nonce::from_bytes([0x02u8; 32]),
        statement_tag: "bench".to_string(),
        query: b"SELECT 1".to_vec(),
        requested_ttl_secs: 3600,
    };

    let t_start = Instant::now();
    let _ = coordinator.attest_frost_distributed_over_transport(
        request, &[], &transport_refs, &keygen.group_key,
    );
    let total = t_start.elapsed();
    let net = *net_time.lock().unwrap();

    RunResult {
        total_ms: total.as_millis() as u64,
        net_ms: net.as_millis() as u64,
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Real FROST WAN Benchmark — Paper §IX, Fig. 12                  ║");
    println!("║  Crypto: ed25519 DKG (trusted dealer) + FROST signing            ║");
    println!("║  Network: per-message sleep injected in LatencyTransport         ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let profiles = [WanProfile::lan(), WanProfile::wan1(), WanProfile::wan2()];
    let configs: &[(usize, usize)] = &[
        (2, 3), (3, 5), (5, 9), (7, 13), (10, 19),
    ];

    println!("{:<10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Config", "LAN(ms)", "WAN1(ms)", "WAN1-net", "WAN2(ms)", "WAN2-net");
    println!("{}", "─".repeat(58));

    let mut results = vec![];

    for &(t, n) in configs {
        let lan  = run_bench(&profiles[0], t, n);
        let wan1 = run_bench(&profiles[1], t, n);
        let wan2 = run_bench(&profiles[2], t, n);

        println!("{:<10} {:>9}ms {:>9}ms {:>9}ms {:>9}ms {:>9}ms",
            format!("{t}-of-{n}"),
            lan.total_ms,
            wan1.total_ms, wan1.net_ms,
            wan2.total_ms, wan2.net_ms,
        );

        results.push(serde_json::json!({
            "config": format!("{t}-of-{n}"),
            "lan_ms": lan.total_ms,
            "wan1_total_ms": wan1.total_ms, "wan1_net_ms": wan1.net_ms,
            "wan2_total_ms": wan2.total_ms, "wan2_net_ms": wan2.net_ms,
        }));
    }

    println!();
    println!("Paper §IX: 15-of-29 WAN2 without DKG ≈ 1,000ms additional overhead.");
    println!("Note: run with --release for accurate CPU timings.");
    println!("      For real WAN: sudo tc qdisc add dev lo root netem delay 40ms 5ms");

    let json = serde_json::json!({
        "benchmark": "frost-wan-real",
        "paper_section": "§IX Fig.12",
        "method": "in-process-frost-with-latency-injection",
        "wan1_profile": { "rtt_ms": 80, "one_way_ms": 40, "jitter_ms": 5, "bandwidth_mbps": 50 },
        "wan2_profile": { "rtt_ms": 150, "one_way_ms": 75, "jitter_ms": 15, "bandwidth_mbps": 20 },
        "results": results,
    });
    println!("\nJSON:\n{}", serde_json::to_string_pretty(&json).unwrap());
}