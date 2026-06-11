//! Full-pipeline WAN benchmark — Π_coll-min, paper §VIII Table II + §IX Fig.12.
//!
//! Prints THREE tables (LAN, WAN1, WAN2), each with the full per-session
//! pipeline broken into:
//!
//!   DKG      — real distributed Pedersen DKG, trustless leader, O(n²) comm.
//!   DVRF     — RC-phase randomness generation
//!   HSP      — co-SNARK π_HSP (2-party MPC, full SHA-256 TLS-PRF)
//!   PGP      — mac-then-encrypt proof (HMAC + AES-128-CBC, 3 blocks)
//!   TSS      — FROST threshold signing
//!   Total    — DKG+DVRF+HSP+PGP+TSS (ms)
//!   noDKG    — Total − DKG (steady-state, key already established) (ms)
//!   Net      — total communication volume (kb)
//!   noDKG-Net— Net − DKG volume (kb)
//!
//! HSP communication is modelled from the co-SNARK's real circuit size
//! (~1.9M constraints × one BLS12-377 field element each ≈ 60 MB of MPC
//! traffic), so HSP is bandwidth-bound: LAN ≪ WAN1 < WAN2.
//!
//! # Why this is fast despite three tables
//!
//! The cryptographic computation is **identical across the three network
//! profiles** — only the network overlay (latency + bandwidth) differs. So we
//! MEASURE each config's pure compute ONCE (no network), capture its message
//! volumes and round counts, then APPLY the three profiles analytically. HSP
//! and PGP are additionally **config-independent** (fixed circuit), so they are
//! measured once globally and reused for every row. Result: instead of 9
//! configs × 3 profiles = 27 heavy crypto runs, we do 1 HSP + 1 PGP + 9 small
//! per-config measurements, and the profiles become instant arithmetic.
//!
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_pipeline_wan \
//!   --features tcp --release -- --binary <co-snark-prover>
//! ```

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tls_attestation_core::{
    hash::sha256,
    ids::{ProverId, VerifierId},
    types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
};
use tls_attestation_crypto::{
    dkg::{dkg_part1, dkg_part2, dkg_part3, DkgRound1Package, DkgRound2Package, Identifier},
    frost_adapter::{FrostGroupKey, FrostParticipant},
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

use tls_attestation_zk::co_snark_distributed::{
    CoSnarkDistributedClient, DistributedCrs, DistributedMode,
};
use tls_attestation_zk::mac_then_encrypt::{
    self, MacThenEncryptCircuit, MacThenEncryptCrs, MacThenEncryptWitness,
};

// ── WAN profiles ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct WanProfile {
    name: &'static str,
    one_way_ms: u64,
    jitter_ms: u64,
    bandwidth_mbps: u64,
    loss_per_mille: u64,
}

impl WanProfile {
    fn lan()  -> Self { Self { name: "LAN",  one_way_ms: 0,  jitter_ms: 0,  bandwidth_mbps: 0,  loss_per_mille: 0 } }
    fn wan1() -> Self { Self { name: "WAN1", one_way_ms: 40, jitter_ms: 5,  bandwidth_mbps: 50, loss_per_mille: 1 } }
    fn wan2() -> Self { Self { name: "WAN2", one_way_ms: 75, jitter_ms: 15, bandwidth_mbps: 20, loss_per_mille: 2 } }

    fn rtt_ms(&self) -> u64 { self.one_way_ms * 2 }

    /// One latency hop in ms (one-way + average jitter contribution + expected
    /// packet-loss retransmit penalty). Analytical — no sleeping.
    fn latency_hop_ms(&self) -> f64 {
        if self.one_way_ms == 0 { return 0.0; }
        // expected loss penalty = p * (one extra RTT)
        let loss_pen = (self.loss_per_mille as f64 / 1000.0) * (self.one_way_ms as f64 * 2.0);
        self.one_way_ms as f64 + loss_pen
    }

    /// Serialization delay (ms) to push `bytes` over this link.
    fn bandwidth_ms(&self, bytes: usize) -> f64 {
        if self.bandwidth_mbps == 0 { return 0.0; }
        (bytes as f64 * 8.0) / (self.bandwidth_mbps as f64 * 1000.0) // bits / (Mbit/s) → ms
    }
}

// ── Pure compute (network-independent) measured once per config ───────────────

struct Compute {
    config: String,
    // Pure proving/compute times (no network), milliseconds.
    dkg_ms: u64,
    dvrf_ms: u64,
    hsp_ms: u64,
    pgp_ms: u64,
    tss_ms: u64,
    // Message volumes and round counts for the analytical network overlay.
    dkg_r1_bytes: usize, // round-1 broadcast volume
    dkg_r2_bytes: usize, // round-2 unicast volume (O(n²) shares)
    dvrf_rounds: usize,  // one round-trip per contributing verifier
    dvrf_bytes: usize,
    tss_bytes: usize,    // FROST coordinator↔aux volume (2 rounds)
    tss_signers: usize,  // t — number of parallel signers (loss fan-out)
    hsp_bytes: usize,
    pgp_bytes: usize,
}

// ── Final per-(config,profile) row ────────────────────────────────────────────

struct Row {
    config: String,
    dkg_ms: u64,
    dvrf_ms: u64,
    hsp_ms: u64,
    pgp_ms: u64,
    tss_ms: u64,
    total_ms: u64,
    net_kb: f64,
    // "without DKG" = pipeline cost when the quorum key already exists (DKG is a
    // one-time setup, amortized away in steady state). Total minus DKG.
    without_dkg_ms: u64,
    without_dkg_kb: f64,
}

fn make_ids(n: usize) -> Vec<VerifierId> {
    (0..n).map(|i| {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        b[8] = 0xBE;
        VerifierId::from_bytes(b)
    }).collect()
}

// ── Distributed DKG (trustless leader, real Pedersen DKG) ─────────────────────
//
// Runs the genuine frost-ed25519 Pedersen DKG (part1/2/3). Returns participants,
// group key, and the O(n²) round-1/round-2 byte volumes. No network is injected
// here — the overlay is applied analytically per profile.
struct DkgResult {
    participants: Vec<FrostParticipant>,
    group_key: FrostGroupKey,
    r1_total_bytes: usize,
    r2_total_bytes: usize,
}

fn run_distributed_dkg(ids: &[VerifierId], threshold: usize) -> DkgResult {
    let n = ids.len();
    let identifiers: Vec<Identifier> = (1u16..=(n as u16))
        .map(|i| Identifier::try_from(i).expect("valid identifier"))
        .collect();

    // Part 1
    let mut r1_states = Vec::with_capacity(n);
    let mut r1_pkgs: Vec<DkgRound1Package> = Vec::with_capacity(n);
    for ident in &identifiers {
        let (state, pkg) = dkg_part1(*ident, n as u16, threshold as u16).expect("dkg part1");
        r1_states.push(state);
        r1_pkgs.push(pkg);
    }
    let r1_total_bytes: usize = r1_pkgs.iter()
        .map(|p| p.to_bytes().len() * n.saturating_sub(1)).sum();

    let r1_map_for = |me: usize| -> BTreeMap<Identifier, DkgRound1Package> {
        let mut m = BTreeMap::new();
        for (j, id) in identifiers.iter().enumerate() {
            if j != me {
                m.insert(*id, DkgRound1Package::from_bytes(&r1_pkgs[j].to_bytes()).expect("r1 decode"));
            }
        }
        m
    };

    // Part 2
    let mut r2_states = Vec::with_capacity(n);
    let mut routed: Vec<BTreeMap<Identifier, Vec<u8>>> = (0..n).map(|_| BTreeMap::new()).collect();
    let mut r2_total_bytes = 0usize;
    let r1_states_drained: Vec<_> = r1_states.into_iter().collect();
    for (me, state) in r1_states_drained.into_iter().enumerate() {
        let r1_map = r1_map_for(me);
        let (r2_state, outbound) = dkg_part2(state, &r1_map).expect("dkg part2");
        r2_states.push(r2_state);
        for (recipient_id, pkg) in outbound {
            let bytes = pkg.to_plaintext_bytes();
            r2_total_bytes += bytes.len();
            let recipient_idx = identifiers.iter()
                .position(|id| *id == recipient_id)
                .expect("recipient in ceremony");
            routed[recipient_idx].insert(identifiers[me], bytes);
        }
    }

    // Part 3
    let mut participants = Vec::with_capacity(n);
    let mut group_key_out: Option<FrostGroupKey> = None;
    for me in 0..n {
        let r1_map = r1_map_for(me);
        let r2_map: BTreeMap<Identifier, DkgRound2Package> = routed[me].iter()
            .map(|(sender, bytes)| (*sender, DkgRound2Package::from_plaintext_bytes(bytes).expect("r2 decode")))
            .collect();
        let out = dkg_part3(&ids[me], identifiers[me], &r2_states[me], &r1_map, &r2_map, ids)
            .expect("dkg part3");
        participants.push(out.participant);
        group_key_out = Some(out.group_key);
    }

    DkgResult {
        participants,
        group_key: group_key_out.expect("≥1 participant"),
        r1_total_bytes,
        r2_total_bytes,
    }
}

// ── Measure pure compute for one config (NO network injection) ────────────────

#[allow(clippy::too_many_arguments)]
fn measure_compute(
    t: usize,
    n: usize,
    hsp_ms: u64,        // measured once globally, reused
    hsp_bytes: usize,
    pgp_ms: u64,        // measured once globally, reused
    pgp_bytes: usize,
) -> Compute {
    let ids = make_ids(n);

    // DKG — real distributed Pedersen DKG, pure compute timed.
    let t0 = Instant::now();
    let dkg = run_distributed_dkg(&ids, t);
    let dkg_ms = t0.elapsed().as_millis() as u64;

    let aux_nodes: Vec<FrostAuxiliaryNode> =
        dkg.participants.into_iter().map(FrostAuxiliaryNode::new).collect();
    let group_key = dkg.group_key;
    let coord_id = { let mut b = [0u8; 32]; b[31] = 0xFF; VerifierId::from_bytes(b) };

    // DVRF — t verifier contributions (one round-trip each). Pure hash compute.
    let t1 = Instant::now();
    {
        let alpha = [0x07u8; 32];
        for vid in ids.iter().take(t) {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(vid.as_bytes());
            buf.extend_from_slice(&alpha);
            let _gamma = sha256(&buf);
        }
    }
    let dvrf_ms = t1.elapsed().as_millis() as u64;
    let dvrf_rounds = t;
    let dvrf_bytes = t * (48 + 96);

    // TSS — real FROST signing over an in-process (zero-latency) transport.
    let net_time = Arc::new(Mutex::new(Duration::ZERO));
    let net_bytes = Arc::new(Mutex::new(0u64));
    let lan = WanProfile::lan(); // no delay during the pure-compute measurement

    let verifier_keys: Vec<(VerifierId, ed25519_dalek::VerifyingKey)> = ids.iter()
        .map(|vid| {
            let mut seed = [0u8; 32];
            seed[..16].copy_from_slice(&vid.as_bytes()[..16]);
            (vid.clone(), ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
        }).collect();
    let dvrf_secrets: HashMap<VerifierId, [u8; 32]> = ids.iter().enumerate()
        .map(|(i, vid)| { let mut s = [0u8; 32]; s[0..4].copy_from_slice(&(i as u32).to_be_bytes()); (vid.clone(), s) })
        .collect();
    let coord_config = CoordinatorConfig {
        coordinator_id: coord_id,
        epoch: Epoch(1),
        quorum: QuorumSpec { threshold: t, verifiers: ids.clone() },
        default_ttl_secs: 3600,
        verifier_public_keys: verifier_keys,
    };
    let store = InMemorySessionStore::new();
    let dvrf = PrototypeDvrf::new(dvrf_secrets);
    let engine = PrototypeAttestationEngine;
    let coordinator = CoordinatorNode::new(coord_config, store, dvrf, engine);

    let transports: Vec<LatencyTransport<'_>> = aux_nodes[..t].iter()
        .map(|node| LatencyTransport::new(node, lan.clone(), Arc::clone(&net_time), Arc::clone(&net_bytes)))
        .collect();
    let transport_refs: Vec<&dyn FrostNodeTransport> =
        transports.iter().map(|x| x as &dyn FrostNodeTransport).collect();
    let request = AttestationRequest {
        prover_id: ProverId::from_bytes([0x01u8; 32]),
        client_nonce: Nonce::from_bytes([0x02u8; 32]),
        statement_tag: "bench".to_string(),
        query: b"SELECT 1".to_vec(),
        requested_ttl_secs: 3600,
    };
    let t4 = Instant::now();
    let _ = coordinator.attest_frost_distributed_over_transport(
        request, &[], &transport_refs, &group_key,
    );
    let tss_ms = t4.elapsed().as_millis() as u64;
    let tss_bytes = *net_bytes.lock().unwrap() as usize;

    Compute {
        config: format!("{t}-of-{n}"),
        dkg_ms, dvrf_ms, hsp_ms, pgp_ms, tss_ms,
        dkg_r1_bytes: dkg.r1_total_bytes,
        dkg_r2_bytes: dkg.r2_total_bytes,
        dvrf_rounds,
        dvrf_bytes,
        tss_bytes,
        tss_signers: t,
        hsp_bytes,
        pgp_bytes,
    }
}

// ── Apply a network profile analytically to a measured compute ────────────────

fn apply_profile(c: &Compute, p: &WanProfile) -> Row {
    // DKG: 2 parallel rounds (broadcast + unicast); latency once per round,
    // bandwidth on each round's aggregate volume.
    let dkg_net = 2.0 * p.latency_hop_ms()
        + p.bandwidth_ms(c.dkg_r1_bytes)
        + p.bandwidth_ms(c.dkg_r2_bytes);
    let dkg_ms = c.dkg_ms + dkg_net.round() as u64;

    // DVRF: one round-trip (2 hops) per contributing verifier; serial here
    // because each contribution depends on the coordinator's relay.
    let dvrf_net = (c.dvrf_rounds as f64) * 2.0 * p.latency_hop_ms()
        + p.bandwidth_ms(c.dvrf_bytes);
    let dvrf_ms = c.dvrf_ms + dvrf_net.round() as u64;

    // HSP: 2-party MPC ≈ 3 communication rounds → 3×RTT, plus bandwidth on the
    // secret-shared MSM volume.
    let hsp_net = 3.0 * (p.rtt_ms() as f64) + p.bandwidth_ms(c.hsp_bytes);
    let hsp_ms = c.hsp_ms + hsp_net.round() as u64;

    // PGP: a single proof artifact returned to the requester (one hop) + its
    // serialization. Tiny.
    let pgp_net = p.latency_hop_ms() + p.bandwidth_ms(c.pgp_bytes);
    let pgp_ms = c.pgp_ms + pgp_net.round() as u64;

    // TSS: FROST is 2 coordinator-mediated rounds (commit, then sign). In each
    // round the coordinator fans out to all t aux signers and collects replies.
    // Sends are parallel, so a round costs one round-trip of wall-clock latency
    // (2 × latency_hop) — but latency_hop already folds in the *expected* packet
    // loss retransmit penalty, and with t independent links the chance that some
    // signer in a round hits a loss grows with t, so we scale the loss component
    // by the fan-out. Bandwidth is on the aggregate FROST message volume.
    let tss_rounds = 2.0; // commit + sign
    let base_hop = p.one_way_ms as f64;
    // expected loss penalty grows with the number of parallel signers (t):
    // P(at least one of t links drops) ≈ 1-(1-p)^t, times one RTT retransmit.
    let p_loss = p.loss_per_mille as f64 / 1000.0;
    let any_loss = 1.0 - (1.0 - p_loss).powi(c.tss_signers as i32);
    let loss_pen = any_loss * (p.one_way_ms as f64 * 2.0);
    let tss_net = tss_rounds * (2.0 * base_hop + loss_pen)
        + p.bandwidth_ms(c.tss_bytes);
    let tss_ms = c.tss_ms + tss_net.round() as u64;

    let total_ms = dkg_ms + dvrf_ms + hsp_ms + pgp_ms + tss_ms;
    let dkg_kb = (c.dkg_r1_bytes + c.dkg_r2_bytes) as f64 / 1024.0;
    let net_kb = (c.dkg_r1_bytes + c.dkg_r2_bytes + c.dvrf_bytes
        + c.tss_bytes + c.hsp_bytes + c.pgp_bytes) as f64 / 1024.0;

    // "without DKG": steady-state per-session cost once the quorum key exists.
    // DKG is a one-time ceremony, so subtract it from both time and volume.
    let without_dkg_ms = total_ms - dkg_ms;
    let without_dkg_kb = net_kb - dkg_kb;

    Row {
        config: c.config.clone(),
        dkg_ms, dvrf_ms, hsp_ms, pgp_ms, tss_ms,
        total_ms, net_kb,
        without_dkg_ms, without_dkg_kb,
    }
}

// ── Latency-injecting FROST transport (used only during compute for TSS) ──────

struct LatencyTransport<'a> {
    inner: InProcessTransport<'a>,
    profile: WanProfile,
    net_time: Arc<Mutex<Duration>>,
    net_bytes: Arc<Mutex<u64>>,
}

impl<'a> LatencyTransport<'a> {
    fn new(node: &'a FrostAuxiliaryNode, profile: WanProfile,
           net_time: Arc<Mutex<Duration>>, net_bytes: Arc<Mutex<u64>>) -> Self {
        Self { inner: InProcessTransport::new(node), profile, net_time, net_bytes }
    }
    fn hop(&self, bytes: usize) {
        *self.net_bytes.lock().unwrap() += bytes as u64;
        let d = self.profile.send_delay(bytes);
        if d > Duration::ZERO {
            std::thread::sleep(d);
            *self.net_time.lock().unwrap() += d;
        }
    }
}

impl WanProfile {
    fn send_delay(&self, payload_bytes: usize) -> Duration {
        if self.one_way_ms == 0 && self.bandwidth_mbps == 0 {
            return Duration::ZERO;
        }
        let jitter_half = self.jitter_ms / 2;
        let jitter_offset = if self.jitter_ms > 0 {
            (rand::random::<u64>() % self.jitter_ms.max(1)) as i64 - jitter_half as i64
        } else { 0 };
        let latency_ms = (self.one_way_ms as i64 + jitter_offset).max(0) as u64;
        let bw_us = if self.bandwidth_mbps > 0 {
            (payload_bytes as u64 * 8) / self.bandwidth_mbps
        } else { 0 };
        let loss_penalty_ms = if self.loss_per_mille > 0
            && (rand::random::<u64>() % 1000) < self.loss_per_mille
        { self.one_way_ms * 2 } else { 0 };
        Duration::from_micros((latency_ms + loss_penalty_ms) * 1000 + bw_us)
    }
}

const FROST_R1_REQ: usize = 96;   const FROST_R1_RESP: usize = 200;
const FROST_R2_REQ: usize = 256;  const FROST_R2_RESP: usize = 64;
const HSP_R1_REQ: usize = 128;    const HSP_R1_RESP: usize = 200;
const HSP_R2_REQ: usize = 256;    const HSP_R2_RESP: usize = 64;

impl<'a> FrostNodeTransport for LatencyTransport<'a> {
    fn verifier_id(&self) -> &VerifierId { self.inner.verifier_id() }
    fn frost_round1(&self, req: &FrostRound1Request, now: UnixTimestamp)
        -> Result<FrostRound1Response, NodeError> {
        self.hop(FROST_R1_REQ); let r = self.inner.frost_round1(req, now)?; self.hop(FROST_R1_RESP); Ok(r)
    }
    fn frost_round2(&self, req: &FrostRound2Request) -> Result<FrostRound2Response, NodeError> {
        self.hop(FROST_R2_REQ); let r = self.inner.frost_round2(req)?; self.hop(FROST_R2_RESP); Ok(r)
    }
    fn handshake_binding_round1(&self, req: &HandshakeBindingRound1Request, now: UnixTimestamp)
        -> Result<HandshakeBindingRound1Response, NodeError> {
        self.hop(HSP_R1_REQ); let r = self.inner.handshake_binding_round1(req, now)?; self.hop(HSP_R1_RESP); Ok(r)
    }
    fn handshake_binding_round2(&self, req: &HandshakeBindingRound2Request)
        -> Result<HandshakeBindingRound2Response, NodeError> {
        self.hop(HSP_R2_REQ); let r = self.inner.handshake_binding_round2(req)?; self.hop(HSP_R2_RESP); Ok(r)
    }
}

// ── HSP / PGP measured ONCE (config-independent) ──────────────────────────────

fn measure_hsp(client: &CoSnarkDistributedClient, crs: &DistributedCrs) -> (u64, usize) {
    let p_share = [0x11u8; 32];
    let v_share = [0x22u8; 32];
    let rand_binding = [0x33u8; 32];
    // No MPC latency injected — pure compute. (Network added analytically later.)
    std::env::set_var("MPC_LATENCY_MS", "0");
    let t = Instant::now();
    let _ = client.prove(&p_share, &v_share, &rand_binding, Some(crs), false)
        .expect("distributed co-SNARK prove");
    let ms = t.elapsed().as_millis() as u64;
    std::env::remove_var("MPC_LATENCY_MS");

    // Real co-SNARK MPC communication volume.
    //
    // The 2-party collaborative Groth16 prover secret-shares the full witness
    // and runs the prover algorithm as an MPC. Per Ozdemir-Boneh (USENIX'22),
    // Groth16 uses "one triple per constraint" and the total communication is
    // O(circuit size): the dominant traffic is the secret-shared witness flowing
    // to the king plus the per-multiplication openings during the MSM/QAP phase.
    // We model the on-wire volume as (constraints × field-element size), one
    // BLS12-377 Fr element (32 bytes) per constraint. This makes HSP genuinely
    // bandwidth-bound on low-capacity links (Ozdemir: "communication costs
    // dominate in low-capacity networks"), so LAN ≪ WAN1 < WAN2.
    const TLS_PRF_CONSTRAINTS: usize = 1_900_000;
    const FR_BYTES: usize = 32;
    let hsp_bytes = TLS_PRF_CONSTRAINTS * FR_BYTES;
    (ms, hsp_bytes)
}

fn measure_pgp(crs: &MacThenEncryptCrs) -> (u64, usize) {
    let witness = MacThenEncryptWitness::new(
        [0x42u8; 32], [0x11u8; 16], [0x22u8; 16], [0xAAu8; 16], 1, 23, [3, 3],
    );
    let circuit = MacThenEncryptCircuit::from_witness(&witness, &[0x33u8; 32]);
    let t = Instant::now();
    let proof = mac_then_encrypt::prove(crs, circuit).expect("pgp prove");
    let ms = t.elapsed().as_millis() as u64;
    (ms, proof.groth16_bytes.len())
}

// ── Output ────────────────────────────────────────────────────────────────────

fn print_table(profile: &WanProfile, rows: &[Row]) {
    println!("== {} (RTT={}ms, one-way={}±{}ms, {}Mbps, {:.1}% loss) ==",
        profile.name, profile.rtt_ms(), profile.one_way_ms, profile.jitter_ms,
        profile.bandwidth_mbps, profile.loss_per_mille as f64 / 10.0);
    println!("{:<10} {:>7} {:>7} {:>9} {:>9} {:>8} {:>9} {:>10} {:>10} {:>11}",
        "Config", "DKG", "DVRF", "HSP", "PGP", "TSS", "Total", "noDKG", "Net", "noDKG-Net");
    println!("{:<10} {:>7} {:>7} {:>9} {:>9} {:>8} {:>9} {:>10} {:>10} {:>11}",
        "", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(kb)", "(kb)");
    println!("{}", "-".repeat(96));
    for r in rows {
        println!("{:<10} {:>7} {:>7} {:>9} {:>9} {:>8} {:>9} {:>10} {:>10.2} {:>11.2}",
            r.config, r.dkg_ms, r.dvrf_ms, r.hsp_ms, r.pgp_ms, r.tss_ms,
            r.total_ms, r.without_dkg_ms, r.net_kb, r.without_dkg_kb);
    }
    println!();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let binary = args.windows(2)
        .find(|w| w[0] == "--binary")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "co-snark-prover".to_string());

    eprintln!("Setting up CRS (one-time)…");
    let hsp_client = CoSnarkDistributedClient::new(&binary, DistributedMode::Distributed);
    let hsp_crs = hsp_client.setup().expect("co-SNARK distributed setup");
    let pgp_crs = mac_then_encrypt::setup().expect("mac-then-encrypt setup");
    eprintln!("CRS ready.");

    // Config-independent proofs: measure once, reuse for every row.
    eprintln!("Measuring HSP (co-SNARK) once…");
    let (hsp_ms, hsp_bytes) = measure_hsp(&hsp_client, &hsp_crs);
    eprintln!("Measuring PGP (mac-then-encrypt) once…");
    let (pgp_ms, pgp_bytes) = measure_pgp(&pgp_crs);

    let configs: &[(usize, usize)] = &[
        (3, 5), (5, 9), (7, 13), (10, 19), (15, 29),
        (20, 39), (30, 59), (40, 79), (50, 99),
    ];

    // Measure each config's compute ONCE (DKG/DVRF/TSS + volumes).
    eprintln!("Measuring per-config compute ({} configs)…", configs.len());
    let computes: Vec<Compute> = configs.iter()
        .map(|&(t, n)| measure_compute(t, n, hsp_ms, hsp_bytes, pgp_ms, pgp_bytes))
        .collect();
    eprintln!("Done. Rendering three tables.\n");

    // Apply the three profiles analytically — instant.
    for profile in [WanProfile::lan(), WanProfile::wan1(), WanProfile::wan2()] {
        let rows: Vec<Row> = computes.iter().map(|c| apply_profile(c, &profile)).collect();
        print_table(&profile, &rows);
    }
}
