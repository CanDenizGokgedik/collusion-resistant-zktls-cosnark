//! WAN latency simulation benchmark — Paper §IX, Fig. 12.
//!
//! Measures the DVRF-then-Sign protocol under two WAN profiles:
//!
//! WAN1: RTT≈80ms,  50Mbps, 0.1% packet loss
//! WAN2: RTT≈150ms, 20Mbps, 0.2% packet loss
//!
//! Real network latency is simulated via Thread::sleep instead of tc/netem.
//!
//! # Paper §IX
//! > "Even under the more challenging WAN2 setting, the DVRF-then-Sign
//!   extension incurs approximately one second of additional overhead for
//!   the 15-out-of-29 configuration."
//!
//! # Usage
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_wan --release
//! ```

use std::time::{Duration, Instant};
use rand::rngs::OsRng;
use tls_attestation_crypto::{
    dkg_secp256k1::run_secp256k1_dkg,
    dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput},
    frost_secp256k1_adapter::{
        secp256k1_build_signing_package, secp256k1_aggregate_signature_shares,
    },
};
use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};

// ── WAN profiles ──────────────────────────────────────────────────────────────

/// Network latency profile (paper §IX).
#[derive(Clone, Debug)]
struct WanProfile {
    name: &'static str,
    /// One-way latency (ms) — RTT/2.
    one_way_latency_ms: u64,
    /// RTT standard deviation (ms).
    latency_jitter_ms: u64,
    /// Bandwidth (Mbps).
    bandwidth_mbps: u64,
    /// Packet loss percentage × 1000 (0.1% = 100).
    packet_loss_per_mille: u64,
}

impl WanProfile {
    /// LAN: no latency.
    fn lan() -> Self {
        Self { name: "LAN", one_way_latency_ms: 0, latency_jitter_ms: 0,
               bandwidth_mbps: 1000, packet_loss_per_mille: 0 }
    }

    /// WAN1: RTT≈80ms, 50Mbps, 0.1% packet loss.
    fn wan1() -> Self {
        Self { name: "WAN1", one_way_latency_ms: 40, latency_jitter_ms: 5,
               bandwidth_mbps: 50, packet_loss_per_mille: 1 }
    }

    /// WAN2: RTT≈150ms, 20Mbps, 0.2% packet loss (paper §IX worst case).
    fn wan2() -> Self {
        Self { name: "WAN2", one_way_latency_ms: 75, latency_jitter_ms: 15,
               bandwidth_mbps: 20, packet_loss_per_mille: 2 }
    }

    /// Simulates the send latency of a single message.
    ///
    /// Latency = one_way_latency ± jitter/2
    /// Bandwidth delay = payload_bytes × 8 / (bandwidth_mbps × 1e6)
    /// Packet loss = probability with mean packet_loss_per_mille/1000
    fn simulate_send(&self, payload_bytes: usize) {
        if self.one_way_latency_ms == 0 { return; }

        // Jitter: simple ±jitter_ms/2 simulation.
        let jitter = (self.latency_jitter_ms / 2) as i64;
        let delay_ms = (self.one_way_latency_ms as i64) + jitter;

        // Bandwidth: additional delay based on data size.
        let bw_delay_us = if self.bandwidth_mbps > 0 {
            (payload_bytes as u64 * 8 * 1000) / (self.bandwidth_mbps * 1000)
        } else { 0 };

        // Packet loss: add RTT penalty on loss.
        let loss_penalty_ms = if self.packet_loss_per_mille > 0
            && (rand::random::<u64>() % 1000) < self.packet_loss_per_mille
        {
            // Packet retransmission: extra one RTT delay.
            self.one_way_latency_ms * 2
        } else { 0 };

        let total_ms = delay_ms.unsigned_abs() + loss_penalty_ms;
        let total_us = total_ms * 1000 + bw_delay_us;
        std::thread::sleep(Duration::from_micros(total_us));
    }

    /// Simulates communication rounds for the t-of-n DVRF-then-Sign protocol.
    ///
    /// DVRF-then-Sign communication rounds (paper Fig. 10/11):
    ///   DKG:  O(n²) — n×(n-1) messages
    ///   DVRF: t × 2 messages (partial_eval + combine)
    ///   TSS:  t × 2 messages (round1 commit + round2 share)
    fn simulate_protocol_communication(
        &self,
        threshold: usize,
        n_verifiers: usize,
        with_dkg: bool,
    ) -> Duration {
        let start = Instant::now();

        // DKG: n×(n-1) messages, each ~1KB.
        if with_dkg {
            let dkg_msgs = n_verifiers * (n_verifiers - 1);
            for _ in 0..dkg_msgs {
                self.simulate_send(1024); // ~1KB per DKG message
            }
        }

        // DVRF partial evaluations: t messages from prover → coordinator.
        for _ in 0..threshold {
            self.simulate_send(64); // ~64 bytes per partial eval
        }

        // DVRF combine response: 1 message coordinator → all.
        self.simulate_send(96); // ~96 bytes (rand + proof)

        // TSS Round 1: t commitment messages.
        for _ in 0..threshold {
            self.simulate_send(64); // commitment
        }

        // TSS Round 2: t signature share messages.
        for _ in 0..threshold {
            self.simulate_send(64); // sig share
        }

        // Aggregate: 1 message.
        self.simulate_send(65); // compact Schnorr sig

        start.elapsed()
    }
}

// ── Local computation time ────────────────────────────────────────────────────

fn measure_local_computation(threshold: usize, n_verifiers: usize) -> (Duration, Duration, Duration) {
    let ids: Vec<VerifierId> = (0..n_verifiers as u8).map(|i| {
        VerifierId::from_bytes({ let mut b = [0u8; 32]; b[0] = i; b })
    }).collect();
    let alpha = DigestBytes::from_bytes([0x42u8; 32]);
    let message = DigestBytes::from_bytes([0xEEu8; 32]);

    // DKG
    let t0 = Instant::now();
    let dkg_outputs = run_secp256k1_dkg(&ids, threshold).expect("DKG");
    let dkg_dur = t0.elapsed();

    // DVRF
    let t1 = Instant::now();
    let input = Secp256k1DvrfInput::new(alpha.clone());
    let partial_evals: Vec<_> = (0..threshold)
        .map(|i| Secp256k1Dvrf::partial_eval(&dkg_outputs[i].participant, &input).unwrap())
        .collect();
    let participant_refs: Vec<_> = (0..threshold).map(|i| &dkg_outputs[i].participant).collect();
    let _dvrf = Secp256k1Dvrf::combine(&dkg_outputs[0].group_key, &input, partial_evals, &participant_refs).unwrap();
    let dvrf_dur = t1.elapsed();

    // TSS
    let t2 = Instant::now();
    let r1: Vec<_> = (0..threshold)
        .map(|i| dkg_outputs[i].participant.round1(&mut OsRng).unwrap())
        .collect();
    let (nonces, commitments): (Vec<_>, Vec<_>) = r1.into_iter().unzip();
    let pkg = secp256k1_build_signing_package(&commitments, &message).unwrap();
    let shares: Vec<_> = nonces.into_iter().enumerate()
        .map(|(i, n)| dkg_outputs[i].participant.round2(&pkg, n).unwrap())
        .collect();
    let _agg = secp256k1_aggregate_signature_shares(&pkg, &shares, &dkg_outputs[0].group_key).unwrap();
    let tss_dur = t2.elapsed();

    (dkg_dur, dvrf_dur, tss_dur)
}

// ── Benchmark ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct WanResult {
    profile: &'static str,
    config: String,
    local_ms: u64,
    comm_ms: u64,
    total_ms: u64,
}

fn run_wan_bench(
    profile: &WanProfile,
    threshold: usize,
    n_verifiers: usize,
    with_dkg: bool,
) -> WanResult {
    // 1. Local computation (CPU time).
    let (dkg_dur, dvrf_dur, tss_dur) = measure_local_computation(threshold, n_verifiers);
    let local_ms = if with_dkg {
        (dkg_dur + dvrf_dur + tss_dur).as_millis() as u64
    } else {
        (dvrf_dur + tss_dur).as_millis() as u64
    };

    // 2. Network communication latency.
    let comm_dur = profile.simulate_protocol_communication(threshold, n_verifiers, with_dkg);
    let comm_ms = comm_dur.as_millis() as u64;

    WanResult {
        profile: profile.name,
        config: format!("{}-of-{}", threshold, n_verifiers),
        local_ms,
        comm_ms,
        total_ms: local_ms + comm_ms,
    }
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  DVRF-then-Sign WAN Benchmark — Paper §IX, Fig. 12              ║");
    println!("║  WAN1: RTT=80ms/50Mbps/0.1%loss  WAN2: RTT=150ms/20Mbps/0.2%   ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let profiles = [WanProfile::lan(), WanProfile::wan1(), WanProfile::wan2()];

    // Paper §IX: t-of-n configurations (from Fig. 9 and Fig. 12).
    let configs: &[(usize, usize)] = &[
        (2, 3), (3, 5), (5, 9), (7, 13), (10, 19), (15, 29),
    ];

    // ── WITH DKG (Fig. 10) ────────────────────────────────────────────────────
    println!("┌─ WITH DKG (Fig. 10) ────────────────────────────────────────────┐");
    println!("{:<10} {:>12} {:>12} {:>12} {:>12}",
        "Config", "LAN (ms)", "WAN1 (ms)", "WAN2 (ms)", "WAN2 comm%");
    println!("{}", "─".repeat(62));

    let mut json_with_dkg = Vec::new();
    for &(t, n) in configs {
        let lan  = run_wan_bench(&profiles[0], t, n, true);
        let wan1 = run_wan_bench(&profiles[1], t, n, true);
        let wan2 = run_wan_bench(&profiles[2], t, n, true);
        let comm_pct = if wan2.total_ms > 0 { wan2.comm_ms * 100 / wan2.total_ms } else { 0 };
        println!("{:<10} {:>12} {:>12} {:>12} {:>11}%",
            format!("{}-of-{}", t, n), lan.total_ms, wan1.total_ms, wan2.total_ms, comm_pct);
        json_with_dkg.push(serde_json::json!({
            "config": format!("{}-of-{}", t, n),
            "lan_ms": lan.total_ms, "wan1_ms": wan1.total_ms, "wan2_ms": wan2.total_ms,
        }));
    }

    // ── WITHOUT DKG (Fig. 11) ─────────────────────────────────────────────────
    println!("\n┌─ WITHOUT DKG (Fig. 11) ─────────────────────────────────────────┐");
    println!("{:<10} {:>12} {:>12} {:>12} {:>12}",
        "Config", "LAN (ms)", "WAN1 (ms)", "WAN2 (ms)", "WAN2 comm%");
    println!("{}", "─".repeat(62));

    let mut json_no_dkg = Vec::new();
    for &(t, n) in configs {
        let lan  = run_wan_bench(&profiles[0], t, n, false);
        let wan1 = run_wan_bench(&profiles[1], t, n, false);
        let wan2 = run_wan_bench(&profiles[2], t, n, false);
        let comm_pct = if wan2.total_ms > 0 { wan2.comm_ms * 100 / wan2.total_ms } else { 0 };
        println!("{:<10} {:>12} {:>12} {:>12} {:>11}%",
            format!("{}-of-{}", t, n), lan.total_ms, wan1.total_ms, wan2.total_ms, comm_pct);
        json_no_dkg.push(serde_json::json!({
            "config": format!("{}-of-{}", t, n),
            "lan_ms": lan.total_ms, "wan1_ms": wan1.total_ms, "wan2_ms": wan2.total_ms,
        }));
    }

    println!();
    println!("Paper §IX reference for 15-of-29:");
    println!("  WAN2 without DKG ≈ 1,000ms additional overhead");
    println!("  WAN1 without DKG ≈    600ms additional overhead");
    println!();
    println!("Notes:");
    println!("  • Network delays simulated via Thread::sleep (actual WAN uses tc/netem).");
    println!("  • Local computation runs on the host machine (M3 equivalent).");
    println!("  • Paper experiments were run on M3 / 16GB RAM machine.");

    // JSON output.
    let json = serde_json::json!({
        "benchmark": "dvrf-tss-wan",
        "paper_section": "§IX Fig.12",
        "wan_profiles": {
            "lan":  {"rtt_ms": 0, "bandwidth_mbps": 1000, "packet_loss_pct": 0.0},
            "wan1": {"rtt_ms": 80, "bandwidth_mbps": 50, "packet_loss_pct": 0.1},
            "wan2": {"rtt_ms": 150, "bandwidth_mbps": 20, "packet_loss_pct": 0.2},
        },
        "with_dkg": json_with_dkg,
        "without_dkg": json_no_dkg,
    });
    println!("\nJSON:\n{}", serde_json::to_string_pretty(&json).unwrap());
}