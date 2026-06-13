//! DECO TLS 1.2 MtE — WAN benchmark. Three tables (LAN, WAN1, WAN2).
//!
//! Mirrors the Π_coll-min pipeline benchmark's methodology, but for plain DECO:
//! there is **no DKG, no DVRF, no TSS**. Per-session pipeline is just:
//!
//!   HSP   — 2-party Yao garbled-circuit handshake, full SHA-256 TLS-PRF
//!           (PMS add + master-secret + key-expansion). Bandwidth-bound:
//!           the garbler ships ~26 MB of garbled tables, but it is
//!           constant-round, so latency barely matters.
//!   PGP   — mac-then-encrypt Groth16 proof (HMAC + AES-128-CBC, 3 blocks).
//!           Identical circuit to the co-SNARK pipeline's PGP; the proof is a
//!           few hundred bytes, so PGP is compute-bound, not network-bound.
//!   Total — HSP + PGP (ms)
//!   Net   — total communication volume (kb)
//!
//! # Why one execution suffices
//! The cryptographic computation is identical across the three network
//! profiles — only the latency+bandwidth overlay differs. So we MEASURE pure
//! compute ONCE (HSP via the in-process 2PC, PGP via a real Groth16 prove),
//! capture the message volumes, then APPLY the three profiles analytically.
//!
//!   cargo run --release --bin bench_deco_wan

use std::time::Instant;

use hsp_2pc::run_hsp;
use pgp::{prove, setup, MacThenEncryptCircuit, MacThenEncryptWitness};

// ── WAN profiles (identical to the Π_coll-min pipeline benchmark) ─────────────

#[derive(Clone)]
struct WanProfile {
    name: &'static str,
    one_way_ms: u64,
    jitter_ms: u64,
    bandwidth_mbps: u64,
    loss_per_mille: u64,
}

impl WanProfile {
    fn lan() -> Self { Self { name: "LAN", one_way_ms: 0, jitter_ms: 0, bandwidth_mbps: 0, loss_per_mille: 0 } }
    fn wan1() -> Self { Self { name: "WAN1", one_way_ms: 40, jitter_ms: 5, bandwidth_mbps: 50, loss_per_mille: 1 } }
    fn wan2() -> Self { Self { name: "WAN2", one_way_ms: 75, jitter_ms: 15, bandwidth_mbps: 20, loss_per_mille: 2 } }

    fn rtt_ms(&self) -> u64 { self.one_way_ms * 2 }

    fn latency_hop_ms(&self) -> f64 {
        if self.one_way_ms == 0 { return 0.0; }
        let loss_pen = (self.loss_per_mille as f64 / 1000.0) * (self.one_way_ms as f64 * 2.0);
        self.one_way_ms as f64 + loss_pen
    }

    fn bandwidth_ms(&self, bytes: usize) -> f64 {
        if self.bandwidth_mbps == 0 { return 0.0; }
        (bytes as f64 * 8.0) / (self.bandwidth_mbps as f64 * 1000.0)
    }
}

// ── HSP communication volume (Yao garbled circuit, analytical) ────────────────
//
// Free-XOR + half-gates: the garbler sends 2 ciphertexts (16 bytes each) per
// AND gate; XOR/INV gates are free. The full TLS-1.2 PRF as built in
// crates/hsp-2pc is 36 SHA-256 compressions:
//   master secret  : 2 partials + A(1)/out_1/A(2)/out_2  = 13 compressions
//   key expansion  : 2 partials + A(1..4)/out_1..4       = 23 compressions
// plus a 256-bit ripple-carry adder for the pre-master secret. Each Bristol
// SHA-256 compression has 22 573 AND gates.
const SHA256_COMPRESSIONS: usize = 36;
const AND_PER_COMPRESSION: usize = 22_573;
const ADDER_AND: usize = 255;
const BYTES_PER_AND: usize = 32; // half-gate: 2 × 128-bit ciphertext
// Yao is constant-round: base-OT/COT setup + one garble→evaluate exchange.
const HSP_ROUNDS: f64 = 2.0;

fn hsp_comm_bytes() -> usize {
    (SHA256_COMPRESSIONS * AND_PER_COMPRESSION + ADDER_AND) * BYTES_PER_AND
}

struct Row {
    profile: &'static str,
    hsp_ms: u64,
    pgp_ms: u64,
    total_ms: u64,
    net_kb: f64,
}

fn apply_profile(
    hsp_compute_ms: u64,
    hsp_bytes: usize,
    pgp_compute_ms: u64,
    pgp_bytes: usize,
    p: &WanProfile,
) -> Row {
    // HSP: constant-round 2PC; dominated by shipping the garbled circuit.
    let hsp_net = HSP_ROUNDS * (p.rtt_ms() as f64) + p.bandwidth_ms(hsp_bytes);
    let hsp_ms = hsp_compute_ms + hsp_net.round() as u64;

    // PGP: prover sends one small SNARK proof to the verifier (1 hop).
    let pgp_net = p.latency_hop_ms() + p.bandwidth_ms(pgp_bytes);
    let pgp_ms = pgp_compute_ms + pgp_net.round() as u64;

    let total_ms = hsp_ms + pgp_ms;
    let net_kb = (hsp_bytes + pgp_bytes) as f64 / 1024.0;

    Row { profile: p.name, hsp_ms, pgp_ms, total_ms, net_kb }
}

fn print_table(p: &WanProfile, row: &Row) {
    println!(
        "== {} (RTT={}ms, one-way={}±{}ms, {}, {:.1}% loss) ==",
        p.name,
        p.rtt_ms(),
        p.one_way_ms,
        p.jitter_ms,
        if p.bandwidth_mbps == 0 { "unmetered".to_string() } else { format!("{}Mbps", p.bandwidth_mbps) },
        p.loss_per_mille as f64 / 10.0
    );
    println!("{:<10} {:>9} {:>9} {:>9} {:>12}", "Config", "HSP", "PGP", "Total", "Net");
    println!("{:<10} {:>9} {:>9} {:>9} {:>12}", "", "(ms)", "(ms)", "(ms)", "(kb)");
    println!("{}", "-".repeat(54));
    println!(
        "{:<10} {:>9} {:>9} {:>9} {:>12.2}",
        "deco", row.hsp_ms, row.pgp_ms, row.total_ms, row.net_kb
    );
    println!();
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    eprintln!("Measuring HSP (2PC Yao, full TLS-PRF) once…");
    let hsp = run_hsp([0x11; 32], [0x22; 32], [0xA5; 32], [0x5C; 32]).await;
    let hsp_compute_ms = hsp.elapsed.as_millis() as u64;
    let hsp_bytes = hsp_comm_bytes();

    eprintln!("Measuring PGP (mac-then-encrypt Groth16) once…");
    let crs = setup().expect("pgp setup");
    let witness = MacThenEncryptWitness::new(
        [0x42; 32], [0x11; 16], [0x22; 16], [0xAA; 16], 1, 23, [3, 3],
    );
    let circuit = MacThenEncryptCircuit::from_witness(&witness, &[0x33; 32]);
    let t = Instant::now();
    let proof = prove(&crs, circuit).expect("pgp prove");
    let pgp_compute_ms = t.elapsed().as_millis() as u64;
    let pgp_bytes = proof.groth16_bytes.len();

    eprintln!(
        "Pure compute: HSP {} ms ({:.2} MB garbled), PGP {} ms ({} B proof).\n",
        hsp_compute_ms,
        hsp_bytes as f64 / (1024.0 * 1024.0),
        pgp_compute_ms,
        pgp_bytes
    );

    for profile in [WanProfile::lan(), WanProfile::wan1(), WanProfile::wan2()] {
        let row = apply_profile(hsp_compute_ms, hsp_bytes, pgp_compute_ms, pgp_bytes, &profile);
        print_table(&profile, &row);
    }
}
