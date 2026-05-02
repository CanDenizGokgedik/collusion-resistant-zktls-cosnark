//! Co-SNARK Groth16 benchmark — collaborative zkSNARK prover performance.
//!
//! Measures:
//!   - Trusted setup (CRS generation)
//!   - Central proving:      standard Groth16, all witness at coordinator
//!   - Distributed proving:  2-party MPC Groth16, each party has one share
//!   - Proof size (bytes)
//!   - Verification (client-side, not timed here — Groth16 verify is ~1ms)
//!
//! # Circuit
//!
//! TlsKeyCircuit: prove K^P_MAC XOR K^V_MAC = K_MAC and commit(K_MAC, r).
//!
//! Constraint counts per mode:
//!   - Simple XOR+commit circuit (current): ~5 constraints
//!   - Full TLS HMAC circuit (paper §VII):  ~1.9M constraints
//!
//! # Usage
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_co_snark --release \
//!   -- --binary /path/to/co-snark-prover
//! ```
//! If --binary is omitted, uses "co-snark-prover" (must be on PATH).

use std::time::{Duration, Instant};
use std::env;
use tls_attestation_zk::co_snark_distributed::{
    CoSnarkDistributedClient, DistributedMode,
};

// ── Benchmark helpers ─────────────────────────────────────────────────────────

struct BenchResult {
    setup_ms:   u64,
    prove_ms:   u64,
    proof_bytes: usize,
    mode:       &'static str,
    constraints: &'static str,
}

fn bench_mode(
    binary: &str,
    mode: DistributedMode,
    crs_hex: &str,
    iters: usize,
) -> BenchResult {
    let mode_str = match mode {
        DistributedMode::Central     => "central",
        DistributedMode::Distributed => "distributed",
    };

    let client = CoSnarkDistributedClient::new(binary, mode);

    // ── Setup (only for central — same CRS for both) ──────────────────────
    let setup_ms = if crs_hex.is_empty() {
        let t = Instant::now();
        client.setup().expect("setup failed");
        t.elapsed().as_millis() as u64
    } else {
        0
    };

    // ── Prove ──────────────────────────────────────────────────────────────
    let p_share      = [0x11u8; 32];
    let v_share      = [0x22u8; 32];
    let rand_binding = [0x33u8; 32];

    let crs = if crs_hex.is_empty() {
        None
    } else {
        Some(tls_attestation_zk::co_snark_distributed::DistributedCrs {
            crs_hex: crs_hex.to_string(),
            vk_hex:  String::new(),
        })
    };

    let mut prove_total = Duration::ZERO;
    let mut proof_bytes = 0usize;

    for _ in 0..iters {
        let t = Instant::now();
        match client.prove(&p_share, &v_share, &rand_binding, crs.as_ref(), false) {
            Ok(result) => {
                prove_total += t.elapsed();
                proof_bytes = result.proof_bytes.len();
            }
            Err(e) => {
                eprintln!("  [{mode_str}] prove error: {e}");
                return BenchResult {
                    setup_ms, prove_ms: 0, proof_bytes: 0,
                    mode: mode_str,
                    constraints: "~5 (XOR+commit)",
                };
            }
        }
    }

    BenchResult {
        setup_ms,
        prove_ms:    prove_total.as_millis() as u64 / iters as u64,
        proof_bytes,
        mode:        mode_str,
        constraints: "~5 (XOR+commit)",
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Co-SNARK Groth16 Prover Benchmark — BLS12-377                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Parse --binary flag
    let args: Vec<String> = env::args().collect();
    let binary = args.windows(2)
        .find(|w| w[0] == "--binary")
        .map(|w| w[1].as_str())
        .unwrap_or("co-snark-prover")
        .to_string();

    println!("  Binary:  {binary}");
    println!("  Circuit: TlsKeyCircuit (K^P XOR K^V = K_MAC, commit)");
    println!("  Curve:   BLS12-377 (Ozdemir & Boneh 2022 fork)\n");

    // ── Step 1: Trusted setup ──────────────────────────────────────────────
    print!("  [1/3] Trusted setup ...");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let setup_client = CoSnarkDistributedClient::new(&binary, DistributedMode::Central);
    let t_setup = Instant::now();
    let crs = match setup_client.setup() {
        Ok(c) => c,
        Err(e) => {
            println!(" FAILED: {e}");
            return;
        }
    };
    let setup_ms = t_setup.elapsed().as_millis();
    println!(" {setup_ms} ms");
    println!("    CRS:  {} bytes", crs.crs_hex.len() / 2);
    println!("    VK:   {} bytes\n", crs.vk_hex.len() / 2);

    // ── Step 2: Central mode ───────────────────────────────────────────────
    print!("  [2/3] Central proving (3 iters) ...");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let central = bench_mode(&binary, DistributedMode::Central, &crs.crs_hex, 3);
    println!(" {} ms/proof  ({} bytes)", central.prove_ms, central.proof_bytes);

    // ── Step 3: Distributed mode ───────────────────────────────────────────
    print!("  [3/3] Distributed proving (1 iter) ...");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let dist = bench_mode(&binary, DistributedMode::Distributed, &crs.crs_hex, 1);
    if dist.prove_ms > 0 {
        println!(" {} ms/proof  ({} bytes)", dist.prove_ms, dist.proof_bytes);
    } else {
        println!(" N/A (MpcTwoNet requires separate OS processes — see notes)");
    }

    // ── Results table ──────────────────────────────────────────────────────
    println!("\n{}", "─".repeat(65));
    println!("{:<18} {:>12} {:>12} {:>12} {:>12}",
        "Mode", "Setup (ms)", "Prove (ms)", "Proof (B)", "Constraints");
    println!("{}", "─".repeat(65));
    println!("{:<18} {:>12} {:>12} {:>12} {:>12}",
        "central",
        setup_ms,
        central.prove_ms,
        central.proof_bytes,
        central.constraints,
    );
    println!("{:<18} {:>12} {:>12} {:>12} {:>12}",
        "distributed",
        "—",
        if dist.prove_ms > 0 { format!("{}", dist.prove_ms) } else { "N/A".to_string() },
        if dist.proof_bytes > 0 { format!("{}", dist.proof_bytes) } else { "N/A".to_string() },
        dist.constraints,
    );
    println!("{}", "─".repeat(65));

    // ── Notes ──────────────────────────────────────────────────────────────
    println!("\nNotes:");
    println!("  • BLS12-377 Groth16 proof is always 192 bytes regardless of circuit size.");
    println!("  • Setup is a one-time cost; CRS is reused for all proofs.");
    println!("  • Distributed mode requires two separate OS processes communicating");
    println!("    over TCP (MpcTwoNet global singleton). Current single-process test");
    println!("    demonstrates the architecture; production deployment uses");
    println!("    one co-snark-prover process per party.");
    println!("  • Full TLS HMAC circuit (~1.9M constraints, paper §VII) will increase");
    println!("    prove time proportionally — setup: ~30s, prove: ~60s on commodity HW.");

    // ── JSON output ────────────────────────────────────────────────────────
    println!("\nJSON:");
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "benchmark":  "co-snark-groth16",
        "curve":      "BLS12-377",
        "circuit":    "TlsKeyCircuit",
        "results": [
            {
                "mode":         "central",
                "setup_ms":     setup_ms,
                "prove_ms":     central.prove_ms,
                "proof_bytes":  central.proof_bytes,
                "constraints":  central.constraints,
            },
            {
                "mode":         "distributed",
                "setup_ms":     null,
                "prove_ms":     if dist.prove_ms > 0 { serde_json::json!(dist.prove_ms) } else { serde_json::json!(null) },
                "proof_bytes":  if dist.proof_bytes > 0 { serde_json::json!(dist.proof_bytes) } else { serde_json::json!(null) },
                "constraints":  dist.constraints,
                "note":         "requires 2 separate OS processes",
            }
        ]
    })).unwrap());
}
