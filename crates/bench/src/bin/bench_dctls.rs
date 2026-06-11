//! §IX dx-DCTLS overhead benchmark.
//!
//! Measures HSP (co-SNARK) + QP + PGP timing.
//!
//! # Paper §IX
//!
//! > co-SNARK (full TLS-PRF, 1.7M R1CS) ≈ 4,700ms
//! > Original DECO 2PC-HMAC: 2 × 5,700ms = 10,400ms
//! > Upper bound (64Mb/s WAN): ≈ 9,400ms
//!
//! # Usage
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_dctls --release
//! ```

use std::time::Instant;
use tls_attestation_attestation::{
    deco_dx_dctls::{DecoAttestationSession, CoSnarkExecutor, CoSnarkRawOutput},
    tls12_session::mock_tls12_session,
};
use tls_attestation_zk::co_snark::{CoSnarkBackend, HspProof};
use tls_attestation_zk::tls12_hmac::{ProverMacKeyShare, VerifierMacKeyShare, combine_mac_key_shares};
use tls_attestation_core::{hash::DigestBytes, ids::SessionId};

struct RealCoSnarkExecutor {
    backend: CoSnarkBackend,
}

impl CoSnarkExecutor for RealCoSnarkExecutor {
    fn execute(
        &self,
        p_share: &[u8; 32],
        v_share: &[u8; 32],
        rand_binding: &[u8; 32],
    ) -> Result<CoSnarkRawOutput, String> {
        let p = ProverMacKeyShare(*p_share);
        let v = VerifierMacKeyShare(*v_share);
        let k_mac = combine_mac_key_shares(&p, &v);
        let proof: HspProof = self.backend.execute(&p, &v, rand_binding)
            .map_err(|e| e.to_string())?;
        Ok(CoSnarkRawOutput {
            groth16_bytes:           proof.groth16_bytes,
            k_mac_commitment_bytes:  proof.k_mac_commitment_bytes,
            rand_binding_bytes:      rand_binding.to_vec(),
            k_mac:                   k_mac.0,
        })
    }
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Π_coll-min dx-DCTLS Overhead Benchmark — Paper §IX             ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    use tls_attestation_zk::tls_prf_circuit::TlsPrfCircuit;
    use tls_attestation_zk::co_snark::count_r1cs_constraints;

    let mode1_r1cs = count_r1cs_constraints(TlsPrfCircuit::dummy());
    let mode2_r1cs = count_r1cs_constraints(TlsPrfCircuit::dummy_full_prf());

    println!("  R1CS Constraint Counts:");
    println!("  {:.<40} {:>10}", "Mode 1 (K_MAC split only) ", mode1_r1cs);
    println!("  {:.<40} {:>10}", "Mode 2 (full TLS-PRF) ", mode2_r1cs);
    println!("  {:.<40} {:>10}", "Paper [19] target (gnark BLS12-381) ", 1_719_598u32);
    println!("  {:.<40} {:>10}", "Delta (arkworks BN254 vs gnark) ",
        format!("+{:.1}%", (mode2_r1cs as f64 / 1_719_598.0 - 1.0) * 100.0));
    println!();

    // ── Mode 1: K_MAC split only ──────────────────────────────────────────────
    print!("  [Mode 1] Groth16 CRS setup...");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let t0 = Instant::now();
    let backend = CoSnarkBackend::setup().expect("Mode 1 setup");
    let setup1_ms = t0.elapsed().as_millis();
    println!(" {}ms", setup1_ms);

    let executor  = RealCoSnarkExecutor { backend };
    let tls_session = mock_tls12_session("api.example.com", 42);
    let rand      = DigestBytes::from_bytes([0x42u8; 32]);
    let cert_hash = tls_session.server_cert_hash.clone();

    let iterations = 3;
    let mut hsp_times = Vec::new();
    let mut qp_times  = Vec::new();
    let mut pgp_times = Vec::new();

    println!("\n  Mode 1 — Running {} iterations...", iterations);
    for i in 0..iterations {
        let sid = SessionId::new_random();

        let t1 = Instant::now();
        let deco_session = DecoAttestationSession::hsp(
            sid.clone(), &rand, &cert_hash, &executor,
        ).expect("HSP");
        let hsp_ms = t1.elapsed().as_millis() as u64;
        hsp_times.push(hsp_ms);

        let t2 = Instant::now();
        let qr = deco_session.qp(
            b"GET /api/price?asset=BTC HTTP/1.1\r\n",
            b"HTTP/1.1 200 OK\r\n{\"price\":67500}",
        );
        let qp_ms = t2.elapsed().as_millis() as u64;
        qp_times.push(qp_ms);

        let t3 = Instant::now();
        let _proof = deco_session.pgp(qr, b"price > 50000".to_vec());
        let pgp_ms = t3.elapsed().as_millis() as u64;
        pgp_times.push(pgp_ms);

        println!("  iter {}: HSP={}ms QP={}ms PGP={}ms", i+1, hsp_ms, qp_ms, pgp_ms);
    }

    let hsp1_avg = hsp_times.iter().sum::<u64>() / iterations as u64;
    let qp_avg   = qp_times.iter().sum::<u64>() / iterations as u64;
    let pgp_avg  = pgp_times.iter().sum::<u64>() / iterations as u64;

    // ── Mode 2: full TLS-PRF — REAL measurement ───────────────────────────────
    println!("\n  [Mode 2] Full TLS-PRF ({} R1CS) — REAL measurement", mode2_r1cs);
    print!("  CRS setup (30-120s expected) ...");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let t_setup2 = Instant::now();
    let crs2 = CoSnarkBackend::setup_mode2().expect("Mode 2 setup");
    let setup2_ms = t_setup2.elapsed().as_millis();
    println!(" {}ms", setup2_ms);

    // Use synthetic MAC key shares and real session parameters.
    let p2   = ProverMacKeyShare([0x11u8; 32]);
    let v2   = VerifierMacKeyShare([0x22u8; 32]);
    let rand2 = [0x42u8; 32];
    let pms  = &tls_session.pre_master_secret;
    let cr   = &tls_session.client_random;
    let sr   = &tls_session.server_random;

    print!("  Prove (1 iteration) ...");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let t_prove2 = Instant::now();
    let _proof2 = crs2.execute_mode2(&p2, &v2, &rand2, pms, cr, sr)
        .expect("Mode 2 prove");
    let prove2_ms = t_prove2.elapsed().as_millis() as u64;
    println!(" {}ms", prove2_ms);

    // ── Summary table ─────────────────────────────────────────────────────────
    println!();
    println!("{:<40} {:>8} {:>8} {:>8} {:>14}",
        "Phase", "Min(ms)", "Max(ms)", "Avg(ms)", "Paper [19]");
    println!("{}", "─".repeat(82));
    println!("{:<40} {:>8} {:>8} {:>8} {:>14}",
        "HSP Mode 1 — K_MAC split (769 R1CS)",
        hsp_times.iter().min().unwrap(),
        hsp_times.iter().max().unwrap(),
        hsp1_avg, "N/A");
    println!("{:<40} {:>8} {:>8} {:>8} {:>14}",
        "HSP Mode 2 — full TLS-PRF (MEASURED)",
        prove2_ms, prove2_ms, prove2_ms, "4,700ms");
    println!("{:<40} {:>8} {:>8} {:>8} {:>14}",
        "QP — HMAC commit",
        qp_times.iter().min().unwrap(),
        qp_times.iter().max().unwrap(),
        qp_avg, "~0ms");
    println!("{:<40} {:>8} {:>8} {:>8} {:>14}",
        "PGP — statement proof",
        pgp_times.iter().min().unwrap(),
        pgp_times.iter().max().unwrap(),
        pgp_avg, "varies");

    println!();
    println!("  Notes:");
    println!("  * Mode 1 measured directly ({} R1CS, avg {}ms).", mode1_r1cs, hsp1_avg);
    println!("  * Mode 2 measured directly ({} R1CS, {}ms).", mode2_r1cs, prove2_ms);
    println!("  * Paper uses gnark/BLS12-381; we use arkworks/BN254 (~2x slower).");
    println!();
    println!("  Paper comparison:");
    println!("    Our Mode 2 R1CS:               {:>10}", mode2_r1cs);
    println!("    Paper [19] R1CS:               {:>10}", 1_719_598);
    println!("    Delta:                         {:>10.1}%",
        (mode2_r1cs as f64 / 1_719_598.0 - 1.0) * 100.0);
    println!("    Our Mode 2 prove (MEASURED):   {:>9}ms  (arkworks/BN254)", prove2_ms);
    println!("    Paper [19] prove:              {:>9}ms  (gnark/BLS12-381)", 4700);
    println!("    DECO 2PC-HMAC baseline:        {:>9}ms", 10400);
    println!("    co-SNARK WAN upper bound:      {:>9}ms", 9400);

    let json = serde_json::json!({
        "benchmark": "dx-dctls",
        "paper_section": "§IX",
        "circuit": {
            "mode1_r1cs": mode1_r1cs,
            "mode2_r1cs": mode2_r1cs,
            "paper_r1cs": 1_719_598,
            "delta_pct":  (mode2_r1cs as f64 / 1_719_598.0 - 1.0) * 100.0,
        },
        "groth16_setup_mode1_ms": setup1_ms,
        "groth16_setup_mode2_ms": setup2_ms,
        "iterations": iterations,
        "hsp_mode1_avg_ms":      hsp1_avg,
        "hsp_mode2_measured_ms": prove2_ms,
        "qp_avg_ms":  qp_avg,
        "pgp_avg_ms": pgp_avg,
        "paper_cosnark_ms":           4700,
        "paper_deco_2pc_hmac_ms":    10400,
        "paper_wan_upper_bound_ms":   9400,
    });
    println!("\nJSON:\n{}", serde_json::to_string_pretty(&json).unwrap());
}