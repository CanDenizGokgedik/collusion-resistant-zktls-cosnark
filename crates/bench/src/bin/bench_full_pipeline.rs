//! Full Π_coll-min end-to-end pipeline benchmark.
//!
//! RC Phase → dx-DCTLS (real co-SNARK) → FROST Sign → on-chain ABI encoding
//!
//! Demonstrates O(1) prover complexity (paper Table II).
//!
//! # Usage
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_full_pipeline --release \
//!   -- --binary /path/to/co-snark-prover
//! ```

use std::time::Instant;
use std::env;
use std::sync::{Arc, Mutex};
use rand::rngs::OsRng;
use tls_attestation_crypto::{
    dkg_secp256k1::run_secp256k1_dkg,
    dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput},
    frost_secp256k1_adapter::{
        secp256k1_build_signing_package, secp256k1_aggregate_signature_shares,
    },
};
use tls_attestation_attestation::{
    deco_dx_dctls::{DecoAttestationSession, CoSnarkExecutor, CoSnarkRawOutput},
    onchain_secp256k1::OnChainAttestationSecp256k1,
    tls12_session::mock_tls12_session,
};
use tls_attestation_zk::co_snark_distributed::{
    CoSnarkDistributedClient, DistributedCrs, DistributedMode, ProverServer,
};
use tls_attestation_core::{hash::DigestBytes, ids::{SessionId, VerifierId}};

// ── Real co-SNARK executor ────────────────────────────────────────────────────

/// Wraps a persistent ProverServer (central) or CoSnarkDistributedClient (MPC).
///
/// Central mode: spawns binary once with `--server`, CRS stays in memory.
/// Distributed mode: spawns fresh subprocess per call with crs_file on disk.
enum RealCoSnarkExecutor {
    Central {
        server: Arc<Mutex<Option<ProverServer>>>,
        binary: String,
    },
    Distributed {
        client: CoSnarkDistributedClient,
        crs:    Arc<Mutex<Option<DistributedCrs>>>,
    },
}

impl RealCoSnarkExecutor {
    fn new(binary: &str, mode: DistributedMode) -> Self {
        match mode {
            DistributedMode::Central => RealCoSnarkExecutor::Central {
                server: Arc::new(Mutex::new(None)),
                binary: binary.to_string(),
            },
            DistributedMode::Distributed => RealCoSnarkExecutor::Distributed {
                client: CoSnarkDistributedClient::new(binary, mode),
                crs:    Arc::new(Mutex::new(None)),
            },
        }
    }

    fn mode_label(&self) -> &'static str {
        match self {
            RealCoSnarkExecutor::Central { .. }      => "co-SNARK central",
            RealCoSnarkExecutor::Distributed { .. }  => "co-SNARK 2-party MPC",
        }
    }

    /// Warm up: spawn server and run setup (for central), or setup CRS (for distributed).
    fn warmup(&self) {
        match self {
            RealCoSnarkExecutor::Central { server, binary } => {
                let mut guard = server.lock().unwrap();
                if guard.is_none() {
                    *guard = Some(ProverServer::spawn(binary).expect("server spawn failed"));
                }
            }
            RealCoSnarkExecutor::Distributed { client, crs } => {
                let mut guard = crs.lock().unwrap();
                if guard.is_none() {
                    *guard = Some(client.setup().expect("co-SNARK setup failed"));
                }
            }
        }
    }
}

impl CoSnarkExecutor for RealCoSnarkExecutor {
    fn execute(
        &self,
        p_share:      &[u8; 32],
        v_share:      &[u8; 32],
        rand_binding: &[u8; 32],
    ) -> Result<CoSnarkRawOutput, String> {
        match self {
            RealCoSnarkExecutor::Central { server, binary } => {
                let mut guard = server.lock().unwrap();
                if guard.is_none() {
                    *guard = Some(ProverServer::spawn(binary).map_err(|e| e.to_string())?);
                }
                let srv = guard.as_mut().unwrap();
                let result = srv.prove(p_share, v_share, rand_binding, false)
                    .map_err(|e| e.to_string())?;
                Ok(CoSnarkRawOutput {
                    groth16_bytes:          result.proof_bytes,
                    k_mac_commitment_bytes: result.public_inputs.first().cloned()
                                               .unwrap_or_else(|| vec![0u8; 32]),
                    rand_binding_bytes:     rand_binding.to_vec(),
                    k_mac:                  result.k_mac,
                })
            }
            RealCoSnarkExecutor::Distributed { client, crs } => {
                let mut guard = crs.lock().unwrap();
                if guard.is_none() {
                    *guard = Some(client.setup().map_err(|e| e.to_string())?);
                }
                let c = guard.as_ref().unwrap();
                let result = client.prove(p_share, v_share, rand_binding, Some(c), false)
                    .map_err(|e| e.to_string())?;
                Ok(CoSnarkRawOutput {
                    groth16_bytes:          result.proof_bytes,
                    k_mac_commitment_bytes: result.public_inputs.first().cloned()
                                               .unwrap_or_else(|| vec![0u8; 32]),
                    rand_binding_bytes:     rand_binding.to_vec(),
                    k_mac:                  result.k_mac,
                })
            }
        }
    }
}

// ── Stub executor (used when --stub flag is passed) ───────────────────────────

struct StubCoSnark;
impl CoSnarkExecutor for StubCoSnark {
    fn execute(
        &self,
        p_share: &[u8; 32],
        v_share: &[u8; 32],
        rand_binding: &[u8; 32],
    ) -> Result<CoSnarkRawOutput, String> {
        let mut k_mac = [0u8; 32];
        for i in 0..32 { k_mac[i] = p_share[i] ^ v_share[i]; }
        Ok(CoSnarkRawOutput {
            groth16_bytes:          vec![0u8; 128],
            k_mac_commitment_bytes: vec![0u8; 32],
            rand_binding_bytes:     rand_binding.to_vec(),
            k_mac,
        })
    }
}

// ── Pipeline runner ───────────────────────────────────────────────────────────

fn run_pipeline<E: CoSnarkExecutor>(
    executor: &E,
    threshold: usize,
    n_verifiers: usize,
) -> (u64, u64, u64, u64, u64, u64) {
    let ids: Vec<VerifierId> = (0..n_verifiers as u8).map(|i| {
        VerifierId::from_bytes({ let mut b = [0u8; 32]; b[0] = i; b })
    }).collect();
    let alpha = DigestBytes::from_bytes([0x42u8; 32]);

    // ── RC Phase: DKG ─────────────────────────────────────────────────────────
    let t0 = Instant::now();
    let dkg_outputs = run_secp256k1_dkg(&ids, threshold).expect("DKG");
    let dkg_ms = t0.elapsed().as_millis() as u64;

    // ── RC Phase: DVRF ────────────────────────────────────────────────────────
    let t_dvrf = Instant::now();
    let input = Secp256k1DvrfInput::new(alpha.clone());
    let partial_evals: Vec<_> = (0..threshold)
        .map(|i| Secp256k1Dvrf::partial_eval(&dkg_outputs[i].participant, &input).unwrap())
        .collect();
    let participant_refs: Vec<_> = (0..threshold)
        .map(|i| &dkg_outputs[i].participant)
        .collect();
    let dvrf_out = Secp256k1Dvrf::combine(
        &dkg_outputs[0].group_key, &input, partial_evals, &participant_refs,
    ).unwrap();
    let rand = dvrf_out.rand.clone();
    let dvrf_ms = t_dvrf.elapsed().as_millis() as u64;

    // ── HSP (K_MAC split + co-SNARK proof) ────────────────────────────────────
    let t1 = Instant::now();
    let tls_session = mock_tls12_session("api.example.com", 1);
    let sid = SessionId::new_random();
    let deco_session = DecoAttestationSession::hsp(
        sid, &rand, &tls_session.server_cert_hash, executor,
    ).expect("HSP");
    let hsp_ms = t1.elapsed().as_millis() as u64;

    // ── QP + PGP (query commit + proof assembly) ──────────────────────────────
    let t_pgp = Instant::now();
    let qr = deco_session.qp(
        b"GET /price?asset=BTC",
        b"HTTP/1.1 200 OK\r\n{\"price\":67500}",
    );
    let _proof = deco_session.pgp(qr, b"price > 50000".to_vec());
    let pgp_ms = t_pgp.elapsed().as_millis() as u64;

    // ── Signing Phase (FROST) ─────────────────────────────────────────────────
    let t2 = Instant::now();
    let message = DigestBytes::from_bytes([0xEEu8; 32]);
    let r1_results: Vec<_> = (0..threshold)
        .map(|i| dkg_outputs[i].participant.round1(&mut OsRng).unwrap())
        .collect();
    let (nonces, commitments): (Vec<_>, Vec<_>) = r1_results.into_iter().unzip();
    let pkg = secp256k1_build_signing_package(&commitments, &message).unwrap();
    let shares: Vec<_> = nonces.into_iter().enumerate()
        .map(|(i, n)| dkg_outputs[i].participant.round2(&pkg, n).unwrap())
        .collect();
    let approval = secp256k1_aggregate_signature_shares(
        &pkg, &shares, &dkg_outputs[0].group_key,
    ).unwrap();
    let sign_ms = t2.elapsed().as_millis() as u64;

    // ── On-chain ABI encoding ─────────────────────────────────────────────────
    let t3 = Instant::now();
    let mut sig_rx = [0u8; 32];
    let mut sig_s  = [0u8; 32];
    let mut gk_x   = [0u8; 32];
    let gk_y       = [0u8; 32];
    let sig = &approval.aggregate_signature_bytes;
    sig_rx.copy_from_slice(&sig[1..33]);
    sig_s.copy_from_slice(&sig[33..65]);
    let gk = &approval.group_verifying_key_bytes;
    gk_x.copy_from_slice(&gk[1..33]);
    let att = OnChainAttestationSecp256k1 {
        statement_digest: [0x11u8; 32],
        dvrf_value:       *rand.as_bytes(),
        envelope_digest:  [0xEEu8; 32],
        group_key_x:      gk_x,
        group_key_y:      gk_y,
        sig_R_x:          sig_rx,
        sig_s,
        threshold:        threshold as u8,
        verifier_count:   n_verifiers as u8,
        alpha_commitment: [0x42u8; 32],
        session_id:       [0x00u8; 32],
    };
    let encoded = att.abi_encode();
    assert_eq!(encoded.len(), 352, "ABI encoding must be 352 bytes");
    let onchain_ms = t3.elapsed().as_millis() as u64;

    (dkg_ms, dvrf_ms, hsp_ms, pgp_ms, sign_ms, onchain_ms)
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Π_coll-min Full Pipeline — RC → dx-DCTLS → FROST → On-Chain   ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    println!("  Demonstrates O(1) prover complexity (paper Table II).\n");

    let args: Vec<String> = env::args().collect();
    let use_stub        = args.iter().any(|a| a == "--stub");
    let use_distributed = args.iter().any(|a| a == "--distributed");
    let binary = args.windows(2)
        .find(|w| w[0] == "--binary")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "co-snark-prover".to_string());

    if use_stub {
        println!("  Mode: STUB (no real Groth16 — use --binary /path/to/co-snark-prover for real)\n");
        run_table(&StubCoSnark, "stub");
    } else {
        let mode = if use_distributed {
            DistributedMode::Distributed
        } else {
            DistributedMode::Central
        };

        let executor = RealCoSnarkExecutor::new(&binary, mode);

        println!("  Mode: {}", executor.mode_label());
        if use_distributed {
            println!("  MPC: 2-party localhost TCP (Ozdemir & Boneh collaborative-zksnark)");
        }
        println!("  Binary: {binary}");

        // Trusted setup (once — same CRS works for both modes)
        print!("\n  [setup] Generating CRS ...");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let t_setup = Instant::now();
        executor.warmup();
        let setup_ms = t_setup.elapsed().as_millis();
        println!(" {setup_ms} ms  (reused for all iterations)\n");

        run_table(&executor, executor.mode_label());
    }

    // Paper comparison table
    println!("\n  Paper Table II comparison:");
    println!("  ┌─────────────────────────┬──────────┬───────────┬──────────────┐");
    println!("  │ Prover Complexity       │ O(1)     │ O(n)      │ O(1) ←       │");
    println!("  │ Public Verifiability    │ No       │ Yes       │ Yes          │");
    println!("  │ Collusion Resistance    │ No       │ Yes       │ Yes          │");
    println!("  │ Auxiliary Node Load     │ N/A      │ Heavy     │ Lightweight  │");
    println!("  └─────────────────────────┴──────────┴───────────┴──────────────┘");
    println!("                             DECO      DECO-DON    Π_coll-min");
}

fn run_table<E: CoSnarkExecutor>(executor: &E, label: &str) {
    println!("  {:12} {:>8} {:>7} {:>12} {:>7} {:>10} {:>10}",
        "Config", "DKG(ms)", "DVRF", label, "PGP", "Sign(ms)", "Total(ms)");
    println!("{}", "─".repeat(85));

    let mut results = Vec::new();
    let configs = [(2, 3), (3, 5), (5, 9), (7, 13), (10, 19), (15, 29), (20, 39), (30, 59), (50, 99)];

    for (t, n) in configs {
        print!("  {:12}", format!("{}-of-{}", t, n));
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let (dkg, dvrf, hsp, pgp, sign, onchain) = run_pipeline(executor, t, n);
        let total = dkg + dvrf + hsp + pgp + sign + onchain;
        println!("{:>8} {:>7} {:>12} {:>7} {:>10} {:>10}", dkg, dvrf, hsp, pgp, sign, total);
        results.push(serde_json::json!({
            "config": format!("{}-of-{}", t, n),
            "dkg_ms": dkg, "dvrf_ms": dvrf,
            "hsp_ms": hsp, "pgp_ms": pgp,
            "sign_ms": sign, "onchain_ms": onchain,
            "total_ms": total,
        }));
    }

    println!("\nJSON:");
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "benchmark": "pi-coll-min-full-pipeline",
        "mode": label,
        "paper_section": "§VIII, Table II",
        "results": results,
    })).unwrap());
}