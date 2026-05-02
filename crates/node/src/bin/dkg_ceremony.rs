//! DKG Ceremony binary — one-time trusted-dealer key generation.
//!
//! Generates FROST key shares for all aux verifier nodes and writes each
//! share to a separate JSON file. In production replace with a Pedersen DKG
//! ceremony (`run_dkg_ceremony`) where no single party sees the full key.
//!
//! # Usage
//!
//! ```bash
//! cargo run --package tls-attestation-node --bin dkg-ceremony \
//!   --features frost,tcp \
//!   -- --nodes 5 --threshold 3 --out-dir ./keys
//! ```
//!
//! Writes:
//!   keys/node-0.json   ← key share for aux node 0
//!   keys/node-1.json   ← key share for aux node 1
//!   ...
//!   keys/group-key.json ← public group key (safe to share)

use std::path::PathBuf;
use tls_attestation_crypto::{
    frost_adapter::{frost_trusted_dealer_keygen, FrostGroupKey},
};
use tls_attestation_core::ids::VerifierId;

fn usage() -> ! {
    eprintln!("Usage: dkg-ceremony --nodes N --threshold T --out-dir DIR");
    eprintln!("  --nodes N       total number of aux verifier nodes");
    eprintln!("  --threshold T   minimum signers required (t-of-n)");
    eprintln!("  --out-dir DIR   directory to write key files");
    std::process::exit(1);
}

fn parse_args() -> (usize, usize, PathBuf) {
    let args: Vec<String> = std::env::args().collect();
    let mut nodes: Option<usize> = None;
    let mut threshold: Option<usize> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--nodes" => {
                i += 1;
                nodes = Some(args[i].parse().unwrap_or_else(|_| usage()));
            }
            "--threshold" => {
                i += 1;
                threshold = Some(args[i].parse().unwrap_or_else(|_| usage()));
            }
            "--out-dir" => {
                i += 1;
                out_dir = Some(PathBuf::from(&args[i]));
            }
            _ => usage(),
        }
        i += 1;
    }
    (
        nodes.unwrap_or_else(|| usage()),
        threshold.unwrap_or_else(|| usage()),
        out_dir.unwrap_or_else(|| usage()),
    )
}

fn main() {
    let (n, t, out_dir) = parse_args();

    if t < 2 {
        eprintln!("ERROR: threshold must be >= 2 (FROST requirement)");
        std::process::exit(1);
    }
    if t > n {
        eprintln!("ERROR: threshold {} > nodes {}", t, n);
        std::process::exit(1);
    }

    std::fs::create_dir_all(&out_dir).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot create output dir: {e}");
        std::process::exit(1);
    });

    // Generate unique VerifierIds for each node.
    let verifier_ids: Vec<VerifierId> = (0..n)
        .map(|i| {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            id[8] = 0xAB; // marker byte
            VerifierId::from_bytes(id)
        })
        .collect();

    println!("Running trusted-dealer DKG ceremony: {t}-of-{n}...");
    let output = frost_trusted_dealer_keygen(&verifier_ids, t)
        .unwrap_or_else(|e| {
            eprintln!("ERROR: DKG failed: {e}");
            std::process::exit(1);
        });

    // Write each participant's key share.
    for (i, participant) in output.participants.iter().enumerate() {
        let path = out_dir.join(format!("node-{i}.json"));
        let bytes = participant.to_json_bytes().unwrap_or_else(|e| {
            eprintln!("ERROR: serialize participant {i}: {e}");
            std::process::exit(1);
        });
        std::fs::write(&path, &bytes).unwrap_or_else(|e| {
            eprintln!("ERROR: write {}: {e}", path.display());
            std::process::exit(1);
        });
        println!("  Wrote {}", path.display());
    }

    // Write the group public key.
    let group_path = out_dir.join("group-key.json");
    let group_bytes = output.group_key.to_json_bytes().unwrap_or_else(|e| {
        eprintln!("ERROR: serialize group key: {e}");
        std::process::exit(1);
    });
    std::fs::write(&group_path, &group_bytes).unwrap_or_else(|e| {
        eprintln!("ERROR: write {}: {e}", group_path.display());
        std::process::exit(1);
    });
    println!("  Wrote {}", group_path.display());

    // Write a config template for each node.
    for i in 0..n {
        let config = serde_json::json!({
            "node_index": i,
            "listen_addr": format!("0.0.0.0:{}", 8080 + i),
            "key_file": format!("node-{i}.json"),
            "group_key_file": "group-key.json",
            "threshold": t,
            "num_nodes": n,
        });
        let cfg_path = out_dir.join(format!("node-{i}-config.json"));
        std::fs::write(&cfg_path, serde_json::to_string_pretty(&config).unwrap())
            .unwrap_or_else(|e| {
                eprintln!("ERROR: write config {i}: {e}");
                std::process::exit(1);
            });
        println!("  Wrote {}", cfg_path.display());
    }

    println!("\nDKG ceremony complete.");
    println!("Start each aux node with:");
    println!("  cargo run --bin aux-node --features frost,tcp -- --config keys/node-N-config.json");
}
