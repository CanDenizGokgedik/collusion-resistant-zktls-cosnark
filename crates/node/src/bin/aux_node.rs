//! Auxiliary verifier node binary.
//!
//! Loads a FROST key share from disk and starts a TCP server that accepts
//! FROST round-1 and round-2 requests from the coordinator.
//!
//! # Usage
//!
//! ```bash
//! # First generate keys with dkg-ceremony:
//! cargo run --bin dkg-ceremony --features frost,tcp \
//!   -- --nodes 5 --threshold 3 --out-dir ./keys
//!
//! # Then start each aux node:
//! cargo run --bin aux-node --features frost,tcp \
//!   -- --config ./keys/node-0-config.json
//! ```
//!
//! # Config file format (JSON)
//!
//! ```json
//! {
//!   "node_index": 0,
//!   "listen_addr": "0.0.0.0:8080",
//!   "key_file": "keys/node-0.json",
//!   "group_key_file": "keys/group-key.json",
//!   "threshold": 3,
//!   "num_nodes": 5
//! }
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use tls_attestation_crypto::frost_adapter::{FrostParticipant, FrostGroupKey};
use tls_attestation_node::{FrostAuxiliaryNode, TcpAuxServer};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct NodeConfig {
    node_index: usize,
    listen_addr: String,
    key_file: String,
    #[allow(dead_code)]
    group_key_file: String,
    threshold: usize,
    num_nodes: usize,
}

fn usage() -> ! {
    eprintln!("Usage: aux-node --config CONFIG_FILE");
    eprintln!("  --config FILE   path to node JSON config file");
    std::process::exit(1);
}

fn parse_args() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let mut config: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config = Some(PathBuf::from(&args[i]));
            }
            _ => usage(),
        }
        i += 1;
    }
    config.unwrap_or_else(|| usage())
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    // ── Logging ────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let config_path = parse_args();

    // ── Load config ────────────────────────────────────────────────────────
    let config_bytes = std::fs::read(&config_path).unwrap_or_else(|e| {
        eprintln!("ERROR: read config {}: {e}", config_path.display());
        std::process::exit(1);
    });
    let config: NodeConfig = serde_json::from_slice(&config_bytes).unwrap_or_else(|e| {
        eprintln!("ERROR: parse config: {e}");
        std::process::exit(1);
    });

    tracing::info!(
        node_index = config.node_index,
        threshold = config.threshold,
        num_nodes = config.num_nodes,
        "Starting aux verifier node"
    );

    // ── Load key share — resolve relative to config file's directory ──────
    let config_dir = config_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let key_path = if PathBuf::from(&config.key_file).is_absolute() {
        PathBuf::from(&config.key_file)
    } else {
        config_dir.join(&config.key_file)
    };
    let key_bytes = std::fs::read(&key_path).unwrap_or_else(|e| {
        eprintln!("ERROR: read key file {}: {e}", key_path.display());
        std::process::exit(1);
    });
    let participant = FrostParticipant::from_json_bytes(&key_bytes).unwrap_or_else(|e| {
        eprintln!("ERROR: load participant key: {e}");
        std::process::exit(1);
    });

    tracing::info!(
        verifier_id = %hex::encode(participant.verifier_id().as_bytes()),
        "Loaded FROST key share"
    );

    // ── Start server ───────────────────────────────────────────────────────
    let node = Arc::new(FrostAuxiliaryNode::new(participant));
    let server = TcpAuxServer::bind(&config.listen_addr, Arc::clone(&node))
        .unwrap_or_else(|e| {
            eprintln!("ERROR: bind {}: {e}", config.listen_addr);
            std::process::exit(1);
        });

    tracing::info!(
        addr = %server.local_addr(),
        "Aux node listening — waiting for coordinator connections"
    );

    println!("Aux node {} ready on {}", config.node_index, server.local_addr());
    println!("Press Ctrl-C to stop.");

    // Block the main thread — the server runs in background threads.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        tracing::info!(
            node_index = config.node_index,
            addr = %server.local_addr(),
            "heartbeat"
        );
    }
}