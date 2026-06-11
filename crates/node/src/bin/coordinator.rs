//! Coordinator node binary.
//!
//! Accepts attestation requests over HTTP, drives the distributed FROST
//! signing protocol across aux verifier nodes, and returns a signed
//! `FrostAttestationEnvelope`.
//!
//! # Usage
//!
//! ```bash
//! # After running dkg-ceremony and starting aux nodes:
//! cargo run --bin coordinator --features frost,tcp \
//!   -- --config ./keys/coordinator-config.json
//! ```
//!
//! # Config file format (JSON)
//!
//! ```json
//! {
//!   "listen_addr": "0.0.0.0:9090",
//!   "coordinator_id_hex": "0000000000000000ff000000000000000000000000000000000000000000000",
//!   "group_key_file": "keys/group-key.json",
//!   "threshold": 3,
//!   "aux_nodes": [
//!     { "verifier_id_hex": "...", "addr": "127.0.0.1:8080" },
//!     { "verifier_id_hex": "...", "addr": "127.0.0.1:8081" },
//!     { "verifier_id_hex": "...", "addr": "127.0.0.1:8082" }
//!   ],
//!   "db_path": "coordinator.db"
//! }
//! ```
//!
//! # HTTP API
//!
//! POST /attest
//!   Body: JSON AttestationRequest
//!   Response: JSON FrostAttestationEnvelope (on success)
//!             JSON { "error": "..." }          (on failure)

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;

use tls_attestation_attestation::{engine::PrototypeAttestationEngine, PrototypeAttestationEngine as _};
use tls_attestation_core::ids::VerifierId;
use tls_attestation_core::types::QuorumSpec;
use tls_attestation_crypto::frost_adapter::FrostGroupKey;
use tls_attestation_crypto::randomness::PrototypeDvrf;
#[cfg(feature = "secp256k1")]
use tls_attestation_crypto::randomness::Secp256k1DvrfEngine;
use tls_attestation_network::messages::AttestationRequest;
use tls_attestation_node::{
    coordinator::{CoordinatorConfig, CoordinatorNode},
    transport::FrostNodeTransport,
    TcpNodeTransport,
};
use tls_attestation_storage::InMemorySessionStore;

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct AuxNodeEntry {
    verifier_id_hex: String,
    addr: String,
}

#[derive(serde::Deserialize)]
struct CoordConfig {
    listen_addr: String,
    coordinator_id_hex: String,
    group_key_file: String,
    threshold: usize,
    aux_nodes: Vec<AuxNodeEntry>,
    #[serde(default = "default_db")]
    #[allow(dead_code)]
    db_path: String,
    /// Paths to secp256k1 FROST participant key JSON files (one per aux node).
    /// When present, enables `Secp256k1DvrfEngine` (bias-resistant DVRF).
    /// When absent, falls back to `PrototypeDvrf` (WARNING: not bias-resistant).
    #[serde(default)]
    dvrf_participant_files: Vec<String>,
}

fn default_db() -> String { "coordinator.db".into() }

fn usage() -> ! {
    eprintln!("Usage: coordinator --config CONFIG_FILE");
    std::process::exit(1);
}

fn parse_args() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let mut config: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => { i += 1; config = Some(PathBuf::from(&args[i])); }
            _ => usage(),
        }
        i += 1;
    }
    config.unwrap_or_else(|| usage())
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn read_http_body(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; 8192];
    let mut headers = String::new();
    let mut body_start = 0usize;
    let mut total_read = 0usize;

    loop {
        let n = stream.read(&mut buf[total_read..]).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        total_read += n;
        let data = std::str::from_utf8(&buf[..total_read]).unwrap_or("");
        if let Some(pos) = data.find("\r\n\r\n") {
            headers = data[..pos].to_string();
            body_start = pos + 4;
            break;
        }
        if total_read >= buf.len() {
            return Err("request too large".into());
        }
    }

    let content_length: usize = headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    let mut body = buf[body_start..total_read].to_vec();

    while body.len() < content_length {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        body.extend_from_slice(&chunk[..n]);
    }

    Ok(body)
}

fn send_json_response(stream: &mut TcpStream, status: u16, body: &str) {
    let phrase = if status == 200 { "OK" } else { "Internal Server Error" };
    let response = format!(
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    let _ = stream.write_all(response.as_bytes());
}

// ── Request handler ───────────────────────────────────────────────────────────

fn handle_request<S, R>(
    mut stream: TcpStream,
    coordinator: &CoordinatorNode<S, R, PrototypeAttestationEngine>,
    transports: &[TcpNodeTransport],
    group_key: &FrostGroupKey,
) where
    S: tls_attestation_storage::traits::SessionStore,
    R: tls_attestation_crypto::randomness::RandomnessEngine,
{
    let body = match read_http_body(&mut stream) {
        Ok(b) => b,
        Err(e) => {
            send_json_response(&mut stream, 500, &format!(r#"{{"error":"read body: {e}"}}"#));
            return;
        }
    };

    let request: AttestationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            send_json_response(&mut stream, 400, &format!(r#"{{"error":"bad request: {e}"}}"#));
            return;
        }
    };

    let response_bytes: Vec<u8> = vec![];

    let transport_refs: Vec<&dyn tls_attestation_node::transport::FrostNodeTransport> =
        transports.iter().map(|t| t as &dyn tls_attestation_node::transport::FrostNodeTransport).collect();

    match coordinator.attest_frost_distributed_over_transport(
        request,
        &response_bytes,
        &transport_refs,
        group_key,
    ) {
        Ok(envelope) => {
            match serde_json::to_string(&envelope) {
                Ok(json) => send_json_response(&mut stream, 200, &json),
                Err(e) => send_json_response(&mut stream, 500, &format!(r#"{{"error":"serialize: {e}"}}"#)),
            }
        }
        Err(e) => {
            send_json_response(&mut stream, 500, &format!(r#"{{"error":"{e}"}}"#));
        }
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let config_path = parse_args();

    // ── Load config ────────────────────────────────────────────────────────
    let config_bytes = std::fs::read(&config_path).unwrap_or_else(|e| {
        eprintln!("ERROR: read config: {e}"); std::process::exit(1);
    });
    let config: CoordConfig = serde_json::from_slice(&config_bytes).unwrap_or_else(|e| {
        eprintln!("ERROR: parse config: {e}"); std::process::exit(1);
    });

    let config_dir = config_path.parent().unwrap_or_else(|| std::path::Path::new("."));

    // ── Load group key ─────────────────────────────────────────────────────
    let gk_path = if PathBuf::from(&config.group_key_file).is_absolute() {
        PathBuf::from(&config.group_key_file)
    } else {
        config_dir.join(&config.group_key_file)
    };
    let gk_bytes = std::fs::read(&gk_path).unwrap_or_else(|e| {
        eprintln!("ERROR: read group key {}: {e}", gk_path.display()); std::process::exit(1);
    });
    let group_key = FrostGroupKey::from_json_bytes(&gk_bytes).unwrap_or_else(|e| {
        eprintln!("ERROR: parse group key: {e}"); std::process::exit(1);
    });

    // ── Build coordinator ID ───────────────────────────────────────────────
    let coord_id_bytes = hex::decode(&config.coordinator_id_hex).unwrap_or_else(|e| {
        eprintln!("ERROR: coordinator_id_hex: {e}"); std::process::exit(1);
    });
    let coord_id_arr: [u8; 32] = coord_id_bytes.try_into().unwrap_or_else(|_| {
        eprintln!("ERROR: coordinator_id must be 32 bytes"); std::process::exit(1);
    });
    let coordinator_id = VerifierId::from_bytes(coord_id_arr);

    // ── Build aux node transports ──────────────────────────────────────────
    let transports: Vec<TcpNodeTransport> = config.aux_nodes.iter().map(|entry| {
        let vid_bytes = hex::decode(&entry.verifier_id_hex).unwrap_or_else(|e| {
            eprintln!("ERROR: verifier_id_hex: {e}"); std::process::exit(1);
        });
        let vid_arr: [u8; 32] = vid_bytes.try_into().unwrap_or_else(|_| {
            eprintln!("ERROR: verifier_id must be 32 bytes"); std::process::exit(1);
        });
        let vid = VerifierId::from_bytes(vid_arr);
        TcpNodeTransport::new(vid, &entry.addr).unwrap_or_else(|e| {
            eprintln!("ERROR: transport for {}: {e}", entry.addr); std::process::exit(1);
        })
    }).collect();

    tracing::info!(
        threshold = config.threshold,
        aux_nodes = transports.len(),
        "Aux node transports configured"
    );

    // ── Build verifier public keys from group key ──────────────────────────
    let verifier_keys: Vec<(VerifierId, ed25519_dalek::VerifyingKey)> = config.aux_nodes.iter().map(|entry| {
        let vid_bytes = hex::decode(&entry.verifier_id_hex).unwrap().try_into().unwrap();
        let vid = VerifierId::from_bytes(vid_bytes);
        let vk_bytes = group_key.verifying_key_bytes();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).unwrap_or_else(|e| {
            eprintln!("ERROR: group verifying key: {e}"); std::process::exit(1);
        });
        (vid, vk)
    }).collect();

    // ── Build CoordinatorNode ──────────────────────────────────────────────
    let verifier_ids: Vec<VerifierId> = transports.iter()
        .map(|t| t.verifier_id().clone())
        .collect();

    let coord_config = CoordinatorConfig {
        coordinator_id: coordinator_id.clone(),
        epoch: tls_attestation_core::types::Epoch(1),
        quorum: QuorumSpec {
            threshold: config.threshold,
            verifiers: verifier_ids,
        },
        default_ttl_secs: 3600,
        verifier_public_keys: verifier_keys,
    };

    let store = InMemorySessionStore::new();
    let engine = PrototypeAttestationEngine;

    // ── DVRF engine selection ──────────────────────────────────────────────
    //
    // Use Box<dyn RandomnessEngine> so both branches share the same type.
    // If `dvrf_participant_files` is set in config + secp256k1 feature enabled:
    //   → Secp256k1DvrfEngine (bias-resistant, publicly verifiable DVRF)
    // Otherwise:
    //   → PrototypeDvrf (WARNING: not bias-resistant — for dev/testing only)

    let dvrf: Box<dyn tls_attestation_crypto::randomness::RandomnessEngine> = {
        #[cfg(feature = "secp256k1")]
        if !config.dvrf_participant_files.is_empty() {
            let participant_paths: Vec<std::path::PathBuf> = config.dvrf_participant_files
                .iter()
                .map(|p| {
                    let path = std::path::PathBuf::from(p);
                    if path.is_absolute() { path } else { config_dir.join(p) }
                })
                .collect();
            let secp_gk_path = if std::path::PathBuf::from(&config.group_key_file).is_absolute() {
                std::path::PathBuf::from(&config.group_key_file)
            } else {
                config_dir.join(&config.group_key_file)
            };
            let engine = Secp256k1DvrfEngine::from_files(
                config.threshold,
                &participant_paths,
                &secp_gk_path,
            ).unwrap_or_else(|e| {
                eprintln!("ERROR: Secp256k1DvrfEngine init: {e}");
                std::process::exit(1);
            });
            tracing::info!("DVRF: Secp256k1DvrfEngine (bias-resistant, publicly verifiable)");
            Box::new(engine)
        } else {
            tracing::warn!(
                "DVRF: PrototypeDvrf — NOT bias-resistant. \
                 Add `dvrf_participant_files` to config for production use."
            );
            let secrets: std::collections::HashMap<VerifierId, [u8; 32]> = coord_config
                .quorum.verifiers.iter().enumerate()
                .map(|(i, vid)| { let mut s = [0u8; 32]; s[..8].copy_from_slice(&(i as u64).to_be_bytes()); (vid.clone(), s) })
                .collect();
            Box::new(PrototypeDvrf::new(secrets))
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            tracing::warn!(
                "DVRF: PrototypeDvrf — NOT bias-resistant. \
                 Compile with --features secp256k1 and add `dvrf_participant_files` for production."
            );
            let secrets: std::collections::HashMap<VerifierId, [u8; 32]> = coord_config
                .quorum.verifiers.iter().enumerate()
                .map(|(i, vid)| { let mut s = [0u8; 32]; s[..8].copy_from_slice(&(i as u64).to_be_bytes()); (vid.clone(), s) })
                .collect();
            Box::new(PrototypeDvrf::new(secrets))
        }
    };

    let coordinator = Arc::new(CoordinatorNode::new(coord_config, store, dvrf, engine));
    let group_key = Arc::new(group_key);
    let transports = Arc::new(transports);

    // ── HTTP server ────────────────────────────────────────────────────────
    let listener = TcpListener::bind(&config.listen_addr).unwrap_or_else(|e| {
        eprintln!("ERROR: bind {}: {e}", config.listen_addr); std::process::exit(1);
    });

    tracing::info!(addr = %config.listen_addr, "Coordinator listening");
    println!("Coordinator ready on {}", config.listen_addr);
    println!("POST /attest with JSON AttestationRequest to start attestation.");
    println!("Press Ctrl-C to stop.");

    for result in listener.incoming() {
        match result {
            Ok(stream) => {
                let coordinator = Arc::clone(&coordinator);
                let group_key = Arc::clone(&group_key);
                let transports = Arc::clone(&transports);
                std::thread::spawn(move || {
                    handle_request(stream, &coordinator, &transports, &group_key);
                });
            }
            Err(e) => tracing::warn!("accept error: {e}"),
        }
    }
}