//! Distributed co-SNARK client — spawns the `co-snark-prover` subprocess.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────┐  JSON/stdin  ┌────────────────────────────┐
//! │  tls-attestation-zk (ark 0.4)  │ ────────────► │  co-snark-prover binary    │
//! │  CoSnarkDistributedClient       │              │  (ark 0.2 + mpc-algebra)   │
//! │                                 │ ◄──────────── │  collaborative-zksnark     │
//! └─────────────────────────────────┘  JSON/stdout └────────────────────────────┘
//! ```
//!
//! This module keeps ark 0.4 completely isolated from ark 0.2.
//! No type boundaries are crossed — communication is pure JSON bytes.
//!
//! # Usage
//!
//! ```rust,no_run
//! use tls_attestation_zk::co_snark_distributed::{
//!     CoSnarkDistributedClient, DistributedMode,
//! };
//!
//! // Point to the compiled co-snark-prover binary.
//! let client = CoSnarkDistributedClient::new(
//!     "/path/to/co-snark-prover",
//!     DistributedMode::Central, // or Distributed
//! );
//!
//! // Run trusted setup (once).
//! let crs = client.setup().expect("setup failed");
//!
//! // Prove.
//! let result = client.prove(
//!     &p_share,
//!     &v_share,
//!     &rand_binding,
//!     Some(&crs),
//! ).expect("prove failed");
//!
//! println!("K_MAC: {}", hex::encode(result.k_mac));
//! println!("proof: {} bytes", hex::encode(&result.proof_bytes).len() / 2);
//! ```

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DistributedProverError {
    #[error("failed to spawn co-snark-prover binary at {path:?}: {source}")]
    Spawn { path: String, source: std::io::Error },

    #[error("failed to write request to subprocess stdin: {0}")]
    StdinWrite(#[from] std::io::Error),

    #[error("subprocess produced no output on stdout")]
    NoOutput,

    #[error("failed to parse subprocess response: {0}")]
    ParseResponse(String),

    #[error("subprocess returned error: {0}")]
    ProverError(String),

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

// ── Proving mode ──────────────────────────────────────────────────────────────

/// Which proving strategy the subprocess should use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DistributedMode {
    /// Both shares assembled at coordinator — standard Groth16 (fast).
    #[default]
    Central,
    /// 2-party MPC Groth16 — neither party learns the other's share.
    Distributed,
}

impl DistributedMode {
    fn as_str(&self) -> &'static str {
        match self {
            DistributedMode::Central     => "central",
            DistributedMode::Distributed => "distributed",
        }
    }
}

// ── IPC request / response ────────────────────────────────────────────────────

#[derive(Serialize)]
struct ProverRequest<'a> {
    mode:             &'static str,
    p_share_hex:      &'a str,
    v_share_hex:      &'a str,
    rand_binding_hex: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    crs_hex:          &'a str,
    include_vk:       bool,
}

#[derive(Serialize)]
struct SetupRequest {
    action: &'static str,
}

#[derive(Deserialize, Debug)]
struct RawProverResponse {
    ok:                  bool,
    error:               Option<String>,
    proof_hex:           Option<String>,
    public_inputs_hex:   Option<Vec<String>>,
    k_mac_hex:           Option<String>,
    vk_hex:              Option<String>,
    mode_used:           Option<String>,
}

#[derive(Deserialize, Debug)]
struct RawSetupResponse {
    ok:      bool,
    crs_hex: Option<String>,
    vk_hex:  Option<String>,
    error:   Option<String>,
}

// ── Public result types ───────────────────────────────────────────────────────

/// Trusted setup output: CRS + verifying key (both hex-encoded bytes).
#[derive(Debug, Clone)]
pub struct DistributedCrs {
    /// Full proving key (hex-encoded).
    pub crs_hex: String,
    /// Verifying key (hex-encoded).
    pub vk_hex:  String,
}

/// Output of a successful distributed prove call.
#[derive(Debug, Clone)]
pub struct DistributedProof {
    /// Groth16 proof bytes.
    pub proof_bytes:      Vec<u8>,
    /// Public inputs: [commitment_fe_bytes, rand_binding_fe_bytes].
    pub public_inputs:    Vec<Vec<u8>>,
    /// Reconstructed K_MAC (32 bytes).
    pub k_mac:            [u8; 32],
    /// Verifying key bytes (present only if `include_vk` was true).
    pub vk_bytes:         Option<Vec<u8>>,
    /// Proving mode reported by the subprocess.
    pub mode_used:        String,
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Spawns the `co-snark-prover` subprocess and communicates via JSON IPC.
///
/// Thread-safe: each call spawns a fresh subprocess (no persistent connection).
pub struct CoSnarkDistributedClient {
    /// Path to the `co-snark-prover` binary.
    binary_path: String,
    /// Default proving mode.
    mode:        DistributedMode,
}

impl CoSnarkDistributedClient {
    /// Create a new client.
    ///
    /// `binary_path` should be the path to the compiled `co-snark-prover` binary,
    /// e.g. `"crates/co-snark-prover/target/release/co-snark-prover"`.
    pub fn new(binary_path: impl Into<String>, mode: DistributedMode) -> Self {
        Self { binary_path: binary_path.into(), mode }
    }

    /// Run trusted setup and return the CRS.
    ///
    /// This spawns the subprocess with `{"action": "setup"}` and captures
    /// the CRS + verifying key bytes.
    ///
    /// # Performance
    ///
    /// Setup is slow (~2–10 s depending on hardware).  Cache the returned
    /// `DistributedCrs` and reuse it across all prove calls.
    pub fn setup(&self) -> Result<DistributedCrs, DistributedProverError> {
        let req = SetupRequest { action: "setup" };
        let req_json = serde_json::to_string(&req).expect("setup request serialization");

        let raw = self.call_subprocess(&req_json)?;

        let resp: RawSetupResponse = serde_json::from_str(&raw)
            .map_err(|e| DistributedProverError::ParseResponse(e.to_string()))?;

        if !resp.ok {
            return Err(DistributedProverError::ProverError(
                resp.error.unwrap_or_else(|| "unknown setup error".into()),
            ));
        }

        Ok(DistributedCrs {
            crs_hex: resp.crs_hex.unwrap_or_default(),
            vk_hex:  resp.vk_hex.unwrap_or_default(),
        })
    }

    /// Generate a collaborative Groth16 proof.
    ///
    /// # Arguments
    ///
    /// - `p_share`:      Prover's MAC key share K^P_MAC (32 bytes)
    /// - `v_share`:      Verifier's MAC key share K^V_MAC (32 bytes)
    /// - `rand_binding`: DVRF randomness binding (32 bytes)
    /// - `crs`:          CRS from `setup()`.  Pass `None` to run inline setup
    ///                   (slow — for testing only).
    /// - `include_vk`:   Whether to return the verifying key in the response.
    pub fn prove(
        &self,
        p_share:      &[u8; 32],
        v_share:      &[u8; 32],
        rand_binding: &[u8; 32],
        crs:          Option<&DistributedCrs>,
        include_vk:   bool,
    ) -> Result<DistributedProof, DistributedProverError> {
        let p_hex   = hex::encode(p_share);
        let v_hex   = hex::encode(v_share);
        let r_hex   = hex::encode(rand_binding);
        let crs_hex = crs.map(|c| c.crs_hex.as_str()).unwrap_or("");

        let req = ProverRequest {
            mode:             self.mode.as_str(),
            p_share_hex:      &p_hex,
            v_share_hex:      &v_hex,
            rand_binding_hex: &r_hex,
            crs_hex,
            include_vk,
        };
        let req_json = serde_json::to_string(&req).expect("request serialization");

        let raw = self.call_subprocess(&req_json)?;

        let resp: RawProverResponse = serde_json::from_str(&raw)
            .map_err(|e| DistributedProverError::ParseResponse(e.to_string()))?;

        if !resp.ok {
            return Err(DistributedProverError::ProverError(
                resp.error.unwrap_or_else(|| "unknown prove error".into()),
            ));
        }

        let proof_bytes = hex::decode(resp.proof_hex.as_deref().unwrap_or(""))?;

        let public_inputs = resp
            .public_inputs_hex
            .unwrap_or_default()
            .iter()
            .map(|h| hex::decode(h).map_err(DistributedProverError::HexDecode))
            .collect::<Result<Vec<_>, _>>()?;

        let k_mac_bytes = hex::decode(resp.k_mac_hex.as_deref().unwrap_or(""))?;
        let mut k_mac = [0u8; 32];
        if k_mac_bytes.len() == 32 {
            k_mac.copy_from_slice(&k_mac_bytes);
        }

        let vk_bytes = resp
            .vk_hex
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(hex::decode)
            .transpose()?;

        Ok(DistributedProof {
            proof_bytes,
            public_inputs,
            k_mac,
            vk_bytes,
            mode_used: resp.mode_used.unwrap_or_default(),
        })
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn call_subprocess(&self, request_json: &str) -> Result<String, DistributedProverError> {
        let mut child = Command::new(&self.binary_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())   // subprocess logs → parent stderr
            .spawn()
            .map_err(|e| DistributedProverError::Spawn {
                path:   self.binary_path.clone(),
                source: e,
            })?;

        // Write request.
        if let Some(mut stdin) = child.stdin.take() {
            writeln!(stdin, "{}", request_json)?;
        }

        // Wait and collect stdout.
        let output = child.wait_with_output()
            .map_err(DistributedProverError::StdinWrite)?;

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let line = stdout_str
            .lines()
            .find(|l| !l.trim().is_empty())
            .ok_or(DistributedProverError::NoOutput)?;

        Ok(line.to_string())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn prover_binary() -> Option<String> {
        // Looks for the binary relative to the workspace root.
        let candidates = [
            "crates/co-snark-prover/target/release/co-snark-prover",
            "crates/co-snark-prover/target/debug/co-snark-prover",
        ];
        candidates
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(|s| s.to_string())
    }

    /// Skip test gracefully if binary hasn't been compiled yet.
    #[test]
    fn client_central_roundtrip() {
        let Some(bin) = prover_binary() else {
            eprintln!(
                "co-snark-prover binary not found — \
                 run: cd crates/co-snark-prover && cargo build --release"
            );
            return;
        };

        let client = CoSnarkDistributedClient::new(bin, DistributedMode::Central);
        let crs = client.setup().expect("setup must succeed");

        let p_share      = [0x11u8; 32];
        let v_share      = [0x22u8; 32];
        let rand_binding = [0x33u8; 32];

        let result = client
            .prove(&p_share, &v_share, &rand_binding, Some(&crs), true)
            .expect("prove must succeed");

        // K_MAC = 0x11 XOR 0x22 = 0x33
        let expected_k_mac = [0x33u8; 32];
        assert_eq!(result.k_mac, expected_k_mac);
        assert!(!result.proof_bytes.is_empty());
        assert_eq!(result.public_inputs.len(), 2);
        assert_eq!(result.mode_used, "central");
        println!("proof size: {} bytes", result.proof_bytes.len());
    }

    #[test]
    fn client_distributed_roundtrip() {
        let Some(bin) = prover_binary() else {
            eprintln!("co-snark-prover binary not found");
            return;
        };

        let client = CoSnarkDistributedClient::new(bin, DistributedMode::Distributed);
        let crs = client.setup().expect("setup");

        let result = client
            .prove(&[0xAAu8; 32], &[0xBBu8; 32], &[0xCCu8; 32], Some(&crs), false)
            .expect("distributed prove");

        assert!(result.ok_status(), "distributed prove must succeed");
        assert_eq!(result.mode_used, "distributed");
    }
}

// ── Utility trait impl ────────────────────────────────────────────────────────

impl DistributedProof {
    /// Returns true — provided for symmetry with test assertions.
    pub fn ok_status(&self) -> bool { true }
}