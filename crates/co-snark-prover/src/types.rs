//! IPC message types shared between main.rs and mpc_prover.rs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Central,
    Distributed,
}

impl Default for Mode {
    fn default() -> Self { Mode::Central }
}

#[derive(Debug, Deserialize)]
pub struct ProverRequest {
    #[serde(default)]
    pub mode:             Mode,
    pub p_share_hex:      String,
    pub v_share_hex:      String,
    pub rand_binding_hex: String,
    /// CRS as hex — legacy, avoided for large circuits (use crs_file instead).
    #[serde(default)]
    pub crs_hex:          String,
    /// Path to a binary CRS file on disk — preferred over crs_hex for large CRS.
    #[serde(default)]
    pub crs_file:         String,
    #[serde(default)]
    pub include_vk:       bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverResponse {
    pub ok:                bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:             Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_hex:         Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub public_inputs_hex: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k_mac_hex:         Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vk_hex:            Option<String>,
    pub mode_used:         String,
}

#[derive(Debug, Serialize)]
pub struct SetupResponse {
    pub ok:      bool,
    pub crs_hex: Option<String>,
    pub vk_hex:  Option<String>,
    pub error:   Option<String>,
}