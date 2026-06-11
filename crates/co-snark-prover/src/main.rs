//! Collaborative zkSNARK prover — stdin/stdout JSON IPC binary.
//!
//! stdin  ← one JSON line: ProverRequest  (or {"action":"setup"})
//! stdout → one JSON line: ProverResponse / SetupResponse
//! stderr → diagnostic logs
//!
//! Uses BLS12-377 (the curve used by the Ozdemir & Boneh collaborative-zksnark fork).
//!
//! # Circuit selection
//!
//! Two circuits are available, selected via the `COSNARK_FULL_CIRCUIT` env var:
//!
//! | Env var              | Circuit         | Constraints | Setup  | Prove  |
//! |----------------------|-----------------|-------------|--------|--------|
//! | (not set)            | TlsKeyCircuit   | ~5          | 21 ms  | 16 ms  |
//! | COSNARK_FULL_CIRCUIT=1 | TlsPrfCircuit | ~1.7M       | ~30 s  | ~60 s  |

#![feature(associated_type_defaults)]

mod circuit;
mod sha256_gadget;
mod hmac_sha256;
mod tls_prf_circuit;
mod mpc_groth;
mod mpc_prover;
mod types;

use types::{Mode, ProverRequest, ProverResponse, SetupResponse};
use circuit::{TlsKeyCircuit, xor_shares};
use tls_prf_circuit::TlsPrfCircuit;

use std::io::{self, BufRead, Write};

use ark_bls12_377::Bls12_377;
use ark_groth16::{
    generate_random_parameters, create_random_proof, ProvingKey,
};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use rand::rngs::OsRng;

type Fr = ark_bls12_377::Fr;

/// If `COSNARK_FULL_CIRCUIT=1`, use the full TLS-PRF circuit (~1.7M constraints).
fn use_full_circuit() -> bool {
    std::env::var("COSNARK_FULL_CIRCUIT").as_deref() == Ok("1")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--server") {
        run_server();
    } else {
        run_single();
    }
}

/// Server mode: CRS loaded once, multiple prove requests served from memory.
fn run_server() {
    let stdin = io::stdin();
    let mut out = io::stdout();

    let mut cached_params: Option<ProvingKey<Bls12_377>> = None;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => { emit_err(&mut out, &format!("stdin: {e}")); break; }
        };
        let line = line.trim();
        if line.is_empty() { continue; }

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            match v.get("action").and_then(|a| a.as_str()) {
                Some("setup") => {
                    let force_key = v["force_key_circuit"].as_bool().unwrap_or(false);
                    let params = match run_setup(force_key) {
                        Ok(p) => p,
                        Err(e) => {
                            let r = SetupResponse { ok: false, crs_hex: None, vk_hex: None, error: Some(e) };
                            writeln!(out, "{}", serde_json::to_string(&r).unwrap()).ok();
                            out.flush().ok();
                            continue;
                        }
                    };
                    let vk_hex = serialize_hex(&params.vk).ok();
                    let resp = SetupResponse { ok: true, crs_hex: None, vk_hex, error: None };
                    writeln!(out, "{}", serde_json::to_string(&resp).unwrap()).ok();
                    out.flush().ok();
                    cached_params = Some(params);
                    continue;
                }
                Some("shutdown") => break,
                Some("mpc_party") => {
                    mpc_prover::handle_mpc_party(&mut out, &v);
                    out.flush().ok();
                    continue;
                }
                _ => {}
            }
        }

        let req: ProverRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => { emit_err(&mut out, &format!("parse: {e}")); out.flush().ok(); continue; }
        };

        let resp = match req.mode {
            Mode::Central => handle_central_with_params(req, cached_params.as_ref()),
            Mode::Distributed => mpc_prover::prove_distributed(req),
        };
        emit(&mut out, &resp);
        out.flush().ok();
    }
}

/// Single-shot mode: one request, one response, exit.
fn run_single() {
    let stdin  = io::stdin();
    let mut out = io::stdout();

    let mut line = String::new();
    if let Err(e) = stdin.lock().read_line(&mut line) {
        emit_err(&mut out, &format!("stdin read: {e}"));
        return;
    }
    let line = line.trim();

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
        match v.get("action").and_then(|a| a.as_str()) {
            Some("setup")     => {
                let force_key = v["force_key_circuit"].as_bool().unwrap_or(false);
                handle_setup_with_flag(&mut out, force_key);
                return;
            }
            Some("mpc_party") => { mpc_prover::handle_mpc_party(&mut out, &v); return; }
            _ => {}
        }
    }

    let req: ProverRequest = match serde_json::from_str(line) {
        Ok(r)  => r,
        Err(e) => { emit_err(&mut out, &format!("JSON parse: {e}")); return; }
    };

    let resp = match req.mode {
        Mode::Central     => handle_central(req),
        Mode::Distributed => mpc_prover::prove_distributed(req),
    };
    emit(&mut out, &resp);
}

// ── Central proving ───────────────────────────────────────────────────────────

/// Used in server mode — CRS passed from memory, no deserialization cost.
fn handle_central_with_params(req: ProverRequest, cached: Option<&ProvingKey<Bls12_377>>) -> ProverResponse {
    let mode = "central";
    let p  = match decode32(&req.p_share_hex)      { Ok(v) => v, Err(e) => return err(e, mode) };
    let v  = match decode32(&req.v_share_hex)      { Ok(v) => v, Err(e) => return err(e, mode) };
    let rb = match decode32(&req.rand_binding_hex) { Ok(v) => v, Err(e) => return err(e, mode) };
    let k_mac = xor_shares(&p, &v);

    let params_owned: ProvingKey<Bls12_377>;
    let params: &ProvingKey<Bls12_377> = if let Some(c) = cached {
        c
    } else if !req.crs_file.is_empty() {
        params_owned = match load_params_from_file(&req.crs_file) { Ok(p) => p, Err(e) => return err(e, mode) };
        &params_owned
    } else if !req.crs_hex.is_empty() {
        params_owned = match deserialize_params(&req.crs_hex) { Ok(p) => p, Err(e) => return err(e, mode) };
        &params_owned
    } else {
        eprintln!("[co-snark-prover server] no CRS — running setup");
        params_owned = match run_setup(false) { Ok(p) => p, Err(e) => return err(e, mode) };
        &params_owned
    };

    let mut rng = OsRng;
    let (proof, commit_fe, rand_fe) = if use_full_circuit() {
        let c  = TlsPrfCircuit::new(p, v, [0u8; 32], [0u8; 32], [0u8; 32], rb);
        let cf = c.commitment;
        let rf = c.rand_binding;
        match create_random_proof(c, params, &mut rng) {
            Ok(pr) => (pr, cf, rf),
            Err(e) => return err(format!("prove: {e:?}"), mode),
        }
    } else {
        let c  = TlsKeyCircuit::<Fr>::new(p, v, rb);
        let cf = c.commitment;
        let rf = c.rand_binding;
        match create_random_proof(c, params, &mut rng) {
            Ok(pr) => (pr, cf, rf),
            Err(e) => return err(format!("prove: {e:?}"), mode),
        }
    };

    let proof_hex  = match serialize_hex(&proof)     { Ok(h) => h, Err(e) => return err(e, mode) };
    let commit_hex = match serialize_hex(&commit_fe) { Ok(h) => h, Err(e) => return err(e, mode) };
    let rand_hex   = match serialize_hex(&rand_fe)   { Ok(h) => h, Err(e) => return err(e, mode) };
    let vk_hex     = if req.include_vk { serialize_hex(&params.vk).ok() } else { None };
    ProverResponse {
        ok: true, error: None,
        proof_hex: Some(proof_hex),
        public_inputs_hex: vec![commit_hex, rand_hex],
        k_mac_hex: Some(hex::encode(k_mac)),
        vk_hex, mode_used: mode.into(),
    }
}

fn handle_central(req: ProverRequest) -> ProverResponse {
    let mode = "central";
    let p  = match decode32(&req.p_share_hex)      { Ok(v) => v, Err(e) => return err(e, mode) };
    let v  = match decode32(&req.v_share_hex)      { Ok(v) => v, Err(e) => return err(e, mode) };
    let rb = match decode32(&req.rand_binding_hex) { Ok(v) => v, Err(e) => return err(e, mode) };

    let k_mac = xor_shares(&p, &v);

    let params = if !req.crs_file.is_empty() {
        // Fast path: read binary CRS from disk (avoids hex decode of ~400MB).
        match load_params_from_file(&req.crs_file) { Ok(p) => p, Err(e) => return err(e, mode) }
    } else if !req.crs_hex.is_empty() {
        match deserialize_params(&req.crs_hex) { Ok(p) => p, Err(e) => return err(e, mode) }
    } else {
        eprintln!("[co-snark-prover] no CRS — running setup");
        match run_setup(false) { Ok(p) => p, Err(e) => return err(e, mode) }
    };

    let mut rng = OsRng;

    // ── Select and run circuit ─────────────────────────────────────────────────
    let (proof, commit_fe, rand_fe) = if use_full_circuit() {
        let c  = TlsPrfCircuit::new(p, v, [0u8; 32], [0u8; 32], [0u8; 32], rb);
        let cf = c.commitment;
        let rf = c.rand_binding;
        match create_random_proof(c, &params, &mut rng) {
            Ok(pr) => (pr, cf, rf),
            Err(e) => return err(format!("prove: {e:?}"), mode),
        }
    } else {
        let c  = TlsKeyCircuit::<Fr>::new(p, v, rb);
        let cf = c.commitment;
        let rf = c.rand_binding;
        match create_random_proof(c, &params, &mut rng) {
            Ok(pr) => (pr, cf, rf),
            Err(e) => return err(format!("prove: {e:?}"), mode),
        }
    };

    let proof_hex  = match serialize_hex(&proof)     { Ok(h) => h, Err(e) => return err(e, mode) };
    let commit_hex = match serialize_hex(&commit_fe) { Ok(h) => h, Err(e) => return err(e, mode) };
    let rand_hex   = match serialize_hex(&rand_fe)   { Ok(h) => h, Err(e) => return err(e, mode) };
    let vk_hex     = if req.include_vk { serialize_hex(&params.vk).ok() } else { None };

    ProverResponse {
        ok: true, error: None,
        proof_hex: Some(proof_hex),
        public_inputs_hex: vec![commit_hex, rand_hex],
        k_mac_hex: Some(hex::encode(k_mac)),
        vk_hex, mode_used: mode.into(),
    }
}

// ── Setup ─────────────────────────────────────────────────────────────────────

fn handle_setup(out: &mut impl Write) {
    handle_setup_with_flag(out, false);
}

fn handle_setup_with_flag(out: &mut impl Write, force_key_circuit: bool) {
    let resp = match run_setup(force_key_circuit) {
        Ok(params) => SetupResponse {
            ok: true,
            crs_hex: serialize_hex(&params).ok(),
            vk_hex:  serialize_hex(&params.vk).ok(),
            error:   None,
        },
        Err(e) => SetupResponse { ok: false, crs_hex: None, vk_hex: None, error: Some(e) },
    };
    writeln!(out, "{}", serde_json::to_string(&resp).unwrap()).ok();
}

fn run_setup(force_key_circuit: bool) -> Result<ProvingKey<Bls12_377>, String> {
    let mut rng = OsRng;
    if !force_key_circuit && use_full_circuit() {
        eprintln!("[co-snark-prover] setup: TlsPrfCircuit (~1.7M constraints) — may take ~30s");
        generate_random_parameters::<Bls12_377, _, _>(TlsPrfCircuit::dummy(), &mut rng)
            .map_err(|e| format!("setup: {e:?}"))
    } else {
        generate_random_parameters::<Bls12_377, _, _>(TlsKeyCircuit::<Fr>::dummy(), &mut rng)
            .map_err(|e| format!("setup: {e:?}"))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn err(msg: impl Into<String>, mode: &str) -> ProverResponse {
    ProverResponse {
        ok: false, error: Some(msg.into()),
        proof_hex: None, public_inputs_hex: vec![],
        k_mac_hex: None, vk_hex: None,
        mode_used: mode.into(),
    }
}

fn emit(out: &mut impl Write, resp: &ProverResponse) {
    writeln!(out, "{}", serde_json::to_string(resp).unwrap()).ok();
}

fn emit_err(out: &mut impl Write, msg: &str) {
    let resp = ProverResponse {
        ok: false, error: Some(msg.into()),
        proof_hex: None, public_inputs_hex: vec![],
        k_mac_hex: None, vk_hex: None, mode_used: "none".into(),
    };
    emit(out, &resp);
}

fn decode32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    if b.len() != 32 { return Err(format!("want 32 bytes, got {}", b.len())); }
    let mut a = [0u8; 32]; a.copy_from_slice(&b); Ok(a)
}

pub fn serialize_hex<T: CanonicalSerialize>(v: &T) -> Result<String, String> {
    let mut buf = Vec::new();
    v.serialize(&mut buf).map_err(|e| format!("ser: {e:?}"))?;
    Ok(hex::encode(buf))
}

pub fn load_params_from_file(path: &str) -> Result<ProvingKey<Bls12_377>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read crs_file {path}: {e}"))?;
    ProvingKey::<Bls12_377>::deserialize(&mut bytes.as_slice())
        .map_err(|e| format!("deser crs_file: {e:?}"))
}

pub fn deserialize_params(s: &str) -> Result<ProvingKey<Bls12_377>, String> {
    let b = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    ProvingKey::<Bls12_377>::deserialize(&mut b.as_slice())
        .map_err(|e| format!("deser: {e:?}"))
}