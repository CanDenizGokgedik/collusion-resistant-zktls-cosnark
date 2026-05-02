//! Distributed 2-party MPC prover using the original MpcTwoNet TCP architecture.
//!
//! # Why two subprocesses (not threads)?
//!
//! `MpcTwoNet` stores its TCP connection in a **process-wide** `lazy_static!`
//! `Mutex<FieldChannel>`.  Two OS threads in the same process would share that
//! global and deadlock when both try to call `exchange_bytes` simultaneously.
//!
//! Fix: spawn **two separate child processes** from the coordinator, each
//! initializing its own `FieldChannel` singleton with a different `party_id`.
//! They connect over localhost TCP, run the MPC proving protocol, and party 0
//! returns the finished (revealed) proof over stdout.
//!
//! # Flow
//!
//!   coordinator           party-0 subprocess      party-1 subprocess
//!   ──────────────────    ────────────────────    ────────────────────
//!   write net.cfg  ──────►
//!   spawn p0 + p1  ──────► mpc_party{party=0}  ── mpc_party{party=1}
//!                          init_from_path(0)       init_from_path(1)
//!                          connect() ◄────TCP─────► connect()
//!                          mpc_create_proof(…)     mpc_create_proof(…)
//!                          proof.reveal()
//!                          print JSON ────────────►
//!   read p0 stdout ◄──────
//!   wait p1 exit   ◄──────────────────────────────

use std::io::Write as IoWrite;
use std::process::{Command, Stdio};

use ark_bls12_377::Bls12_377;
use ark_groth16::{generate_random_parameters, ProvingKey};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ff::{PrimeField, BigInteger};
use rand::rngs::OsRng;

use mpc_net::two::{init_from_path, deinit};
use mpc_algebra::{
    honest_but_curious::{MpcPairingEngine, MpcField},
    Reveal,
};

use crate::types::{ProverRequest, ProverResponse};
use crate::circuit::{TlsKeyCircuit, xor_shares, bytes32_to_field};
use crate::mpc_groth::prover::create_random_proof as mpc_create_proof;
use crate::{serialize_hex, deserialize_params};

type Fr    = ark_bls12_377::Fr;
type MpcFr = MpcField<Fr>;
type MpcE  = MpcPairingEngine<Bls12_377>;

// ── Coordinator: spawn two child processes ────────────────────────────────────

/// Called by the coordinator binary when mode == "distributed".
///
/// Spawns two subprocesses (party 0 and party 1) that connect via localhost
/// TCP and run the 2-party MPC Groth16 protocol.  Returns the proof produced
/// by party 0.
pub fn prove_distributed(req: ProverRequest) -> ProverResponse {
    let mode = "distributed";

    let p  = match decode32(&req.p_share_hex)      { Ok(v) => v, Err(e) => return err(e, mode) };
    let v  = match decode32(&req.v_share_hex)      { Ok(v) => v, Err(e) => return err(e, mode) };
    let rb = match decode32(&req.rand_binding_hex) { Ok(v) => v, Err(e) => return err(e, mode) };

    let k_mac = xor_shares(&p, &v);

    // Find two free localhost ports and write a net-config file.
    let (port0, port1) = match find_two_ports() {
        Ok(p) => p, Err(e) => return err(format!("ports: {e}"), mode),
    };
    let cfg_path = match write_net_config(port0, port1) {
        Ok(p) => p, Err(e) => return err(format!("netcfg: {e}"), mode),
    };

    // Determine the path to *this* binary (we re-invoke ourselves).
    let self_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "co-snark-prover".into());

    // Build the mpc_party JSON payloads.
    let make_req = |party_id: u8, share_hex: &str| serde_json::json!({
        "action":           "mpc_party",
        "party_id":         party_id,
        "net_config":       &cfg_path,
        "my_share_hex":     share_hex,       // this party's contribution
        "crs_hex":          &req.crs_hex,
        "rand_binding_hex": &req.rand_binding_hex,
        // commitment is public — both parties compute it the same way
        "commitment_hex": hex::encode(compute_commitment(&p, &v, &rb)),
    });

    let req0 = serde_json::to_string(&make_req(0, &req.p_share_hex))
        .expect("serialize p0 req");
    let req1 = serde_json::to_string(&make_req(1, &req.v_share_hex))
        .expect("serialize p1 req");

    // Spawn party 1 first so it is listening before party 0 connects.
    let mut child1 = match Command::new(&self_path)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return err(format!("spawn party1: {e}"), mode),
    };
    if let Some(mut s) = child1.stdin.take() {
        let _ = writeln!(s, "{}", req1);
    }

    // Small delay to give party 1 time to bind its listener.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Spawn party 0 — it will connect to party 1.
    let mut child0 = match Command::new(&self_path)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return err(format!("spawn party0: {e}"), mode),
    };
    if let Some(mut s) = child0.stdin.take() {
        let _ = writeln!(s, "{}", req0);
    }

    // Collect party 0's output (the proof).
    let out0 = match child0.wait_with_output() {
        Ok(o) => o,
        Err(e) => return err(format!("wait party0: {e}"), mode),
    };
    let _ = child1.wait(); // wait for cleanup

    // Parse party 0's JSON response.
    let stdout0 = String::from_utf8_lossy(&out0.stdout);
    let line0 = stdout0.lines().find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let mut resp: ProverResponse = match serde_json::from_str(line0) {
        Ok(r) => r,
        Err(e) => return err(format!("parse p0 resp: {e} (got: {line0:?})"), mode),
    };
    resp.k_mac_hex = Some(hex::encode(k_mac));
    resp.mode_used = mode.into();
    resp
}

/// Compute commit = pack(K_MAC) + pack(rand_binding) — the public input.
fn compute_commitment(p: &[u8; 32], v: &[u8; 32], rb: &[u8; 32]) -> Vec<u8> {
    let k_mac    = xor_shares(p, v);
    let k_mac_fe = bytes32_to_field::<Fr>(&k_mac);
    let rb_fe    = bytes32_to_field::<Fr>(rb);
    let cmt_fe   = k_mac_fe + rb_fe;
    let mut buf  = Vec::new();
    cmt_fe.serialize(&mut buf).unwrap_or_default();
    buf
}

// ── Single party: invoked by subprocess ──────────────────────────────────────

/// Handle an `{"action":"mpc_party",...}` request.
///
/// Runs one side of the 2-party MPC Groth16 protocol.  Party 0 emits the
/// final proof JSON; party 1 emits `{"ok":true,"mode_used":"mpc_party_1"}`.
pub fn handle_mpc_party(out: &mut impl IoWrite, v: &serde_json::Value) {
    let mode = "distributed";
    let result = run_as_party(v);
    writeln!(out, "{}", serde_json::to_string(&result).unwrap()).ok();
}

fn run_as_party(v: &serde_json::Value) -> ProverResponse {
    let mode = "distributed";

    let party_id: usize = v["party_id"].as_u64().unwrap_or(0) as usize;
    let net_cfg   = match v["net_config"].as_str()     { Some(s) => s, None => return err("missing net_config", mode) };
    let my_share  = match v["my_share_hex"].as_str()   { Some(s) => s, None => return err("missing my_share_hex", mode) };
    let rb_hex    = match v["rand_binding_hex"].as_str(){ Some(s) => s, None => return err("missing rand_binding_hex", mode) };
    let cmt_hex   = match v["commitment_hex"].as_str() { Some(s) => s, None => return err("missing commitment_hex", mode) };
    let crs_hex   = v["crs_hex"].as_str().unwrap_or("");

    let my_share_bytes  = match decode32(my_share) { Ok(b) => b, Err(e) => return err(e, mode) };
    let rb_bytes        = match decode32(rb_hex)   { Ok(b) => b, Err(e) => return err(e, mode) };

    // Deserialize or generate CRS.
    let params: ProvingKey<Bls12_377> = if crs_hex.is_empty() {
        eprintln!("[co-snark-prover party{party_id}] no CRS — running setup");
        match generate_random_parameters::<Bls12_377, _, _>(
            TlsKeyCircuit::<Fr>::dummy(), &mut OsRng)
        {
            Ok(pk) => pk,
            Err(e) => return err(format!("setup: {e:?}"), mode),
        }
    } else {
        match deserialize_params(crs_hex) { Ok(pk) => pk, Err(e) => return err(e, mode) }
    };

    let mpc_params: ProvingKey<MpcE> = ProvingKey::from_public(params.clone());

    // Deserialize the public inputs (commitment, rand_binding).
    let cmt_bytes: Vec<u8> = match hex::decode(cmt_hex) {
        Ok(b) => b, Err(e) => return err(format!("commitment hex: {e}"), mode),
    };
    let commitment_fe: Fr = match Fr::deserialize(&mut cmt_bytes.as_slice()) {
        Ok(f) => f,
        Err(_) => bytes32_to_field::<Fr>(&rb_bytes), // fallback
    };
    let rb_fe: Fr = bytes32_to_field::<Fr>(&rb_bytes);

    // Additive sharing layout (XOR ≡ Fp addition):
    //   p_wire: Party 0 holds pack(K^P),  Party 1 holds 0
    //   v_wire: Party 0 holds 0,           Party 1 holds pack(K^V)
    let my_share_fe: Fr = bytes32_to_field::<Fr>(&my_share_bytes);

    // In MPC Groth16 ALL scalars in every MSM must have the same is_shared()
    // status.  We therefore treat EVERY wire — including public inputs — as
    // additive shares.  Party 0 holds the full value; party 1 holds zero.
    // Combined: full + 0 = full  ✓
    let zero = Fr::from(0u64);
    let (p_share_fe, v_share_fe, cmt_share_fe, rb_share_fe) = if party_id == 0 {
        (my_share_fe, zero,   commitment_fe, rb_fe)
    } else {
        (zero, my_share_fe,   zero,           zero)
    };

    // Build the MPC circuit — all four fields are additive shares.
    let p_mpc   = MpcFr::from_add_shared(p_share_fe);
    let v_mpc   = MpcFr::from_add_shared(v_share_fe);
    let cmt_mpc = MpcFr::from_add_shared(cmt_share_fe);
    let rb_mpc  = MpcFr::from_add_shared(rb_share_fe);
    let circuit = TlsKeyCircuit::new_mpc(p_mpc, v_mpc, cmt_mpc, rb_mpc);

    // Initialize MPC network and connect.
    init_from_path(net_cfg, party_id);
    mpc_net::two::CH.lock().unwrap().connect();

    // Run the MPC proving protocol.
    let mpc_proof = match mpc_create_proof(circuit, &mpc_params, &mut OsRng) {
        Ok(p) => p,
        Err(e) => { deinit(); return err(format!("mpc prove: {e:?}"), mode); }
    };
    deinit();

    // Only party 0 reveals and returns the proof.
    if party_id == 0 {
        let proof = mpc_proof.reveal();
        let proof_hex = match serialize_hex(&proof) { Ok(h) => h, Err(e) => return err(e, mode) };
        let vk_hex    = serialize_hex(&params.vk).ok();

        let cmt_out = commitment_fe.into_repr().to_bytes_le();
        let rb_out  = rb_fe.into_repr().to_bytes_le();

        ProverResponse {
            ok: true, error: None,
            proof_hex: Some(proof_hex),
            public_inputs_hex: vec![hex::encode(cmt_out), hex::encode(rb_out)],
            k_mac_hex: None, // filled in by prove_distributed
            vk_hex,
            mode_used: mode.into(),
        }
    } else {
        // Party 1 just signals completion.
        ProverResponse {
            ok: true, error: None,
            proof_hex: None, public_inputs_hex: vec![],
            k_mac_hex: None, vk_hex: None,
            mode_used: "mpc_party_1".into(),
        }
    }
}

// ── Network helpers ───────────────────────────────────────────────────────────

fn find_two_ports() -> Result<(u16, u16), String> {
    use std::net::TcpListener;
    let l0 = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let l1 = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let p0 = l0.local_addr().unwrap().port();
    let p1 = l1.local_addr().unwrap().port();
    drop(l0); drop(l1);
    Ok((p0, p1))
}

fn write_net_config(port0: u16, port1: u16) -> Result<String, String> {
    let path = format!("/tmp/co-snark-mpc-{}-{}.cfg", port0, port1);
    let mut f = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    writeln!(f, "127.0.0.1:{}", port0).map_err(|e| e.to_string())?;
    writeln!(f, "127.0.0.1:{}", port1).map_err(|e| e.to_string())?;
    Ok(path)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn decode32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    if b.len() != 32 { return Err(format!("want 32 bytes, got {}", b.len())); }
    let mut a = [0u8; 32]; a.copy_from_slice(&b); Ok(a)
}

fn err(msg: impl Into<String>, mode: &str) -> ProverResponse {
    ProverResponse {
        ok: false, error: Some(msg.into()),
        proof_hex: None, public_inputs_hex: vec![],
        k_mac_hex: None, vk_hex: None,
        mode_used: mode.into(),
    }
}