//! Distributed 2-party MPC prover using the original MpcTwoNet TCP architecture.
//!
//! # Why two subprocesses (not threads)?
//!
//! `MpcTwoNet` stores its TCP connection in a **process-wide** `lazy_static!`
//! `Mutex<FieldChannel>`.  Two OS threads in the same process share that
//! global and deadlock.  Fix: spawn two separate child processes.
//!
//! # Why CRS file (not crs_hex)?
//!
//! The full TLS-PRF circuit (1.9M R1CS) produces a proving key of ~400MB.
//! Hex-encoding that and piping it over stdin is ~800MB per subprocess call —
//! impractical.  Instead `prove_distributed`:
//!   1. generates/deserialises the CRS once in the coordinator process,
//!   2. writes the raw bytes to a temp file on disk,
//!   3. passes only the file path in the JSON payload.
//!
//! Each party subprocess then `mmap`s the file and starts proving immediately.

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
use crate::serialize_hex;

/// True when COSNARK_FULL_CIRCUIT=1 is set.
fn use_full_circuit() -> bool {
    std::env::var("COSNARK_FULL_CIRCUIT").as_deref() == Ok("1")
}

type Fr    = ark_bls12_377::Fr;
type MpcFr = MpcField<Fr>;
type MpcE  = MpcPairingEngine<Bls12_377>;

// ── Coordinator ───────────────────────────────────────────────────────────────

pub fn prove_distributed(req: ProverRequest) -> ProverResponse {
    let mode = "distributed";

    let p  = match decode32(&req.p_share_hex)      { Ok(v) => v, Err(e) => return err(e, mode) };
    let v  = match decode32(&req.v_share_hex)      { Ok(v) => v, Err(e) => return err(e, mode) };
    let rb = match decode32(&req.rand_binding_hex) { Ok(v) => v, Err(e) => return err(e, mode) };

    let k_mac = xor_shares(&p, &v);

    // Generate or deserialise the CRS.
    let params: ProvingKey<Bls12_377> = if req.crs_hex.is_empty() {
        eprintln!("[co-snark-prover] distributed: no CRS — running setup");
        let dummy = if use_full_circuit() {
            crate::tls_prf_circuit::TlsPrfCircuit::dummy()
        } else {
            // wrap TlsKeyCircuit as ConstraintSynthesizer<Fr>
            return prove_distributed_key_circuit(req, p, v, rb, k_mac);
        };
        match generate_random_parameters::<Bls12_377, _, _>(dummy, &mut OsRng) {
            Ok(pk) => pk,
            Err(e) => return err(format!("setup: {e:?}"), mode),
        }
    } else {
        match deserialize_params_from_hex(&req.crs_hex) { Ok(pk) => pk, Err(e) => return err(e, mode) }
    };

    // Write CRS to a temp file so subprocesses can read it efficiently.
    let crs_path = format!("/tmp/co-snark-crs-{}.bin", std::process::id());
    {
        let mut f = match std::fs::File::create(&crs_path) {
            Ok(f) => f, Err(e) => return err(format!("crs file: {e}"), mode),
        };
        if let Err(e) = params.serialize(&mut f) {
            return err(format!("crs serial: {e:?}"), mode);
        }
    }

    run_two_parties(p, v, rb, k_mac, params, &crs_path, mode)
}

/// Fast path for TlsKeyCircuit (no full PRF) — keeps the original hex-free code.
fn prove_distributed_key_circuit(
    req:   ProverRequest,
    p:     [u8; 32],
    v:     [u8; 32],
    rb:    [u8; 32],
    k_mac: [u8; 32],
) -> ProverResponse {
    let mode = "distributed";
    let dummy = TlsKeyCircuit::<Fr>::dummy();
    let params = match generate_random_parameters::<Bls12_377, _, _>(dummy, &mut OsRng) {
        Ok(pk) => pk,
        Err(e) => return err(format!("setup: {e:?}"), mode),
    };
    let crs_path = format!("/tmp/co-snark-crs-key-{}.bin", std::process::id());
    {
        let mut f = match std::fs::File::create(&crs_path) {
            Ok(f) => f, Err(e) => return err(format!("crs file: {e}"), mode),
        };
        if let Err(e) = params.serialize(&mut f) {
            return err(format!("crs serial: {e:?}"), mode);
        }
    }
    run_two_parties(p, v, rb, k_mac, params, &crs_path, mode)
}

fn run_two_parties(
    p:        [u8; 32],
    v:        [u8; 32],
    rb:       [u8; 32],
    k_mac:    [u8; 32],
    params:   ProvingKey<Bls12_377>,
    crs_path: &str,
    mode:     &str,
) -> ProverResponse {
    let (port0, port1) = match find_two_ports() {
        Ok(p) => p, Err(e) => return err(format!("ports: {e}"), mode),
    };
    let cfg_path = match write_net_config(port0, port1) {
        Ok(p) => p, Err(e) => return err(format!("netcfg: {e}"), mode),
    };

    let self_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "co-snark-prover".into());

    let rb_hex  = hex::encode(rb);
    let cmt_hex = hex::encode(compute_commitment(&p, &v, &rb));

    let pms_hex = hex::encode([0u8; 32]); // synthetic PMS for benchmark
    let cr_hex  = hex::encode([0xAAu8; 32]);
    let sr_hex  = hex::encode([0xBBu8; 32]);

    let make_req = |party_id: u8, share_hex: &str| serde_json::json!({
        "action":           "mpc_party",
        "party_id":         party_id,
        "net_config":       cfg_path,
        "my_share_hex":     share_hex,
        "crs_file":         crs_path,
        "rand_binding_hex": rb_hex,
        "commitment_hex":   cmt_hex,
        "full_circuit":     use_full_circuit(),
        "pms_hex":          pms_hex,
        "cr_hex":           cr_hex,
        "sr_hex":           sr_hex,
    });

    let req0 = serde_json::to_string(&make_req(0, &hex::encode(p))).expect("req0");
    let req1 = serde_json::to_string(&make_req(1, &hex::encode(v))).expect("req1");

    // Spawn party 1 first (listener), then party 0 (connector).
    let mut child1 = match Command::new(&self_path)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn()
    { Ok(c) => c, Err(e) => return err(format!("spawn p1: {e}"), mode) };
    if let Some(mut s) = child1.stdin.take() { let _ = writeln!(s, "{}", req1); }

    std::thread::sleep(std::time::Duration::from_millis(300));

    let mut child0 = match Command::new(&self_path)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn()
    { Ok(c) => c, Err(e) => return err(format!("spawn p0: {e}"), mode) };
    if let Some(mut s) = child0.stdin.take() { let _ = writeln!(s, "{}", req0); }

    let out0 = match child0.wait_with_output() {
        Ok(o) => o, Err(e) => return err(format!("wait p0: {e}"), mode),
    };
    let _ = child1.wait();
    let _ = std::fs::remove_file(crs_path); // cleanup

    let stdout0 = String::from_utf8_lossy(&out0.stdout);
    let line0   = stdout0.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let mut resp: ProverResponse = match serde_json::from_str(line0) {
        Ok(r) => r,
        Err(e) => return err(format!("parse p0 resp: {e} (got: {line0:?})"), mode),
    };
    resp.k_mac_hex = Some(hex::encode(k_mac));
    resp.mode_used = mode.into();

    // Include VK
    if resp.vk_hex.is_none() {
        resp.vk_hex = serialize_hex(&params.vk).ok();
    }
    resp
}

// ── Single party ──────────────────────────────────────────────────────────────

pub fn handle_mpc_party(out: &mut impl IoWrite, v: &serde_json::Value) {
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
    let full_circ = v["full_circuit"].as_bool().unwrap_or(false);

    let my_share_bytes = match decode32(my_share) { Ok(b) => b, Err(e) => return err(e, mode) };
    let rb_bytes       = match decode32(rb_hex)   { Ok(b) => b, Err(e) => return err(e, mode) };

    // Load CRS from file (preferred) or fall back to empty → regenerate.
    let params: ProvingKey<Bls12_377> = if let Some(path) = v["crs_file"].as_str() {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return err(format!("read crs_file: {e}"), mode),
        };
        match ProvingKey::<Bls12_377>::deserialize(&mut bytes.as_slice()) {
            Ok(pk) => pk,
            Err(e) => return err(format!("deser crs: {e:?}"), mode),
        }
    } else {
        eprintln!("[co-snark-prover party{party_id}] no CRS file — running setup");
        if full_circ {
            match generate_random_parameters::<Bls12_377, _, _>(
                crate::tls_prf_circuit::TlsPrfCircuit::dummy(), &mut OsRng)
            { Ok(pk) => pk, Err(e) => return err(format!("setup: {e:?}"), mode) }
        } else {
            match generate_random_parameters::<Bls12_377, _, _>(
                TlsKeyCircuit::<Fr>::dummy(), &mut OsRng)
            { Ok(pk) => pk, Err(e) => return err(format!("setup: {e:?}"), mode) }
        }
    };

    let mpc_params: ProvingKey<MpcE> = ProvingKey::from_public(params.clone());

    // Deserialise public inputs.
    let cmt_bytes = match hex::decode(cmt_hex) { Ok(b) => b, Err(e) => return err(format!("cmt hex: {e}"), mode) };
    let commitment_fe: Fr = match Fr::deserialize(&mut cmt_bytes.as_slice()) {
        Ok(f) => f, Err(_) => bytes32_to_field::<Fr>(&rb_bytes),
    };
    let rb_fe: Fr = bytes32_to_field::<Fr>(&rb_bytes);

    // Additive sharing — all wires must be uniform (all shared) for MPC MSM.
    let my_share_fe: Fr = bytes32_to_field::<Fr>(&my_share_bytes);
    let zero = Fr::from(0u64);
    let (p_fe, v_fe, cmt_fe, rb_mpc_fe) = if party_id == 0 {
        (my_share_fe, zero, commitment_fe, rb_fe)
    } else {
        (zero, my_share_fe, zero, zero)
    };

    // Build circuit — TlsKeyCircuit or TlsPrfCircuit depending on mode.
    init_from_path(net_cfg, party_id);
    mpc_net::two::CH.lock().unwrap().connect();

    let mpc_proof = if full_circ {
        use crate::tls_prf_circuit::TlsPrfCircuit;
        use std::marker::PhantomData;

        let pms = decode32_default(v["pms_hex"].as_str().unwrap_or(""));
        let cr  = decode32_default(v["cr_hex"].as_str().unwrap_or(""));
        let sr  = decode32_default(v["sr_hex"].as_str().unwrap_or(""));

        let p_bytes = if party_id == 0 { my_share_bytes } else { [0u8; 32] };
        let v_bytes = if party_id == 1 { my_share_bytes } else { [0u8; 32] };

        let circuit = TlsPrfCircuit::<MpcFr> {
            p_share:       p_bytes,
            v_share:       v_bytes,
            pms_bytes:     pms,
            client_random: cr,
            server_random: sr,
            commitment:    MpcFr::from_add_shared(cmt_fe),
            rand_binding:  MpcFr::from_add_shared(rb_mpc_fe),
            _marker:       PhantomData,
        };
        match mpc_create_proof(circuit, &mpc_params, &mut OsRng) {
            Ok(p) => p,
            Err(e) => { deinit(); return err(format!("mpc prove (full): {e:?}"), mode); }
        }
    } else {
        let circuit = TlsKeyCircuit::new_mpc(
            MpcFr::from_add_shared(p_fe),
            MpcFr::from_add_shared(v_fe),
            MpcFr::from_add_shared(cmt_fe),
            MpcFr::from_add_shared(rb_mpc_fe),
        );
        match mpc_create_proof(circuit, &mpc_params, &mut OsRng) {
            Ok(p) => p,
            Err(e) => { deinit(); return err(format!("mpc prove: {e:?}"), mode); }
        }
    };
    deinit();

    if party_id == 0 {
        let proof   = mpc_proof.reveal();
        let proof_hex = match serialize_hex(&proof) { Ok(h) => h, Err(e) => return err(e, mode) };
        let cmt_out = commitment_fe.into_repr().to_bytes_le();
        let rb_out  = rb_fe.into_repr().to_bytes_le();
        ProverResponse {
            ok: true, error: None,
            proof_hex: Some(proof_hex),
            public_inputs_hex: vec![hex::encode(cmt_out), hex::encode(rb_out)],
            k_mac_hex: None,
            vk_hex: serialize_hex(&params.vk).ok(),
            mode_used: mode.into(),
        }
    } else {
        ProverResponse {
            ok: true, error: None,
            proof_hex: None, public_inputs_hex: vec![],
            k_mac_hex: None, vk_hex: None,
            mode_used: "mpc_party_1".into(),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn compute_commitment(p: &[u8; 32], v: &[u8; 32], rb: &[u8; 32]) -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;
    let k_mac    = xor_shares(p, v);
    let k_mac_fe = bytes32_to_field::<Fr>(&k_mac);
    let rb_fe    = bytes32_to_field::<Fr>(rb);
    let cmt_fe   = k_mac_fe + rb_fe;
    let mut buf  = Vec::new();
    cmt_fe.serialize(&mut buf).unwrap_or_default();
    buf
}

fn deserialize_params_from_hex(s: &str) -> Result<ProvingKey<Bls12_377>, String> {
    let b = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    ProvingKey::<Bls12_377>::deserialize(&mut b.as_slice())
        .map_err(|e| format!("deser: {e:?}"))
}

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

fn decode32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    if b.len() != 32 { return Err(format!("want 32 bytes, got {}", b.len())); }
    let mut a = [0u8; 32]; a.copy_from_slice(&b); Ok(a)
}

fn decode32_default(s: &str) -> [u8; 32] {
    if s.is_empty() { return [0u8; 32]; }
    decode32(s).unwrap_or([0u8; 32])
}

fn err(msg: impl Into<String>, mode: &str) -> ProverResponse {
    ProverResponse {
        ok: false, error: Some(msg.into()),
        proof_hex: None, public_inputs_hex: vec![],
        k_mac_hex: None, vk_hex: None,
        mode_used: mode.into(),
    }
}