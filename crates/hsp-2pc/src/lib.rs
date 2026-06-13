//! HSP — full DECO TLS 1.2 (MAC-then-Encrypt) handshake key derivation as a
//! 2-party computation (prover <-> verifier) over mpz garbled circuits.
//!
//! Real TLS 1.2 PRF (not a stand-in):
//!   PMS           = Z_P + Z_V                                   (2PC add)
//!   master_secret = PRF(PMS, "master secret", cr || sr)[0..48]
//!   key_block     = PRF(MS,  "key expansion", sr || cr)[0..128]
//!   K_MAC         = key_block[0..32]   (client write MAC key, AES-128-CBC-SHA256)
//!
//!   PRF(secret,label,seed) = P_SHA256(secret, label || seed)
//!   P_SHA256: A(0)=seed, A(i)=HMAC(secret,A(i-1)),
//!             output = HMAC(secret,A(1)||seed) || HMAC(secret,A(2)||seed) || ...
//!   HMAC(k,m) = H((k'^opad) || H((k'^ipad) || m))
//!
//! HMAC/SHA-256 plumbing mirrors TLSNotary's tlsn-hmac-sha256 (compute_partial /
//! merge_outputs / hmac), adapted to a single-shot build. No DVRF/TSS/DKG; the
//! verifier samples rand_binding like the prover. Output: additive shares of
//! K_MAC (k_mac_p to P, k_mac_v to V; XOR = K_MAC).

use std::sync::Arc;
use std::time::{Duration, Instant};

use mpz_circuits::{Circuit, CircuitBuilder, circuits::xor, ops::wrapping_add};
use mpz_common::context::test_st_context;
use mpz_core::prg::Prg;
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_hash::sha256::Sha256;
use mpz_memory_core::{
    Array, MemoryExt, Vector, ViewExt,
    binary::{Binary, U8},
    correlated::Delta,
};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{Call, CallableExt, Execute, Vm};

const IPAD: [u8; 64] = [0x36; 64];
const OPAD: [u8; 64] = [0x5c; 64];
const CLIENT_RANDOM: [u8; 32] = [0x01; 32];
const SERVER_RANDOM: [u8; 32] = [0x02; 32];

/// Result of the 2PC handshake.
pub struct HspOutput {
    pub k_mac_p: [u8; 32],
    pub k_mac_v: [u8; 32],
    pub rand_binding: [u8; 32],
    pub elapsed: Duration,
}

/// 256-bit add (wrapping): out = a + b = 32-byte pre-master secret.
pub fn premaster_add_circuit() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new();
    let a: Vec<_> = (0..256).map(|_| builder.add_input()).collect();
    let b: Vec<_> = (0..256).map(|_| builder.add_input()).collect();
    let sum = wrapping_add(&mut builder, &a, &b);
    for node in &sum {
        builder.add_output(*node);
    }
    Arc::new(builder.build().expect("premaster add circuit builds"))
}

/// `key' ^ mask` compressed into a SHA-256 partial (key' = key zero-padded to 64
/// bytes). Reused across HMAC calls with the same key (mask = IPAD or OPAD).
fn compute_partial(vm: &mut dyn Vm<Binary>, key: Vector<U8>, mask: [u8; 64]) -> Sha256 {
    let xor_circ = Arc::new(xor(8 * 64));

    let additional_len = 64 - key.len();
    let padding = vec![0u8; additional_len];

    let padding_ref: Vector<U8> = vm.alloc_vec(additional_len).unwrap();
    vm.mark_public(padding_ref).unwrap();
    vm.assign(padding_ref, padding).unwrap();
    vm.commit(padding_ref).unwrap();

    let mask_ref: Array<U8, 64> = vm.alloc().unwrap();
    vm.mark_public(mask_ref).unwrap();
    vm.assign(mask_ref, mask).unwrap();
    vm.commit(mask_ref).unwrap();

    let call = Call::builder(xor_circ)
        .arg(key)
        .arg(padding_ref)
        .arg(mask_ref)
        .build()
        .unwrap();
    let key_padded: Vector<U8> = vm.call(call).unwrap();

    let mut sha = Sha256::new_with_init(vm).unwrap();
    sha.update(&key_padded);
    sha.compress(vm).unwrap();
    sha
}

/// One HMAC-SHA256 with precomputed key partials and message segments.
fn hmac(
    vm: &mut dyn Vm<Binary>,
    outer_partial: &Sha256,
    inner_partial: &Sha256,
    msgs: &[Vector<U8>],
) -> Array<U8, 32> {
    let mut inner = inner_partial.clone();
    for m in msgs {
        inner.update(m);
    }
    let inner_local = inner.finalize(vm).unwrap();

    let mut outer = outer_partial.clone();
    let ilv: Vector<U8> = inner_local.into();
    outer.update(&ilv);
    outer.finalize(vm).unwrap()
}

/// Allocate a public byte vector in the VM.
fn public_vec(vm: &mut dyn Vm<Binary>, bytes: &[u8]) -> Vector<U8> {
    let r: Vector<U8> = vm.alloc_vec(bytes.len()).unwrap();
    vm.mark_public(r).unwrap();
    vm.assign(r, bytes.to_vec()).unwrap();
    vm.commit(r).unwrap();
    r
}

/// P_SHA256 expansion -> `nblocks` 32-byte output blocks.
fn prf_blocks(
    vm: &mut dyn Vm<Binary>,
    outer: &Sha256,
    inner: &Sha256,
    seed_bytes: &[u8],
    nblocks: usize,
) -> Vec<Array<U8, 32>> {
    let seed = public_vec(vm, seed_bytes);
    let mut outputs = Vec::with_capacity(nblocks);
    let mut a = hmac(vm, outer, inner, &[seed.clone()]); // A(1) = HMAC(key, seed)
    for k in 0..nblocks {
        outputs.push(hmac(vm, outer, inner, &[a.into(), seed.clone()])); // out_{k+1}
        if k + 1 < nblocks {
            a = hmac(vm, outer, inner, &[a.into()]); // A(k+2) = HMAC(key, A(k+1))
        }
    }
    outputs
}

fn gen_merge_circ(size: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new();
    let inputs = (0..size).map(|_| builder.add_input()).collect::<Vec<_>>();
    for feed in inputs {
        let out = builder.add_id_gate(feed);
        builder.add_output(out);
    }
    Arc::new(builder.build().expect("merge circuit is valid"))
}

/// Merge 32-byte blocks into a contiguous `output_bytes`-long vector.
fn merge_outputs(
    vm: &mut dyn Vm<Binary>,
    inputs: Vec<Array<U8, 32>>,
    output_bytes: usize,
) -> Vector<U8> {
    let bits = inputs.len() * 256;
    let circ = gen_merge_circ(bits);
    let mut builder = Call::builder(circ);
    for input in &inputs {
        builder = builder.arg(*input);
    }
    let call = builder.build().unwrap();
    let mut output: Vector<U8> = vm.call(call).unwrap();
    output.truncate(output_bytes);
    output
}

/// PRF(secret, label, seed) producing `outlen` bytes (key partials supplied).
fn prf_merged(
    vm: &mut dyn Vm<Binary>,
    outer: &Sha256,
    inner: &Sha256,
    seed_bytes: &[u8],
    outlen: usize,
) -> Vector<U8> {
    let nblocks = outlen.div_ceil(32);
    let outs = prf_blocks(vm, outer, inner, seed_bytes, nblocks);
    merge_outputs(vm, outs, outlen)
}

/// Build the (identical) HSP circuit graph on one party; returns the K_MAC_v handle.
fn build_hsp(
    vm: &mut dyn Vm<Binary>,
    prover: bool,
    z: [u8; 32],
    mask_r: [u8; 32],
    premaster: &Arc<Circuit>,
    xor256: &Arc<Circuit>,
) -> Array<U8, 32> {
    let zp: Array<U8, 32> = vm.alloc().unwrap();
    let zv: Array<U8, 32> = vm.alloc().unwrap();
    let r: Array<U8, 32> = vm.alloc().unwrap();
    if prover {
        vm.mark_private(zp).unwrap();
        vm.mark_blind(zv).unwrap();
        vm.mark_private(r).unwrap();
        vm.assign(zp, z).unwrap();
        vm.assign(r, mask_r).unwrap();
    } else {
        vm.mark_blind(zp).unwrap();
        vm.mark_private(zv).unwrap();
        vm.mark_blind(r).unwrap();
        vm.assign(zv, z).unwrap();
    }
    vm.commit(zp).unwrap();
    vm.commit(zv).unwrap();
    vm.commit(r).unwrap();

    // PMS = Z_P + Z_V
    let pms: Array<U8, 32> = vm
        .call(Call::builder(premaster.clone()).arg(zp).arg(zv).build().unwrap())
        .unwrap();

    // master_secret = PRF(PMS, "master secret", cr || sr)[0..48]
    let outer_pms = compute_partial(vm, pms.into(), OPAD);
    let inner_pms = compute_partial(vm, pms.into(), IPAD);
    let ms_seed = [b"master secret".as_ref(), &CLIENT_RANDOM, &SERVER_RANDOM].concat();
    let ms = prf_merged(vm, &outer_pms, &inner_pms, &ms_seed, 48);

    // key_block = PRF(MS, "key expansion", sr || cr)[0..128]; K_MAC = block 0.
    let outer_ms = compute_partial(vm, ms.clone(), OPAD);
    let inner_ms = compute_partial(vm, ms, IPAD);
    let ke_seed = [b"key expansion".as_ref(), &SERVER_RANDOM, &CLIENT_RANDOM].concat();
    let kb = prf_blocks(vm, &outer_ms, &inner_ms, &ke_seed, 4);
    let k_mac = kb[0];

    // K_MAC_v = K_MAC XOR r
    vm.call(Call::builder(xor256.clone()).arg(k_mac).arg(r).build().unwrap())
        .unwrap()
}

/// Run the full 2PC handshake.
pub async fn run_hsp(
    z_p: [u8; 32],
    z_v: [u8; 32],
    mask_r: [u8; 32],
    rand_binding: [u8; 32],
) -> HspOutput {
    let mut rng = Prg::new_with_seed([0u8; 16]);
    let delta = Delta::random(&mut rng);
    let (mut ctx_v, mut ctx_p) = test_st_context(8);
    let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

    let mut vm_v = Garbler::new(cot_send, [0u8; 16], delta);
    let mut vm_p = Evaluator::new(cot_recv);

    let premaster = premaster_add_circuit();
    let xor256 = Arc::new(xor(256));

    let kmac_v_v = build_hsp(&mut vm_v, false, z_v, mask_r, &premaster, &xor256);
    let kmac_v_p = build_hsp(&mut vm_p, true, z_p, mask_r, &premaster, &xor256);

    let mut dec_v = vm_v.decode(kmac_v_v).unwrap();
    let mut dec_p = vm_p.decode(kmac_v_p).unwrap();

    let t0 = Instant::now();
    let (k_mac_v, _) = futures::join!(
        async {
            vm_v.execute_all(&mut ctx_v).await.unwrap();
            dec_v.try_recv().unwrap().unwrap()
        },
        async {
            vm_p.execute_all(&mut ctx_p).await.unwrap();
            let _ = dec_p.try_recv().unwrap().unwrap();
        }
    );

    HspOutput {
        k_mac_p: mask_r,
        k_mac_v,
        rand_binding,
        elapsed: t0.elapsed(),
    }
}
