//! Full DECO TLS 1.2 MtE pipeline, prover ↔ verifier, in one repo:
//!
//!   HSP (2PC, mpz)  ->  K_MAC additive shares + verifier rand_binding
//!        |                  K_MAC = k_mac_p XOR k_mac_v
//!        v
//!   bind            ->  k_mac_commitment = pack(K_MAC) + rand_binding
//!        v
//!   PGP (Groth16)   ->  prove MAC-then-Encrypt over 3 AES blocks, K_MAC bound
//!        v
//!   verify          ->  verifier checks the PGP SNARK   (== protocol end)
//!
//! No DVRF, no TSS, no DKG. HSP is a 2PC (not a co-SNARK); no public
//! verifiability — the verifier is convinced by participating, then by
//! verifying the PGP proof.
//!
//! Run:  cargo run --release --bin deco_full

use hsp_2pc::run_hsp;
use pgp::{
    bytes32_to_fr, k_mac_commitment, prove, setup, verify, MacThenEncryptCircuit,
    MacThenEncryptWitness,
};
use std::time::Instant;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("== DECO TLS 1.2 MtE — full pipeline (prover <-> verifier) ==\n");

    // ---- session inputs (real run: from ECtF / the TLS session) ----
    // Sampled fresh each run so K_MAC and the shares differ every time.
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut z_p = [0u8; 32]; // prover pre-master share
    let mut z_v = [0u8; 32]; // verifier pre-master share
    let mut mask_r = [0u8; 32]; // prover K_MAC mask
    let mut rand_binding = [0u8; 32]; // verifier-sampled randomness (ex-DVRF)
    rng.fill_bytes(&mut z_p);
    rng.fill_bytes(&mut z_v);
    rng.fill_bytes(&mut mask_r);
    rng.fill_bytes(&mut rand_binding);

    // ============================ HSP (2PC) ============================
    let hsp = run_hsp(z_p, z_v, mask_r, rand_binding).await;
    // Post-commit, the verifier releases its share; the prover reconstructs K_MAC.
    let mut k_mac = [0u8; 32];
    for i in 0..32 {
        k_mac[i] = hsp.k_mac_p[i] ^ hsp.k_mac_v[i];
    }
    println!("[HSP] 2PC handshake done in {:?}", hsp.elapsed);
    println!("      K_MAC_p (prover)   = {}", hex::encode(hsp.k_mac_p));
    println!("      K_MAC_v (verifier) = {}", hex::encode(hsp.k_mac_v));
    println!("      K_MAC (recombined) = {}", hex::encode(k_mac));

    // ============================ bind ============================
    // The verifier holds the commitment; the PGP proof must open to it.
    let rand_fe = bytes32_to_fr(&hsp.rand_binding);
    let commitment = k_mac_commitment(&k_mac, rand_fe);
    println!("\n[bind] k_mac_commitment = pack(K_MAC) + rand_binding (verifier-held)");

    // ============================ PGP (Groth16) ============================
    // Prover's remaining session secrets (demo values).
    let k_enc: [u8; 16] = [0x33; 16];
    let iv: [u8; 16] = [0x44; 16];
    let plaintext: [u8; 16] = *b"GET /balance\0\0\0\0";
    let seq: u64 = 1;
    let content_type: u8 = 23; // application_data
    let version: [u8; 2] = [0x03, 0x03]; // TLS 1.2

    let witness = MacThenEncryptWitness::new(k_mac, k_enc, iv, plaintext, seq, content_type, version);
    let circuit = MacThenEncryptCircuit::from_witness(&witness, &hsp.rand_binding);

    // Sanity: the circuit's commitment public input must equal the HSP commitment.
    let circuit_commitment = circuit.k_mac_commitment_fe;
    println!(
        "[bind] commitment matches HSP = {}",
        circuit_commitment == commitment
    );

    let t_setup = Instant::now();
    let crs = setup().expect("groth16 setup");
    println!("\n[PGP] Groth16 setup   {:?}", t_setup.elapsed());

    let t_prove = Instant::now();
    let proof = prove(&crs, circuit).expect("groth16 prove");
    println!("[PGP] Groth16 prove   {:?}", t_prove.elapsed());

    // ============================ verify ============================
    let t_verify = Instant::now();
    let ok = verify(&crs, &proof).is_ok();
    println!("[PGP] Groth16 verify  {:?}", t_verify.elapsed());

    println!("\n== verifier accepts PGP proof: {} ==", ok);
}
