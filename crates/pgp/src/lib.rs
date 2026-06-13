//! PGP — Mac-then-Encrypt Groth16 proof (BN254) for the DECO TLS 1.2 CBC
//! handshake, reused verbatim from the co-SNARK repo. Proves, in zero
//! knowledge, that a prover knows (K_MAC, K_ENC, plaintext) such that the
//! ciphertext is the genuine mac-then-encrypt of the plaintext under keys
//! derived from the attested session, with K_MAC bound to a public commitment
//! produced by the 2PC HSP.
//!
//! Difference from the original repo: the commitment's `rand_binding` now comes
//! from the verifier's 2PC sample rather than a DVRF. No DVRF / TSS / DKG.

pub mod binding;
pub mod sha256_gadget;
pub mod aes128_gadget;
pub mod hmac_sha256_gadget;
pub mod mac_then_encrypt;

pub use binding::{bytes32_to_fr, k_mac_commitment};
pub use mac_then_encrypt::{
    setup, prove, verify, MacThenEncryptCircuit, MacThenEncryptCrs, MacThenEncryptError,
    MacThenEncryptProof, MacThenEncryptWitness,
};
