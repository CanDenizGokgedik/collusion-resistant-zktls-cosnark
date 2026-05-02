//! DVRF security and correctness tests.
#![cfg(feature = "frost")]

use tls_attestation_core::{
    hash::DigestBytes,
    ids::{ProverId, SessionId, VerifierId},
    types::{Epoch, Nonce},
};
use tls_attestation_crypto::{
    dvrf::{DvRFInput, FrostDvRF},
    frost_adapter::frost_trusted_dealer_keygen,
};

fn make_alpha(seed: u8) -> DvRFInput {
    let session_id = SessionId::from_bytes([seed; 16]);
    let prover_id = ProverId::from_bytes([seed.wrapping_add(1); 32]);
    let nonce = Nonce::from_bytes([seed.wrapping_add(2); 32]);
    let quorum_hash = DigestBytes::from_bytes([seed.wrapping_add(3); 32]);
    DvRFInput::for_session(&session_id, &prover_id, &nonce, Epoch::GENESIS, &quorum_hash)
}

#[test]
fn dvrf_2_of_3_produces_verifiable_output() {
    let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key);
    let alpha = make_alpha(1);
    let participants: Vec<_> = keygen.participants.iter().collect();
    let output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");
    assert_ne!(output.value, DigestBytes::ZERO, "output must not be zero");
    FrostDvRF::verify(&alpha, &output).expect("must verify");
}

#[test]
fn dvrf_3_of_5_produces_verifiable_output() {
    let vids: Vec<VerifierId> = (1u8..=5).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 3).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key);
    let alpha = make_alpha(10);
    let participants: Vec<_> = keygen.participants.iter().collect();
    let output = dvrf.evaluate(&alpha, &participants[..3]).expect("evaluate");
    FrostDvRF::verify(&alpha, &output).expect("must verify");
}

#[test]
fn dvrf_different_alpha_different_output() {
    let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key);
    let participants: Vec<_> = keygen.participants.iter().collect();
    let out1 = dvrf.evaluate(&make_alpha(1), &participants[..2]).expect("eval1");
    let out2 = dvrf.evaluate(&make_alpha(2), &participants[..2]).expect("eval2");
    assert_ne!(out1.value, out2.value, "different alpha must give different output");
}

#[test]
fn dvrf_verify_rejects_tampered_value() {
    let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key);
    let alpha = make_alpha(5);
    let participants: Vec<_> = keygen.participants.iter().collect();
    let mut output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");
    output.value = DigestBytes::from_bytes([0xFF; 32]);
    assert!(FrostDvRF::verify(&alpha, &output).is_err(), "tampered value must be rejected");
}

#[test]
fn dvrf_verify_rejects_wrong_alpha() {
    let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key);
    let alpha = make_alpha(6);
    let wrong_alpha = make_alpha(7);
    let participants: Vec<_> = keygen.participants.iter().collect();
    let output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");
    assert!(FrostDvRF::verify(&wrong_alpha, &output).is_err(), "wrong alpha must be rejected");
}

#[test]
fn dvrf_verify_rejects_tampered_signature() {
    let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
    let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
    let dvrf = FrostDvRF::new(keygen.group_key);
    let alpha = make_alpha(9);
    let participants: Vec<_> = keygen.participants.iter().collect();
    let mut output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");
    output.proof.aggregate_signature[0] ^= 0xFF;
    assert!(FrostDvRF::verify(&alpha, &output).is_err(), "tampered signature must be rejected");
}

#[test]
fn dvrf_input_binds_to_all_session_fields() {
    let sid = SessionId::from_bytes([0x01; 16]);
    let pid = ProverId::from_bytes([0xAA; 32]);
    let n = Nonce::from_bytes([0x55; 32]);
    let e = Epoch::GENESIS;
    let q = DigestBytes::from_bytes([0x77; 32]);
    let base = DvRFInput::for_session(&sid, &pid, &n, e, &q);
    assert_ne!(base.bytes, DvRFInput::for_session(&SessionId::from_bytes([0x02; 16]), &pid, &n, e, &q).bytes);
    assert_ne!(base.bytes, DvRFInput::for_session(&sid, &ProverId::from_bytes([0xBB; 32]), &n, e, &q).bytes);
    assert_ne!(base.bytes, DvRFInput::for_session(&sid, &pid, &Nonce::from_bytes([0x66; 32]), e, &q).bytes);
    assert_ne!(base.bytes, DvRFInput::for_session(&sid, &pid, &n, Epoch(1), &q).bytes);
    assert_ne!(base.bytes, DvRFInput::for_session(&sid, &pid, &n, e, &DigestBytes::from_bytes([0x88; 32])).bytes);
}
