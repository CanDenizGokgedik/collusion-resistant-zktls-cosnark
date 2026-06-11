//! dx-DCTLS protocol proof generation and verification tests.

use tls_attestation_attestation::dctls::{
    verify_hsp_proof, verify_pgp_proof, verify_query_record,
    DctlsEvidence, HSPProof, PGPProof, QueryRecord, SessionParamsPublic,
    SessionParamsSecret, Statement,
};
use tls_attestation_core::{
    hash::{CanonicalHasher, DigestBytes},
    ids::SessionId,
};

fn sid() -> SessionId { SessionId::from_bytes([1u8; 16]) }
fn rand_val() -> DigestBytes { DigestBytes::from_bytes([2u8; 32]) }
fn cert_hash() -> DigestBytes { DigestBytes::from_bytes([3u8; 32]) }

fn make_sps(session_id: &SessionId, rand: &DigestBytes) -> SessionParamsSecret {
    let mut h = CanonicalHasher::new("test/exporter");
    h.update_fixed(session_id.as_bytes());
    h.update_digest(rand);
    let dvrf_exporter = h.finalize();
    SessionParamsSecret {
        dvrf_exporter,
        session_nonce: DigestBytes::from_bytes([99u8; 32]),
    }
}

fn make_spp(cert: DigestBytes) -> SessionParamsPublic {
    let established_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    SessionParamsPublic {
        server_cert_hash: cert,
        tls_version: 0x0304,
        server_name: "example.com".into(),
        established_at,
    }
}

// ── HSP tests ─────────────────────────────────────────────────────────────────

#[test]
fn hsp_round_trip() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert.clone());
    let proof = HSPProof::generate(&sid, &rand, &sps, &spp);
    verify_hsp_proof(&proof, &rand, &cert).unwrap();
}

#[test]
fn hsp_wrong_rand_fails() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert.clone());
    let proof = HSPProof::generate(&sid, &rand, &sps, &spp);
    assert!(verify_hsp_proof(&proof, &DigestBytes::from_bytes([0xFF; 32]), &cert).is_err());
}

#[test]
fn hsp_wrong_cert_fails() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert);
    let proof = HSPProof::generate(&sid, &rand, &sps, &spp);
    assert!(verify_hsp_proof(&proof, &rand, &DigestBytes::from_bytes([0xFF; 32])).is_err());
}

#[test]
fn hsp_tampered_commitment_fails() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert.clone());
    let mut proof = HSPProof::generate(&sid, &rand, &sps, &spp);
    proof.commitment = DigestBytes::from_bytes([0xAB; 32]);
    assert!(verify_hsp_proof(&proof, &rand, &cert).is_err());
}

// ── QP tests ──────────────────────────────────────────────────────────────────

#[test]
fn qp_round_trip() {
    let (sid, rand) = (sid(), rand_val());
    let rec = QueryRecord::build(&sid, &rand, b"GET /api", b"200 OK");
    verify_query_record(&rec, b"GET /api", b"200 OK").unwrap();
}

#[test]
fn qp_wrong_query_fails() {
    let (sid, rand) = (sid(), rand_val());
    let rec = QueryRecord::build(&sid, &rand, b"GET /api", b"200 OK");
    assert!(verify_query_record(&rec, b"POST /api", b"200 OK").is_err());
}

#[test]
fn qp_wrong_response_fails() {
    let (sid, rand) = (sid(), rand_val());
    let rec = QueryRecord::build(&sid, &rand, b"GET /api", b"200 OK");
    assert!(verify_query_record(&rec, b"GET /api", b"500 Error").is_err());
}

#[test]
fn qp_different_rand_produces_different_commitment() {
    let sid = sid();
    let rec1 = QueryRecord::build(&sid, &DigestBytes::from_bytes([1u8; 32]), b"GET /", b"OK");
    let rec2 = QueryRecord::build(&sid, &DigestBytes::from_bytes([2u8; 32]), b"GET /", b"OK");
    assert_ne!(rec1.query_commitment, rec2.query_commitment);
    assert_ne!(rec1.transcript_commitment, rec2.transcript_commitment);
}

// ── PGP tests ─────────────────────────────────────────────────────────────────

#[test]
fn pgp_round_trip() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert);
    let hsp = HSPProof::generate(&sid, &rand, &sps, &spp);
    let qp = QueryRecord::build(&sid, &rand, b"GET /", b"OK");
    let stmt = Statement::derive(b"result".to_vec(), "test/v1".into(), &qp.transcript_commitment);
    let pgp = PGPProof::generate(&sid, &rand, &qp, stmt, &hsp);
    verify_pgp_proof(&pgp, &rand, &hsp).unwrap();
}

#[test]
fn pgp_wrong_rand_fails() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert);
    let hsp = HSPProof::generate(&sid, &rand, &sps, &spp);
    let qp = QueryRecord::build(&sid, &rand, b"GET /", b"OK");
    let stmt = Statement::derive(b"result".to_vec(), "test/v1".into(), &qp.transcript_commitment);
    let pgp = PGPProof::generate(&sid, &rand, &qp, stmt, &hsp);
    let wrong_rand = DigestBytes::from_bytes([0xFF; 32]);
    assert!(verify_pgp_proof(&pgp, &wrong_rand, &hsp).is_err());
}

#[test]
fn pgp_tampered_statement_fails() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert);
    let hsp = HSPProof::generate(&sid, &rand, &sps, &spp);
    let qp = QueryRecord::build(&sid, &rand, b"GET /", b"OK");
    let stmt = Statement::derive(b"result".to_vec(), "test/v1".into(), &qp.transcript_commitment);
    let mut pgp = PGPProof::generate(&sid, &rand, &qp, stmt, &hsp);
    pgp.statement.content = b"tampered".to_vec();
    assert!(verify_pgp_proof(&pgp, &rand, &hsp).is_err());
}

// ── Full evidence bundle ───────────────────────────────────────────────────────

#[test]
fn dctls_evidence_verify_all_passes() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert.clone());
    let hsp = HSPProof::generate(&sid, &rand, &sps, &spp);
    let qp = QueryRecord::build(&sid, &rand, b"GET /", b"OK");
    let stmt = Statement::derive(b"result".to_vec(), "test/v1".into(), &qp.transcript_commitment);
    let pgp = PGPProof::generate(&sid, &rand, &qp, stmt, &hsp);
    let ev = DctlsEvidence { hsp_proof: hsp, query_record: qp, pgp_proof: pgp };
    ev.verify_all(&rand, &cert, b"GET /", b"OK").unwrap();
}

#[test]
fn dctls_evidence_verify_all_wrong_rand_fails() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert.clone());
    let hsp = HSPProof::generate(&sid, &rand, &sps, &spp);
    let qp = QueryRecord::build(&sid, &rand, b"GET /", b"OK");
    let stmt = Statement::derive(b"result".to_vec(), "test/v1".into(), &qp.transcript_commitment);
    let pgp = PGPProof::generate(&sid, &rand, &qp, stmt, &hsp);
    let ev = DctlsEvidence { hsp_proof: hsp, query_record: qp, pgp_proof: pgp };
    assert!(ev.verify_all(&DigestBytes::from_bytes([0xFF; 32]), &cert, b"GET /", b"OK").is_err());
}

#[test]
fn dctls_evidence_verify_all_wrong_query_fails() {
    let (sid, rand, cert) = (sid(), rand_val(), cert_hash());
    let sps = make_sps(&sid, &rand);
    let spp = make_spp(cert.clone());
    let hsp = HSPProof::generate(&sid, &rand, &sps, &spp);
    let qp = QueryRecord::build(&sid, &rand, b"GET /", b"OK");
    let stmt = Statement::derive(b"result".to_vec(), "test/v1".into(), &qp.transcript_commitment);
    let pgp = PGPProof::generate(&sid, &rand, &qp, stmt, &hsp);
    let ev = DctlsEvidence { hsp_proof: hsp, query_record: qp, pgp_proof: pgp };
    assert!(ev.verify_all(&rand, &cert, b"WRONG", b"OK").is_err());
}
