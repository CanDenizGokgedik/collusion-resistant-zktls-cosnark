# Π_coll-min: Collusion-Minimized TLS Attestation

> **Prototype implementation** of the protocol described in:
>
> **"Collusion-Minimized TLS Attestation Protocol for Decentralized Applications"**
> *Cryptology ePrint Archive, Paper 2026/277* — https://eprint.iacr.org/2026/277
>
> This repository implements the **DVRF-then-Sign component** (RC Phase + Signing
> Phase) in full, plus the structural scaffolding for the dx-DCTLS Attestation
> Phase. The ZK and 2PC components use prototype implementations.

---

## Table of Contents

1. [What is Π_coll-min?](#what-is-coll-min)
2. [Protocol Overview](#protocol-overview)
3. [Architecture](#architecture)
4. [Crate Reference](#crate-reference)
6. [Binaries](#binaries)
7. [Benchmarks](#benchmarks)
8. [Quick Start](#quick-start)
9. [Building](#building)
10. [Running a Local Network](#running-a-local-network)
11. [Security Notes](#security-notes)

---

## What is Π_coll-min?

TLS attestation lets a third party prove, without involving the server, that a specific HTTP response was served over a genuine TLS session.

Existing DCTLS schemes (DECO, TLSNotary, Distefano) rely on a **single designated verifier**, creating a collusion problem: if the prover and that verifier collude, they can forge an attestation. **Π_coll-min** distributes the verifier role across a *t-of-n* quorum — forging an attestation requires corrupting at least *t* independent verifiers.

Π_coll-min has three phases (paper §V, §VIII, Fig. 8):

1. **RC Phase** — Distributed Verifiable Random Function (DVRF): the verifier quorum runs DKG and jointly generates an unbiasable `rand` that will bind the attestation session.
2. **Attestation Phase** — dx-DCTLS: the coordinator runs a single DCTLS session with the prover, binding the handshake to `rand` via co-SNARK (DECO/TLS 1.2) or v2PC (Distefano/TLS 1.3). The resulting exportable proof lets auxiliary verifiers validate the session without joining it.
3. **Signing Phase** — TSS: auxiliary verifiers check the proofs and, if valid, jointly produce a FROST threshold Schnorr signature over the attested statement.

The key advantage over DECO-DON (naive decentralization): prover complexity drops from **O(n) to O(1)** — one TLS session regardless of verifier set size.

---

## Protocol Overview

```
 Prover              Coordinator (Vcoord)         Aux Verifiers V_1..V_n
   │                       │                              │
   │                       │◄── RC Phase (offline) ──────┤
   │                       │  DKG(pp, t, n) → (ski, pk)  │
   │                       │  PartialEval(α, ski) → γi ──►│
   │                       │  Combine(pk, α, {γi}) → rand │
   │                       │                              │
   │── AttestationRequest ►│                              │
   │                       │                              │
   │   Attestation Phase: dx-DCTLS (paper §VIII.C)        │
   │◄──────────── HSP ─────►│                              │
   │  3-party TLS handshake │                              │
   │  K_MAC = K^P ⊕ K^V    │                              │
   │  Vcoord: π_HSP ← co-SNARK.Execute({K^P,K^V}, Zp)    │
   │                       │                              │
   │◄──────────── QP ──────►│                              │
   │  P gets (Q, R)         │                              │
   │  Vcoord gets (Q̂, R̂)   │                              │
   │                       │                              │
   │  PGP: π_dx ← ZKP.Prove(x=(Q,R,θs), w=(Q̂,R̂,spv,b)) │
   │──── π_dx, π_HSP ──────►│                              │
   │                       │──── broadcast π_dx, π_HSP ──►│
   │                       │                              │
   │   Signing Phase: FROST (paper §VIII.B)                │
   │                       │◄──── Round 1 (commitments) ──┤
   │                       │◄──── Round 2 (shares) ───────┤
   │                       │  σ ← Aggregate(shares)       │
   │◄── FrostAttestationEnvelope (σ, π_HSP, π_dx) ────────│
   │                       │                              │
   │   On-chain: SC.Verify(σ, pk) + ZKP.Verify(π_HSP, π_dx)
```

---

## Architecture

```
tls-cosnark/
├── crates/
│   ├── core/              # Domain types: VerifierId, DigestBytes, Epoch, QuorumSpec
│   ├── crypto/            # FROST (ed25519+secp256k1), DVRF, DKG
│   ├── zk/                # Groth16 circuits: co-SNARK π_HSP, TLS-PRF, session binding
│   ├── attestation/       # dx-DCTLS session logic (DECO + Distefano variants)
│   ├── network/           # Serializable wire messages for FROST rounds
│   ├── node/              # CoordinatorNode + FrostAuxiliaryNode + TCP transport
│   ├── storage/           # InMemorySessionStore, SqliteSessionStore
│   ├── bench/             # DVRF-then-Sign benchmarks (paper §IX Fig. 9–12)
│   ├── testing/           # Integration test helpers, mock TLS sessions
│   └── co-snark-prover/   # Standalone MPC prover binary (ark 0.2 + BLS12-377)
│                          # Communicates with crates/zk via JSON IPC (stdin/stdout)
│
├── collaborative-zksnark-main/   ← git submodule
│   │   github.com/CanDenizGokgedik/collaborative-zksnark
│   │   Fork of Özdemir & Boneh (USENIX Security 2022) — ark 0.2 codebase
│   ├── mpc-algebra/       # MpcField, MpcPairingEngine (additive secret sharing)
│   ├── mpc-net/           # MpcTwoNet — 2-party TCP channel
│   ├── groth16/           # MPC-aware Groth16 prover (create_random_proof)
│   └── algebra/, curves/  # ark 0.2 fork (BLS12-377, Fr, G1, G2)
│
```

### Why a separate `co-snark-prover` binary?

The main workspace uses **arkworks 0.4 / BN254**. The Özdemir & Boneh co-SNARK library requires **arkworks 0.2 / BLS12-377**. These two versions of arkworks are incompatible at the type level and cannot coexist in the same crate.

`co-snark-prover` is therefore a **standalone binary** that is built separately (using the `collaborative-zksnark-main` submodule) and communicates with the rest of the system via JSON over stdin/stdout. The `tls-attestation-zk` crate spawns it as a subprocess via `CoSnarkDistributedClient`.

---

## Crate Reference

### `tls-attestation-core`

Pure domain types — no I/O, no crypto.

```rust
use tls_attestation_core::{
    ids::{VerifierId, ProverId, SessionId},
    types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
    hash::{DigestBytes, sha256},
};
```

### `tls-attestation-crypto`

All cryptographic primitives, feature-gated.

| Feature | What it enables |
|---------|----------------|
| *(default)* | `PrototypeDvrf` (XOR-based, not secure), `PrototypeThresholdSigner` |
| `frost` | Ed25519 FROST (RFC 9591) via `frost-core` — used by coordinator/aux nodes |
| `secp256k1` | secp256k1 FROST + DDH-DVRF — EVM-compatible, used in benchmarks |

**RC Phase — DVRF (paper §III, §V):**

```rust
use tls_attestation_crypto::dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput};

// Each aux verifier:
let input = Secp256k1DvrfInput::new(alpha);
let partial = Secp256k1Dvrf::partial_eval(&participant, &input)?;

// Coordinator:
let rand = Secp256k1Dvrf::combine(&group_key, &input, &partials, &participants)?;
```

**DKG:**

```rust
// Distributed (production):
use tls_attestation_crypto::dkg_secp256k1::run_secp256k1_dkg;
let outputs = run_secp256k1_dkg(&verifier_ids, threshold)?;

// Trusted dealer (tests/benchmarks only — dealer sees all shares):
use tls_attestation_crypto::frost_adapter::frost_trusted_dealer_keygen;
let keys = frost_trusted_dealer_keygen(&verifier_ids, threshold)?;
```

### `tls-attestation-zk`

Groth16 zero-knowledge backend (arkworks 0.4, BN254).

| Module | What it implements | Paper ref |
|--------|--------------------|-----------|
| `co_snark` | π_HSP: Groth16 proof that K_MAC = K^P ⊕ K^V from Zp | §VIII.C eq. 2 |
| `tls_prf_circuit` | TLS 1.2 PRF R1CS circuit | §IX ref [19] |
| `hmac_sha256_gadget` | HMAC-SHA256 R1CS gadget (~74k constraints/call) | §IX ref [19] |
| `aes128_gadget` | AES-128 R1CS gadget (SubBytes/ShiftRows/MixColumns/AddRoundKey + key schedule + CBC) | §VIII.C PGP |
| `mac_then_encrypt` | Full TLS 1.2 CBC mac-then-encrypt PGP proof: HMAC tag then AES-128-CBC over plaintext‖MAC (3 blocks) | §VIII.C PGP |
| `tls_session_binding` | PGP proof (HMAC-only variant): ZKP.Prove(x=(Q,R,θs), w=(Q̂,R̂,spv,b)) | §VIII.C PGP |

```rust
use tls_attestation_zk::{CoSnarkCrs, co_snark_execute, co_snark_verify};

let crs = CoSnarkCrs::setup()?;   // one-time trusted setup
let proof = co_snark_execute(&crs, &prover_share, &verifier_share, &pms)?;
co_snark_verify(&crs.vk, &k_mac_commitment, &proof)?;
```

> **MPC co-SNARK:** the distributed (2-party MPC) co-SNARK uses the Özdemir & Boneh collaborative-zksnark library — two subprocesses run the 2-party MPC Groth16 protocol over localhost TCP, so K_MAC is never reconstructed in one place. This is the only co-SNARK mode the benchmark uses.

### `tls-attestation-attestation`

dx-DCTLS session logic — DECO and Distefano variants.

| Module | TLS version | Handshake binding | Paper ref |
|--------|-------------|-------------------|-----------|
| `deco_dx_dctls` | TLS 1.2 | co-SNARK π_HSP over K_MAC | §VIII.C eq. 2 |
| `distefano_dx_dctls` | TLS 1.3 | v2PC π_2PC over traffic secrets | §VIII.C eq. 3 |
| `rc_phase` | — | DKG + DVRF orchestration | §V RC Phase |

> **Prototype limitation:** Both variants use `mock_tls12_session` / `mock_tls13_session` instead of a real rustls session. The `--features tls` path wires up a real rustls connector but is not exercised in the benchmarks.

### `tls-attestation-node`

Coordinator and auxiliary verifier node implementations.

**Coordinator — orchestrates all three phases:**

```rust
use tls_attestation_node::{CoordinatorNode, coordinator::CoordinatorConfig};

let coordinator = CoordinatorNode::new(config, store, dvrf, engine);

// In-process (tests, single binary):
let envelope = coordinator.attest_frost_distributed(
    request, &response_bytes, &aux_nodes, &group_key
)?;

// Over TCP (real network):
let envelope = coordinator.attest_frost_distributed_over_transport(
    request, &response_bytes, &transport_refs, &group_key
)?;
```

**Auxiliary node — holds key share, serves FROST round requests:**

```rust
use tls_attestation_node::FrostAuxiliaryNode;

// Built from DKG output:
let node = FrostAuxiliaryNode::new(dkg_output.participant);
```

**Transport layer:**

| Type | Use case |
|------|----------|
| `InProcessTransport` | Tests, zero-copy single-binary |
| `TcpNodeTransport` | Production TCP (coordinator → aux) |
| `TcpAuxServer` | Production TCP (aux node listener) |
| `AuthTcpNodeTransport` | Ed25519-signed TCP (`--features auth`) |
| `MtlsTcpNodeTransport` | Mutual TLS (`--features mtls`) |

### `tls-attestation-storage`

Session store for coordinator's in-flight state.

```rust
use tls_attestation_storage::InMemorySessionStore;  // tests / single binary
use tls_attestation_storage::SqliteSessionStore;    // persistent / production
```

---

## Binaries

### `aux-node`

```bash
cargo build --package tls-attestation-node --features frost,tcp --bin aux-node --release
./target/release/aux-node --config node-0.json
```

Holds one FROST key share and serves `FrostRound1` + `FrostRound2` requests over TCP. Optionally supports Ed25519 node authentication (`--features auth`) and mTLS (`--features mtls`).

### `coordinator`

```bash
cargo build --package tls-attestation-node --features frost,tcp --bin coordinator --release
./target/release/coordinator --config coordinator.json
```

HTTP server (default: `:9100`) that accepts attestation requests, runs the DVRF and FROST rounds against aux nodes, and returns a `FrostAttestationEnvelope`.

### `dkg-ceremony`

```bash
cargo build --package tls-attestation-node --features frost --bin dkg-ceremony --release
./target/release/dkg-ceremony --threshold 10 --num-nodes 19 --output-dir /keys/
```

Runs a Pedersen DKG ceremony in-process and writes one key file per node. For production, each node must run its own DKG participant process.

### `gen-test-vectors`

```bash
cargo run --package tls-attestation-node --features frost,tcp,secp256k1 \
  --bin gen-test-vectors --release
```

Generates secp256k1 Schnorr test vectors with the exact `keccak256(R_x ‖ pk_x ‖ msg) mod N` challenge format.

---

## Benchmarks

One command produces three tables — **LAN**, **WAN1**, **WAN2** — for the full
Π_coll-min per-session pipeline using the **distributed (2-party MPC)**
co-SNARK only (no central mode):

```bash
git submodule update --init --recursive   # populate collaborative-zksnark-main
./run_wan_tables.sh
```

Columns:

| Column | Meaning |
|--------|---------|
| `DKG (ms)`     | Real distributed Pedersen DKG (trustless leader, no trusted dealer). O(n²) communication: round-2 secret shares dominate. Latency paid once per round (parallel sends); bandwidth paid on the aggregate volume — so large quorums become bandwidth-bound on low-capacity links. |
| `DVRF (ms)`    | RC-phase randomness generation — per session |
| `HSP (ms)`     | co-SNARK π_HSP, 2-party MPC (Özdemir & Boneh) |
| `PGP (ms)`     | mac-then-encrypt proof: HMAC tag + AES-128-CBC (3 blocks) |
| `TSS (ms)`     | FROST threshold signing |
| `OnChain (gas)`| SC.Verify (~14k) + ZKP.Verify (~181k) = ~195k gas |
| `Total (ms)`   | DKG + DVRF + HSP + PGP + TSS (total proving time) |
| `Net (kb)`     | Communication volume over the session |

Network conditions are injected into the FROST transport per message:
RTT ± jitter + bandwidth serialization + probabilistic packet-loss retransmit.

Profiles: **LAN** (no delay) · **WAN1** RTT≈80ms / 50 Mbps / 0.1% loss ·
**WAN2** RTT≈150ms / 20 Mbps / 0.2% loss.

> **HSP co-SNARK now runs the full SHA-256 TLS-PRF under 2-party MPC.** The
> vendored collaborative-zksnark MSM promotes public scalars (SHA-256 round
> constants / cleartext-derived wires) to trivially-shared values, so the full
> `TlsPrfCircuit` — `K_MAC = TLS-PRF(PMS, client_random, server_random)` via the
> HMAC-SHA256 chain — proves inside the distributed proof. The K_MAC binding
> (p + v shares) stays secret-shared. Enable with `COSNARK_FULL_CIRCUIT=1`
> (the launcher sets it). Set it to `0` for the fast XOR-only `TlsKeyCircuit`.
>
> The PGP proof (`mac_then_encrypt`) proves the full TLS 1.2 CBC record
> protection in-circuit: `MAC = HMAC-SHA256(K_MAC, …)` then
> `ciphertext = AES-128-CBC(K_ENC, IV, plaintext‖MAC)`. The AES-128 gadget
> implements full SubBytes/ShiftRows/MixColumns/AddRoundKey + key schedule
> (gnark `std/aes` structure). HSP MPC proves the K_MAC split (TlsKeyCircuit);
> the SHA-256-heavy full TLS-PRF circuit is not MPC-compatible and is benched
> separately by `bench_dctls`.

## Quick Start

```bash
git clone --recurse-submodules <repo-url>
cd collusion-resistant-zktls-cosnark
./run_wan_tables.sh
```

`run_wan_tables.sh` builds the standalone 2-party MPC co-SNARK prover and the
main workspace, then prints the three pipeline tables (LAN, WAN1, WAN2) — and
nothing else.

> **Important:** the `collaborative-zksnark-main/` submodule must be populated
> (`git submodule update --init --recursive`). A plain "Download ZIP" omits it
> and the co-SNARK prover will not build.

## Building

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.78+ nightly | All Rust crates |
| OpenSSL | 3.x | `--features mtls` only |

```bash
# Rust (nightly required for co-snark-prover)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default nightly

```

### Clone (with submodule)

```bash
git clone --recurse-submodules <repo-url>
cd tls-cosnark

# Or if already cloned without submodules:
git submodule update --init --recursive
```

This initialises `collaborative-zksnark-main/` — the Özdemir & Boneh fork required by the MPC co-SNARK prover.

### Build

```bash
# Main workspace (arkworks 0.4, BN254):
cargo build --workspace --features frost,tcp,secp256k1

# co-snark-prover binary (arkworks 0.2, BLS12-377 — built separately):
cd crates/co-snark-prover && cargo build --release
# Binary: crates/co-snark-prover/target/release/co-snark-prover
```

> The co-snark-prover is a **standalone binary** that must be built separately because it depends on `collaborative-zksnark-main` (arkworks 0.2), which is incompatible with the main workspace (arkworks 0.4). The two communicate via JSON over stdin/stdout.

### Feature Matrix

| Feature | Description |
|---------|-------------|
| `frost` | Ed25519 FROST (RFC 9591) — coordinator and aux-node |
| `secp256k1` | secp256k1 FROST + DDH-DVRF — EVM-compatible RC Phase |
| `tcp` | TCP transport layer |
| `auth` | Ed25519-signed node-to-node authentication |
| `mtls` | Mutual TLS transport |
| `tls` | Real TLS 1.2 session capture via rustls |
| `sqlite` | Persistent session store |

### Tests

```bash
# Rust unit + integration tests:
cargo test --workspace --features frost,tcp,secp256k1

```

---

## Running a Local Network

3-of-5 network on localhost — all in-process using `InProcessTransport`.

### Step 1 — DKG

```bash
./target/release/dkg-ceremony \
  --threshold 3 \
  --num-nodes 5 \
  --output-dir /tmp/keys/
```

Produces `/tmp/keys/node-{0..4}.json` (key shares) and `/tmp/keys/group-key.json`.

### Step 2 — Start aux nodes

```bash
for i in 0 1 2 3 4; do
  ./target/release/aux-node --config /tmp/keys/node-$i.json &
done
```

Default ports: `9200`–`9204`.

### Step 3 — Start coordinator

```bash
./target/release/coordinator --config coordinator.json
```

### Step 4 — Request attestation

```bash
curl -X POST http://localhost:9100/attest \
  -H "Content-Type: application/json" \
  -d '{
    "prover_id_hex": "0101010101010101010101010101010101010101010101010101010101010101",
    "client_nonce_hex": "0202020202020202020202020202020202020202020202020202020202020202",
    "statement_tag": "example.com/balance",
    "query": "GET /balance HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "requested_ttl_secs": 3600
  }'
```

Response — `FrostAttestationEnvelope` JSON:

```json
{
  "session": { "prover_id": "...", "epoch": 1, "nonce": "..." },
  "randomness": { "rand_binding": "...", "dvrf_proof": "..." },
  "statement": { "tag": "example.com/balance", "digest": "..." },
  "frost_approval": {
    "signature_r": "...",
    "signature_s": "...",
    "group_verifying_key": "..."
  },
  "envelope_digest": "..."
}
```

Produce a `frost_approval` aggregate signature for the quorum.

---

## Security Notes

### Prototype Components

The following are **not production-safe**:

- `PrototypeDvrf` — uses `H(key XOR alpha)` instead of DDH-based DVRF. Correct interface, insecure construction.
- `PrototypeThresholdSigner` — single-round, single-party. Does not threshold.
- `PrototypeAttestationEngine` — skips real TLS session verification.
- `frost_trusted_dealer_keygen` — the dealer sees all key shares. For tests and benchmarks only.
- `mock_tls12_session` / `mock_tls13_session` — synthetic session parameters.

The production path uses `Secp256k1Dvrf` (DDH-DVRF on secp256k1) and ed25519/secp256k1 FROST from `frost-core`.

### co-SNARK: Two Modes

The paper (§VIII.C eq. 2) specifies:

```
(K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp)
```

where each party holds their witness independently. Two modes are implemented:

**Distributed mode** (`--distributed`): uses the Özdemir & Boneh (USENIX Security 2022) collaborative zkSNARK library directly. Two subprocesses communicate over localhost TCP using additive secret sharing — neither party reconstructs the other's share. K_MAC is never assembled in one place. This is the only co-SNARK mode used by `run_wan_tables.sh`.

### BN254 Zero-Verifying-Key

### Schnorr Challenge Divergence

---