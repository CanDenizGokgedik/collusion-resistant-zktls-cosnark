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
5. [Smart Contracts](#smart-contracts)
6. [Binaries](#binaries)
7. [Benchmarks](#benchmarks)
8. [Building](#building)
9. [Running a Local Network](#running-a-local-network)
10. [Security Notes](#security-notes)

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
└── contracts/
    ├── src/
    │   ├── FrostVerifier.sol   # secp256k1 Schnorr SC.Verify (ecrecover trick)
    │   └── DctlsVerifier.sol   # Groth16 BN254 ZKP.Verify (EIP-197)
    └── test/
        ├── FrostVerifier.t.sol
        └── DctlsVerifier.t.sol
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
| `secp256k1` | secp256k1 FROST + DDH-DVRF — EVM-compatible, used in benchmarks and `FrostVerifier.sol` |

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
| `tls_session_binding` | PGP proof: ZKP.Prove(x=(Q,R,θs), w=(Q̂,R̂,spv,b)) | §VIII.C PGP |
| `vk_export` | Export arkworks verifying key → Solidity calldata | §IX |

```rust
use tls_attestation_zk::{CoSnarkCrs, co_snark_execute, co_snark_verify};

let crs = CoSnarkCrs::setup()?;   // one-time trusted setup
let proof = co_snark_execute(&crs, &prover_share, &verifier_share, &pms)?;
co_snark_verify(&crs.vk, &k_mac_commitment, &proof)?;
```

> **Two modes available:** Central mode assembles the full witness at the coordinator (honest-but-curious assumption). Distributed mode (`--distributed` flag) uses the Özdemir & Boneh collaborative-zksnark library — two subprocesses run the 2-party MPC Groth16 protocol over localhost TCP, so K_MAC is never reconstructed in one place. See §Benchmarks for measured timings.

### `tls-attestation-attestation`

dx-DCTLS session logic — DECO and Distefano variants.

| Module | TLS version | Handshake binding | Paper ref |
|--------|-------------|-------------------|-----------|
| `deco_dx_dctls` | TLS 1.2 | co-SNARK π_HSP over K_MAC | §VIII.C eq. 2 |
| `distefano_dx_dctls` | TLS 1.3 | v2PC π_2PC over traffic secrets | §VIII.C eq. 3 |
| `rc_phase` | — | DKG + DVRF orchestration | §V RC Phase |
| `onchain` | — | FrostAttestationEnvelope → on-chain format | §IX |

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

## Smart Contracts

Located in `contracts/`. Requires [Foundry](https://getfoundry.sh/).

### `FrostVerifier.sol` — on-chain SC.Verify

Verifies secp256k1 FROST Schnorr signatures (paper §VIII.B, Table I).

```solidity
function verify(
    bytes32 message_hash,
    uint256 pk_x,
    uint256 pk_y,
    uint256 sig_R_x,
    uint256 sig_s
) public view returns (bool)
```

The EVM has no secp256k1 scalar multiplication precompile (0x06/0x07 are BN254-only). This contract implements Schnorr verification via the `ecrecover` precompile (0x01), which internally uses secp256k1. Gas cost: **~14,000 gas**.

Challenge hash convention (EVM-compatible, differs from RFC 9591):
```
e = keccak256(R_x ‖ pk_x ‖ message_hash) mod N
```

### `DctlsVerifier.sol` — on-chain ZKP.Verify

Verifies Groth16 proofs on BN254 using EIP-196/197 precompiles (paper §IX).

```solidity
// Set verifying keys once after deployment (owner only):
function setHspVK(VerifyingKey calldata vk, uint256[2][4] calldata ic) external onlyOwner;
function setSessionBindingVK(VerifyingKey calldata vk, uint256[2][5] calldata ic) external onlyOwner;

// Atomic verification — reverts if any proof is invalid:
function verifyFullAttestation(
    Proof calldata hspProof,
    Proof calldata sessionProof,
    uint256 kMacCommitment,
    uint256 randBinding,
    uint256 pmsHash,
    uint256 macCommitmentQ,
    uint256 macCommitmentR
) external view;
```

Gas cost: **~181,000 gas** per `verifyFullAttestation` (4-pairing BN254 check).

### Running Contract Tests

```bash
cd contracts && forge test -v
```

Output (17 tests, 0 failures — measured on this machine):
```
Ran 8 tests for FrostVerifier.t.sol:
[PASS] test_Deploy()          (gas:     2,462)
[PASS] test_GasCost()         (gas:    13,918)  ← ~14k gas, paper Table I
[PASS] test_ValidSignature()  (gas:    12,424)
[PASS] test_WrongMessage()    (gas:    12,422)
[PASS] test_WrongPubKeyX()    (gas:    12,252)
[PASS] test_WrongRx()         (gas:     8,269)
[PASS] test_WrongSigS()       (gas:    12,284)
[PASS] test_ZeroSignature()   (gas:     8,176)

Ran 9 tests for DctlsVerifier.t.sol:
[PASS] test_Deploy()                              (gas:      8,212)
[PASS] test_OwnerCanSetVK()                       (gas:     55,359)
[PASS] test_OwnerCanSetHspMode2VK()               (gas:     60,945)
[PASS] test_OwnerCanSetSessionBindingVK()         (gas:     65,932)
[PASS] test_OnlyOwnerCanSetVK()                   (gas:     12,142)
[PASS] test_Gas_HspMode1()                        (gas:    263,682)  ← ~181k pairing gas
[PASS] test_ZeroProofWithZeroVK_IsAccepted_ByPairing() (gas: 261,232)
[PASS] test_FullAttestation_ZeroProof_PassesTrivially() (gas: 561,728)
[PASS] test_FullZKP_Skipped()                     (gas:        524)
```

> **Warning:** `DctlsVerifier.sol` accepts all-zero proofs when the verifying key is all-zero (BN254 identity). Always call `setHspVK` and `setSessionBindingVK` with real circuit keys before accepting proofs.

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

Generates secp256k1 Schnorr test vectors with the exact `keccak256(R_x ‖ pk_x ‖ msg) mod N` challenge used by `FrostVerifier.sol`.

---

## Benchmarks

All results measured on **Apple M2, release build (`--release`)**. All crypto is real — no stubs in the numbers below.

> **What is and isn't mocked:** DKG, DVRF, FROST signing, and Groth16 proving are all genuine. TLS sessions use `mock_tls12_session` (deterministic synthetic parameters) rather than a live HTTPS connection — network round-trips are not included.

---

### 1 — DVRF-then-Sign: DKG + DVRF + TSS (paper §IX, Fig. 9)

```bash
cargo run --package tls-attestation-bench --bin bench_dvrf_tss --release
```

Real secp256k1 FROST DKG, real DDH-DVRF (Secp256k1Dvrf), real FROST threshold signing.

```
Config       DKG (ms)  DVRF (ms)   TSS (ms)  Total (ms)
───────────────────────────────────────────────────────
2-of-3              5          1          1          7
3-of-5             13          1          1         15
4-of-7             33          2          2         37
5-of-9             63          2          3         68
7-of-13           179          4          4        187
10-of-19          459          6          6        471
15-of-29         1558         12         12       1582
```

DKG is O(n²) in verifier count and dominates at large n. DVRF + TSS are O(t) and stay below 25 ms even at 15-of-29.

---

### 2 — Full Pipeline: RC → co-SNARK → FROST → On-Chain (paper §VIII, Table II)

Demonstrates O(1) prover complexity. The co-SNARK column uses the **real Groth16 prover** (BLS12-377, Özdemir & Boneh collaborative-zksnark) with the TlsKeyCircuit (769 R1CS). See §3 below for the full TLS-PRF circuit timing.

#### 2a — Central co-SNARK (coordinator assembles full witness)

```bash
BINARY=crates/co-snark-prover/target/release/co-snark-prover
cargo run --package tls-attestation-bench --bin bench_full_pipeline --release \
  -- --binary "$BINARY"
```

```
Config       RC (ms)  co-SNARK (ms)  Sign (ms)  OnChain (ms)  Total (ms)
────────────────────────────────────────────────────────────────────────
2-of-3             6             23          1             0         30
3-of-5            17             19          1             0         37
5-of-9            90             17          2             0        109
7-of-13          168             16          4             0        188
10-of-19         517             18          8             0        543
```

co-SNARK is **O(1)** — constant ~18 ms regardless of quorum size. RC (DKG) cost dominates.

#### 2b — 2-Party MPC co-SNARK (Özdemir & Boneh, no witness reconstruction)

```bash
cargo run --package tls-attestation-bench --bin bench_full_pipeline --release \
  -- --binary "$BINARY" --distributed
```

Two separate subprocesses connect via localhost TCP and run the MPC Groth16 protocol. Neither party sees the other's MAC key share.

**Mode 1 (TlsKeyCircuit, 769 R1CS) — measured:**

**Mode 1 (TlsKeyCircuit, 769 R1CS) — measured:**

```
Config       RC (ms)  co-SNARK MPC (ms)  Sign (ms)  OnChain (ms)  Total (ms)
─────────────────────────────────────────────────────────────────────────────
2-of-3             5               219          1             0        225
3-of-5            14               225          1             0        240
5-of-9            64               225          3             0        292
7-of-13          177               229          4             0        410
10-of-19         475               335          9             0        819
```

MPC overhead vs. central Mode 1: **+~210 ms** (2 subprocess spawns + localhost TCP handshake + distributed MSM). MPC co-SNARK remains O(1) in quorum size.

**Mode 2 (TlsPrfCircuit, 1.9M R1CS, ark 0.2/BLS12-377) — MEASURED (central server mode):**

```
Groth16 CRS setup (Mode 2, ~1.9M R1CS)... 188,824ms  (one-time)

Config       RC (ms)   Attest (ms)   Sign (ms)   OnChain (ms)   Total (ms)
───────────────────────────────────────────────────────────────────────────
2-of-3             6        63,217           1              0       63,224
3-of-5            19        62,748           1              0       62,768
5-of-9            76        60,148           2              0       60,226
7-of-13          196        63,674           5              0       63,875
10-of-19         544        65,901          11              0       66,456
15-of-29        1838        66,347          13              0       68,198
20-of-39        4306        63,761          26              0       68,093
30-of-59       13160        56,105          52              0       69,317
50-of-99       58111        54,178         108              0      112,397
```

**Attest column is constant at ~60s** — scaling from 2-of-3 to 50-of-99 does not increase prover work (O(1) prover complexity). In the 50-of-99 configuration, the dominant cost is RC (DKG), not proving.

Backend comparison for the same 1.9M R1CS circuit: `ark 0.2/BLS12-377` ~62s (this pipeline), `ark 0.4/BN254` ~23s (`bench_dctls`), `gnark/BLS12-381` ~16-17s (paper [19]). The difference is entirely due to MSM optimizations in the respective prover backends, not the circuit itself.

---

### 3 — co-SNARK Circuit: R1CS Counts + TLS-PRF Timing (paper §IX)

```bash
cargo run --package tls-attestation-bench --bin bench_dctls --release
```

```
R1CS Constraint Counts:
  Mode 1 — K_MAC split only (TlsKeyCircuit):   769
  Mode 2 — full TLS-PRF   (TlsPrfCircuit):     1,927,271
  Paper [19] gnark/BLS12-381 target:            1,719,598
  Delta (arkworks/BN254 vs gnark):              +12.1%

Phase                                  Avg (ms)     Paper [19]
──────────────────────────────────────────────────────────────
HSP Mode 1 — 769 R1CS   (measured)        17ms           N/A
HSP Mode 2 — 1.9M R1CS  (MEASURED)    23,141ms        4,700ms
QP  — HMAC commit                          0ms          ~0ms
PGP — statement proof                      0ms         varies

  CRS setup Mode 1:   57ms
  CRS setup Mode 2:   68,094ms  (~68s)
  Prove    Mode 2:    23,141ms  (~23s)
```

Mode 2 is measured directly with `arkworks/BN254`. The paper's 4,700 ms uses `gnark/BLS12-381` — our result is **~5× slower**, consistent with arkworks being a less optimised prover backend (not ~2× as commonly cited; BN254 MSM is slower than BLS12-381 on this workload).

```bash
cargo run --package tls-attestation-bench --bin bench_dctls --release
```

---

## Building

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.78+ nightly | All Rust crates |
| Foundry (`forge`) | latest | Solidity tests |
| OpenSSL | 3.x | `--features mtls` only |

```bash
# Rust (nightly required for co-snark-prover)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default nightly

# Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup
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

# Solidity tests:
cd contracts && forge test -v
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

Submit `frost_approval` to `FrostVerifier.sol` for on-chain verification.

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

**Central mode** (default): the coordinator assembles the full `{K^P_MAC, K^V_MAC}` and runs standard single-prover Groth16. The coordinator therefore learns K_MAC. Acceptable under the honest-but-curious coordinator assumption (§IV).

**Distributed mode** (`--distributed`): uses the Özdemir & Boneh (USENIX Security 2022) collaborative zkSNARK library directly. Two subprocesses communicate over localhost TCP using additive secret sharing — neither party reconstructs the other's share. K_MAC is never assembled in one place. Use `--binary $BINARY --distributed` in `bench_full_pipeline`.

### BN254 Zero-Verifying-Key

`DctlsVerifier.sol` will accept any proof if the verifying key is all-zero (BN254 pairing identity). Always deploy with real circuit verifying keys set via `setHspVK` / `setSessionBindingVK`.

### Schnorr Challenge Divergence

`FrostVerifier.sol` uses `keccak256(R_x ‖ pk_x ‖ msg) mod N` — not the RFC 9591 domain-separated SHA-512 challenge. Test vectors from `gen-test-vectors` match this contract exactly.

---