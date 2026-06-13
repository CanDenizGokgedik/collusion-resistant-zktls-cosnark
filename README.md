not use, only research purpose, inspired by https://github.com/jplaui/decoTls12MtE

# DECO TLS 1.2 MtE — Full Pipeline (HSP 2PC + PGP), prover ↔ verifier

The complete plain-DECO baseline for the `dx-DCTLS` efficiency comparison, in
one repo. Compared to the co-SNARK repo the **only** differences are: the HSP is
a **2PC** (not a co-SNARK), and there is **no DVRF and no TSS** (and no DKG).

```
HSP (2PC, mpz)   ->  K_MAC additive shares (k_mac_p to P, k_mac_v to V)
     |                + verifier-sampled rand_binding   (replaces the DVRF)
     v                  K_MAC = k_mac_p XOR k_mac_v
bind             ->  k_mac_commitment = pack(K_MAC) + rand_binding   (verifier-held)
     v
PGP (Groth16)    ->  prove MAC-then-Encrypt over 3 AES blocks (16B pt + 32B MAC),
     v                 with K_MAC bound to the commitment
verify           ->  verifier checks the PGP SNARK    (protocol end)
```

* **HSP** — `crates/hsp-2pc`, built on [mpz](https://github.com/privacy-ethereum/mpz)
  garbled circuits. The verifier samples randomness exactly like the prover; no
  public verifiability — the verifier is convinced by participating. Outputs the
  additive K_MAC shares.
* **PGP** — `crates/pgp`, the Groth16 mac-then-encrypt circuit reused verbatim
  from the co-SNARK repo (SHA-256 / HMAC / AES-128-CBC gadgets), proving
  `MAC = HMAC-SHA256(K_MAC, ·)`, `ct = AES-128-CBC(K_ENC, pt‖MAC‖pad)`, and
  `pack(K_MAC) + rand_binding = commitment`. The 48-byte `pt‖MAC` is exactly
  3 AES blocks.
* **runner** — `crates/runner`, glues HSP → bind → PGP → verify and prints timings.

## Quick  Run

```
cargo run --release --bin bench_deco_wan
```

Requires Rust 1.85+ (mpz is edition 2024). First build clones mpz (alpha,
`v0.1.0-alpha.6`) and the arkworks 0.4 stack.

## Status / next iteration

- End-to-end wiring (2PC handshake → K_MAC binding → Groth16 PGP → verify) is
  complete; this is the apples-to-apples DECO baseline against the co-SNARK
  pipeline, minus DVRF/TSS.
- The HSP now runs the **full TLS 1.2 PRF** (master-secret + key-expansion,
  ~40-50 SHA-256 compressions), so the handshake cost is realistic — no longer
  the single-compression stand-in.
- In the networked protocol the 2PC reveals the commitment to the verifier; the
  single-process runner reconstructs K_MAC from both shares and computes it
  directly (representative for the benchmark).

> Research prototype. Not for production.

## WAN benchmark (LAN / WAN1 / WAN2)

```
cargo run --release --bin bench_deco_wan
```

Prints three tables (LAN, WAN1, WAN2) with per-session **HSP(ms) PGP(ms)
Total(ms) Net(kb)** — same methodology as the Π_coll-min pipeline benchmark, but
DECO has no DKG/DVRF/TSS. Pure compute is measured once (HSP via the in-process
2PC, PGP via a real Groth16 prove); the three network profiles are then applied
analytically, so all three tables come from a single execution.

- **HSP** is a Yao garbled circuit: ~26 MB of garbled tables (36 SHA-256
  compressions × 22 573 AND × 32 B), constant-round ⇒ bandwidth-bound on WAN.
- **PGP** is the mac-then-encrypt Groth16 proof (identical circuit to the
  co-SNARK pipeline's PGP); the proof is a few hundred bytes ⇒ compute-bound.
- PGP column is prove time; Groth16 `setup` (~19 s) is a one-time CRS cost,
  amortized away, so it is not in the per-session table.
