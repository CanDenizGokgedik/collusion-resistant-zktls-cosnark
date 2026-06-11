#!/usr/bin/env bash
# run_wan_tables.sh
# ─────────────────────────────────────────────────────────────────────────────
# One command → three tables: LAN, WAN1, WAN2.
# Full Π_coll-min pipeline, distributed (2-party MPC) co-SNARK with the REAL
# SHA-256 TLS-PRF circuit (K_MAC = TLS-PRF(PMS); binding secret-shared).
#
# Columns: DKG(ms) DVRF(ms) HSP(ms) PGP(ms) TSS(ms) OnChain(gas) Total(ms) Net(kb)
#
# Self-contained: the collaborative-zksnark MPC library is vendored into
# ./collaborative-zksnark-main (no git submodule step needed).
#
# Usage:   ./run_wan_tables.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PROVER_BIN="crates/co-snark-prover/target/release/co-snark-prover"

# Keep ONLY hard errors on the terminal; drop warnings and their context lines.
# rustc warning blocks look like: "warning: ...", then "  --> file", "   | ",
# "  = note", "N | code", "   ^^^", and blank lines. Errors start with "error".
filter_build() {
  grep -E "^error|^error\[|could not compile|^\[" || true
}

if [ ! -d "collaborative-zksnark-main" ] || [ -z "$(ls -A collaborative-zksnark-main 2>/dev/null)" ]; then
  echo "error: vendored collaborative-zksnark-main is missing from the bundle." >&2
  exit 1
fi

# 1. Build the standalone 2-party MPC co-SNARK prover (vendored ark 0.2 crate).
echo "[1/3] building co-snark-prover (vendored MPC library)…" >&2
set +e
( cd crates/co-snark-prover && cargo build --release 2>&1 ) | filter_build
st=${PIPESTATUS[0]}
set -e
[ "$st" -eq 0 ] || { echo "co-snark-prover build FAILED (rerun without filter to see details: cd crates/co-snark-prover && cargo build --release)" >&2; exit 1; }

# 2. Build the main workspace bench (only feature gate is "tcp").
echo "[2/3] building bench_pipeline_wan…" >&2
set +e
cargo build --release --package tls-attestation-bench \
  --bin bench_pipeline_wan --features tcp 2>&1 | filter_build
st=${PIPESTATUS[0]}
set -e
[ "$st" -eq 0 ] || { echo "bench build FAILED (rerun without filter: cargo build --release -p tls-attestation-bench --bin bench_pipeline_wan --features tcp)" >&2; exit 1; }

# 3. Run — full SHA-256 TLS-PRF co-SNARK enabled. Prints only the three tables.
echo "[3/3] running…" >&2
COSNARK_FULL_CIRCUIT=1 \
  ./target/release/bench_pipeline_wan --binary "$ROOT/$PROVER_BIN"
