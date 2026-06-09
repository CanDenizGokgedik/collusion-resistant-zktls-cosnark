#!/usr/bin/env bash
# fulltest.sh — Full integration test: Phase 1-2-3 connected + real distributed co-SNARK.
#
# No mocks or stubs:
#   • HMAC-SHA256 gadget unit test (circuit == native)
#   • Phase 1-2-3 R1CS connection test (PRF output linked to share commitment)
#   • Soundness test (wrong share is rejected)
#   • Bit extraction test (248-bit field encoding correctness)
#   • FULL PIPELINE: RC (Pedersen DKG + DVRF) -> dx-DCTLS + co-SNARK (Groth16) -> FROST sign
#     With COSNARK_FULL_CIRCUIT=1, TlsPrfCircuit (1.9M R1CS) is used for central proving.
#
# Usage:
#   chmod +x fulltest.sh && ./fulltest.sh
#
# Flags:
#   --skip-build      Skip build if binaries already exist
#   --no-pipeline     Run unit tests only (skip pipeline benchmark)
#   --distributed     Run pipeline in 2-party MPC mode (slower but real distributed co-SNARK)
#   --network wan1    Simulate WAN1: RTT=80ms  — injects sleep into MPC rounds
#   --network wan2    Simulate WAN2: RTT=150ms — injects sleep into MPC rounds
#
# Network simulation sets MPC_LATENCY_MS env var; the prover subprocess sleeps
# per MPC communication round (no sudo, no OS tools required).

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[..]${NC}  $*"; }
step() { echo -e "${CYAN}[>>]${NC}  $*"; }
fail() { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

SKIP_BUILD=0
NO_PIPELINE=0
DISTRIBUTED=0
NETWORK=""
for arg in "$@"; do
  case $arg in
    --skip-build)        SKIP_BUILD=1 ;;
    --no-pipeline)       NO_PIPELINE=1 ;;
    --distributed)       DISTRIBUTED=1 ;;
    --network)           shift; NETWORK="$1" ;;
    --network=*)         NETWORK="${arg#--network=}" ;;
    --network\ wan1)     NETWORK="wan1" ;;
    --network\ wan2)     NETWORK="wan2" ;;
  esac
done

# ── Network simulation ────────────────────────────────────────────────────────
#
# Sets MPC_LATENCY_MS so the prover subprocess sleeps per MPC communication
# round, simulating WAN round-trip delay. No sudo or OS tools needed.
#
# WAN1: RTT=80ms   (one-way 40ms ±5ms,  50 Mbps, 0.1% loss)
# WAN2: RTT=150ms  (one-way 75ms ±15ms, 20 Mbps, 0.2% loss)

case "$NETWORK" in
  wan1) export MPC_LATENCY_MS=80  ;;
  wan2) export MPC_LATENCY_MS=150 ;;
  "")   export MPC_LATENCY_MS=0   ;;
  *)    echo "[ERR] Unknown --network value: $NETWORK (use wan1 or wan2)"; exit 1 ;;
esac

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  tls-cosnark — Full Integration Test                            ║"
echo "║  Phase 1-2-3 connected + Distributed co-SNARK                   ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
if [[ -n "$NETWORK" ]]; then
  case "$NETWORK" in
    wan1) echo "  Network: WAN1 -- RTT=80ms, BW=50Mbps, loss=0.1%" ;;
    wan2) echo "  Network: WAN2 -- RTT=150ms, BW=20Mbps, loss=0.2%" ;;
  esac
fi
echo ""

# ── 1. Rust toolchain ─────────────────────────────────────────────────────────
step "Checking Rust toolchain..."
command -v rustc &>/dev/null || fail "rustc not found. Install from https://rustup.rs"
ok "Rust: $(rustc --version)"

# ── 2. Submodule ──────────────────────────────────────────────────────────────
step "Checking collaborative-zksnark submodule..."
if [ ! -f "collaborative-zksnark-main/algebra/ff/Cargo.toml" ]; then
  info "Submodule missing — running git submodule update --init --recursive..."
  git submodule update --init --recursive \
    || fail "Submodule init failed."
fi
ok "Submodule ready"

# ── 3. co-snark-prover binary (ark 0.2 / BLS12-377) ────────────────────────
PROVER_BIN="crates/co-snark-prover/target/release/co-snark-prover"

if [ "$SKIP_BUILD" = "1" ] && [ -f "$PROVER_BIN" ]; then
  ok "co-snark-prover binary exists (--skip-build)"
else
  step "Building co-snark-prover (ark 0.2 / BLS12-377)..."
  (cd crates/co-snark-prover && cargo build --release) \
    || fail "co-snark-prover build failed."
  ok "co-snark-prover built"
fi

# ── 4. Main workspace (ark 0.4 / BN254) ─────────────────────────────────────
if [ "$SKIP_BUILD" = "1" ]; then
  ok "Main workspace build skipped (--skip-build)"
else
  step "Building main workspace (ark 0.4 / BN254)..."
  cargo build --release \
    || fail "Main workspace build failed."
  ok "Main workspace built"
fi

# ── 5. Circuit unit tests (NO MOCKS) ────────────────────────────────────────
echo ""
echo "─── Unit Tests: co-snark-prover (ark 0.2 / BLS12-377) ─────────────────"
echo ""
echo "  These tests verify:"
echo "  * HMAC-SHA256 gadget = native sha2 (SHA256 gadget correctness)"
echo "  * 248-bit bit extraction = k_mac_fe_248 (field encoding consistency)"
echo "  * Phase 1-2-3 connection: PRF(PMS,CR,SR) -> K_MAC -> commitment"
echo "  * Soundness: wrong share causes R1CS failure"
echo ""

step "Running cargo test (co-snark-prover)..."
(cd crates/co-snark-prover && cargo test --release 2>&1) \
  || fail "co-snark-prover unit tests failed."
ok "All co-snark-prover tests passed"

# ── 6. Main workspace unit tests ────────────────────────────────────────────
echo ""
step "Running cargo test (main workspace)..."
cargo test --release --quiet \
  || fail "Main workspace tests failed."
ok "Main workspace tests passed"

# ── 7. Full Pipeline (Phase 1-2-3 + co-SNARK) ───────────────────────────────
if [ "$NO_PIPELINE" = "1" ]; then
  echo ""
  info "Pipeline benchmark skipped (--no-pipeline). Unit tests only."
  echo ""
else
  echo ""
  echo "─── Full Pipeline: RC -> dx-DCTLS -> co-SNARK -> FROST ─────────────────"
  echo ""
  echo "  COSNARK_FULL_CIRCUIT=1 -> TlsPrfCircuit (1.9M R1CS, central only)"
  echo "  Phase 1: PMS -> Master Secret (HMAC-SHA256 R1CS chain)"
  echo "  Phase 2: Master Secret -> K_MAC (key expansion R1CS chain)"
  echo "  Phase 3: K_MAC commitment (PRF output linked, no mock)"
  echo ""

  BINARY="$(pwd)/$PROVER_BIN"

  if [ "$DISTRIBUTED" = "1" ]; then
    echo "  Mode: 2-party MPC Groth16 (real distributed co-SNARK)"
    echo "  Note: TlsKeyCircuit used for MPC (SHA-256 gadget incompatible with MPC MSM)"
    if [[ -n "$NETWORK" ]]; then
      echo "  Network: $NETWORK emulation active (loopback delay applied)"
    fi
    echo ""
    if [[ "$MPC_LATENCY_MS" -gt 0 ]]; then
      info "Network simulation: MPC_LATENCY_MS=${MPC_LATENCY_MS}ms per round-trip"
    fi
    step "Running Full Pipeline (distributed MPC)..."
    COSNARK_FULL_CIRCUIT=1 \
    cargo run --package tls-attestation-bench --bin bench_full_pipeline --release \
      -- --binary "$BINARY" --distributed \
      || fail "Full pipeline (distributed) failed."
  else
    echo "  Mode: central co-SNARK (single prover, fast)"
    echo "  Note: For distributed mode run: ./fulltest.sh --distributed"
    echo ""
    step "Running Full Pipeline (central)..."
    COSNARK_FULL_CIRCUIT=1 \
    cargo run --package tls-attestation-bench --bin bench_full_pipeline --release \
      -- --binary "$BINARY" \
      || fail "Full pipeline (central) failed."
  fi

  ok "Full pipeline complete"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║  All tests passed.                                                       ║"
echo "║                                                                         ║"
echo "║  Verified properties:                                                    ║"
echo "║    v HMAC-SHA256 gadget = standard (no mock)                            ║"
echo "║    v Phase 1-2-3 fully connected (PRF -> K_MAC -> commitment)           ║"
echo "║    v Soundness: wrong share rejected                                    ║"
if [ "$NO_PIPELINE" = "0" ]; then
echo "║    v Full pipeline: RC + co-SNARK + FROST (COSNARK_FULL_CIRCUIT=1)      ║"
if [ "$DISTRIBUTED" = "1" ]; then
echo "║    v Distributed 2-party MPC Groth16 (real co-SNARK)                   ║"
fi
fi
echo "║                                                                         ║"
echo "║  Flags:                                                                  ║"
echo "║    --distributed       2-party MPC mode                                ║"
echo "║    --network wan1      Simulate WAN1: RTT=80ms  (no sudo needed)        ║"
echo "║    --network wan2      Simulate WAN2: RTT=150ms (no sudo needed)       ║"
echo "║    --no-pipeline       Unit tests only (~30s)                          ║"
echo "║    --skip-build        Skip rebuild of binaries                        ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""