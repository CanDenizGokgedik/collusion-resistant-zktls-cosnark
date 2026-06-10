#!/usr/bin/env bash
# wan_compare.sh — Run distributed co-SNARK benchmark under three network conditions
# and display a unified comparison table.
#
# New column layout (after bench_full_pipeline split):
#   DKG    = Pedersen DKG         (O(n^2), pre-computable)
#   DVRF   = Threshold VRF eval   (O(n), per-session)
#   HSP    = K_MAC split + co-SNARK proof  (the ZK phase)
#   PGP    = Query commit + proof assembly (<1ms)
#   Sign   = FROST threshold sign
#
# Usage:
#   chmod +x wan_compare.sh && ./wan_compare.sh [--skip-build]

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[..]${NC}  $*"; }
step() { echo -e "${CYAN}[>>]${NC}  $*"; }

SKIP_BUILD=0
for arg in "$@"; do
  case $arg in --skip-build) SKIP_BUILD=1 ;; esac
done

PROVER_BIN="crates/co-snark-prover/target/release/co-snark-prover"

# ── Build ──────────────────────────────────────────────────────────────────────
if [ "$SKIP_BUILD" = "1" ] && [ -f "$PROVER_BIN" ]; then
  ok "Binaries exist (--skip-build)"
else
  step "Building co-snark-prover..."
  (cd crates/co-snark-prover && cargo build --release 2>&1) | tail -1
  step "Building main workspace..."
  cargo build --release --quiet
  ok "Build complete"
fi

BINARY="$(pwd)/$PROVER_BIN"

# ── Helper: run one benchmark, capture raw output ─────────────────────────────
run_bench() {
  local latency_ms="$1"
  MPC_LATENCY_MS="$latency_ms" COSNARK_FULL_CIRCUIT=1 \
    cargo run --package tls-attestation-bench --bin bench_full_pipeline \
      --release --quiet -- --binary "$BINARY" --distributed 2>/dev/null
}

# ── Helper: extract a column value for a given config row ─────────────────────
# New columns: Config DKG DVRF HSP(co-SNARK) PGP Sign Total
#              col     1   2    3             4   5    6
extract_col() {
  local output="$1"
  local config="$2"
  local col="$3"
  echo "$output" \
    | grep -E "^\s+${config}\s+" \
    | awk -v c="$((col+1))" '{print $c}' \
    | head -1
}

# ── Run three scenarios ────────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  WAN Comparison: Distributed co-SNARK under network conditions        ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""

CONFIGS=("2-of-3" "3-of-5" "5-of-9" "7-of-13" "10-of-19" "15-of-29" "20-of-39" "30-of-59" "50-of-99")

step "Running LAN (no delay)..."
OUT_LAN=$(run_bench 0)
ok "LAN done"

step "Running WAN1 (RTT=80ms)..."
OUT_WAN1=$(run_bench 80)
ok "WAN1 done"

step "Running WAN2 (RTT=150ms)..."
OUT_WAN2=$(run_bench 150)
ok "WAN2 done"

# ── Print comparison table ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  Distributed 2-party MPC co-SNARK — timing (ms) by network condition${NC}"
echo ""
printf "  %-12s  %8s  %6s  %10s  %10s  %10s  %8s\n" \
  "Config" "DKG" "DVRF" "HSP/LAN" "HSP/WAN1" "HSP/WAN2" "Sign"
printf "  %-12s  %8s  %6s  %10s  %10s  %10s  %8s\n" \
  "────────────" "────────" "──────" "──────────" "──────────" "──────────" "────────"

for cfg in "${CONFIGS[@]}"; do
  dkg=$(extract_col  "$OUT_LAN"  "$cfg" 1)
  dvrf=$(extract_col "$OUT_LAN"  "$cfg" 2)
  hsp_lan=$(extract_col  "$OUT_LAN"  "$cfg" 3)
  hsp_wan1=$(extract_col "$OUT_WAN1" "$cfg" 3)
  hsp_wan2=$(extract_col "$OUT_WAN2" "$cfg" 3)
  sign=$(extract_col "$OUT_LAN"  "$cfg" 5)

  printf "  %-12s  %8s  %6s  %10s  %10s  %10s  %8s\n" \
    "$cfg" "$dkg" "$dvrf" "$hsp_lan" "$hsp_wan1" "$hsp_wan2" "$sign"
done

echo ""
echo "  DKG      — Pedersen DKG (O(n^2)), pre-computable: reuse across sessions"
echo "  DVRF     — Threshold VRF evaluation (O(n)), required per session"
echo "  HSP      — K_MAC split + co-SNARK Groth16 proof (2-party MPC)"
echo "  Sign     — FROST threshold signature"
echo ""
echo "  HSP/LAN  — localhost, no added delay"
echo "  HSP/WAN1 — RTT=80ms  (one-way 40ms +/-5ms,  50 Mbps, 0.1% loss)"
echo "  HSP/WAN2 — RTT=150ms (one-way 75ms +/-15ms, 20 Mbps, 0.2% loss)"
echo ""
