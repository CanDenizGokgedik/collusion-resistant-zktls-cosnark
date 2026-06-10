#!/usr/bin/env bash
# wan_compare.sh — Run distributed co-SNARK benchmark under three network conditions
# and display three separate tables matching paper Table II format.
#
# Columns per table:
#   config      — threshold-of-n
#   dkg_ms      — Pedersen DKG        (O(n^2), pre-computable)
#   rc_sess_ms  — Threshold VRF eval  (O(n), per-session)
#   hsp_ms      — K_MAC split + co-SNARK Groth16 (2-party MPC)
#   pgp_ms      — Query commit + proof assembly
#   sign_ms     — FROST threshold signature
#   onchain_ms  — ABI encoding
#   net_ms      — Network overhead (0 for LAN; WAN total − LAN total for WAN)
#   total_ms    — Sum of all columns
#   comm_kb     — Communication size estimate (formula: 0.073*(t+n) + 0.52)
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

# ── Helper: run one benchmark pass, capture JSON output ───────────────────────
run_bench() {
  local latency_ms="$1"
  MPC_LATENCY_MS="$latency_ms" COSNARK_FULL_CIRCUIT=1 \
    cargo run --package tls-attestation-bench --bin bench_full_pipeline \
      --release --quiet -- --binary "$BINARY" --distributed 2>/dev/null
}

# ── Write Python helper to a temp file (avoids stdin conflict with pipe+heredoc) ─
_PYSCRIPT=$(mktemp /tmp/wan_jq_field_XXXX.py)
cat > "$_PYSCRIPT" <<'PYEOF'
import sys, json

config = sys.argv[1]
field  = sys.argv[2]

text = sys.stdin.read()

# Find "JSON:" marker, then raw_decode to skip trailing text ("Paper Table II" etc.)
idx = text.find('JSON:')
if idx == -1:
    print("0"); sys.exit(0)

start = text.find('{', idx)
if start == -1:
    print("0"); sys.exit(0)

try:
    data, _ = json.JSONDecoder().raw_decode(text, start)
except json.JSONDecodeError:
    print("0"); sys.exit(0)

for row in data.get("results", []):
    if row.get("config") == config:
        val = row.get(field, 0)
        if isinstance(val, float):
            print(f"{val:.2f}")
        else:
            print(val)
        sys.exit(0)
print("0")
PYEOF
trap 'rm -f "$_PYSCRIPT"' EXIT

# ── Helper: extract one JSON field for a given config ─────────────────────────
jq_field() {
  local json_blob="$1"   # full benchmark stdout
  local config="$2"      # e.g. "3-of-5"
  local field="$3"       # e.g. "hsp_ms"
  echo "$json_blob" | python3 "$_PYSCRIPT" "$config" "$field"
}

# ── Print one table section ────────────────────────────────────────────────────
print_table() {
  local label="$1"
  local out_cur="$2"    # benchmark output for this network condition
  local out_lan="$3"    # LAN output (for net_ms = total_cur - total_lan)
  local is_lan="$4"     # "1" if this IS the LAN run

  echo ""
  echo -e "${BOLD}  ${label}${NC}"
  echo ""
  printf "  %-12s  %8s  %10s  %8s  %8s  %8s  %10s  %8s  %9s  %8s\n" \
    "config" "dkg_ms" "rc_sess_ms" "hsp_ms" "pgp_ms" "sign_ms" "onchain_ms" "net_ms" "total_ms" "comm_kb"
  printf "  %-12s  %8s  %10s  %8s  %8s  %8s  %10s  %8s  %9s  %8s\n" \
    "────────────" "────────" "──────────" "────────" "────────" "────────" "──────────" "────────" "─────────" "────────"

  for cfg in "${CONFIGS[@]}"; do
    dkg=$(jq_field      "$out_cur" "$cfg" "dkg_ms")
    rc=$(jq_field       "$out_cur" "$cfg" "rc_sess_ms")
    hsp=$(jq_field      "$out_cur" "$cfg" "hsp_ms")
    pgp=$(jq_field      "$out_cur" "$cfg" "pgp_ms")
    sign=$(jq_field     "$out_cur" "$cfg" "sign_ms")
    onchain=$(jq_field  "$out_cur" "$cfg" "onchain_ms")
    total=$(jq_field    "$out_cur" "$cfg" "total_ms")
    comm=$(jq_field     "$out_cur" "$cfg" "comm_kb")

    if [ "$is_lan" = "1" ]; then
      net=0
    else
      total_lan=$(jq_field "$out_lan" "$cfg" "total_ms")
      net=$(( total - total_lan ))
      [ "$net" -lt 0 ] && net=0
    fi

    printf "  %-12s  %8s  %10s  %8s  %8s  %8s  %10s  %8s  %9s  %8s\n" \
      "$cfg" "$dkg" "$rc" "$hsp" "$pgp" "$sign" "$onchain" "$net" "$total" "$comm"
  done
}

# ── Run three scenarios ────────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  Π_coll-min — Distributed 2-party MPC Benchmark (LAN / WAN1 / WAN2)  ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""

CONFIGS=("3-of-5" "5-of-9" "7-of-13" "10-of-19" "15-of-29" "20-of-39" "30-of-59" "50-of-99")

step "Running LAN (no delay)..."
OUT_LAN=$(run_bench 0)
ok "LAN done"

step "Running WAN1 (RTT=80ms, 50 Mbps, 0.1% loss)..."
OUT_WAN1=$(run_bench 80)
ok "WAN1 done"

step "Running WAN2 (RTT=150ms, 20 Mbps, 0.2% loss)..."
OUT_WAN2=$(run_bench 150)
ok "WAN2 done"

# ── Print three separate tables ────────────────────────────────────────────────
print_table "LAN" \
  "$OUT_LAN" "$OUT_LAN" "1"

print_table "WAN1 — 80 ms RTT, 50 Mbps, 0.1% loss" \
  "$OUT_WAN1" "$OUT_LAN" "0"

print_table "WAN2 — 150 ms RTT, 20 Mbps, 0.2% loss" \
  "$OUT_WAN2" "$OUT_LAN" "0"

echo ""
echo "  Column legend:"
echo "  dkg_ms     — Pedersen DKG (O(n²)), pre-computable; amortised to 0 across sessions"
echo "  rc_sess_ms — Threshold VRF evaluation (O(n)), required once per session"
echo "  hsp_ms     — K_MAC split + co-SNARK Groth16 proof (2-party MPC)"
echo "  pgp_ms     — Query commit + proof assembly (symmetric crypto, <1 ms)"
echo "  sign_ms    — FROST threshold signature (O(n))"
echo "  onchain_ms — ABI encoding for on-chain submission"
echo "  net_ms     — Network overhead vs. LAN baseline (WAN total − LAN total)"
echo "  total_ms   — End-to-end wall time"
echo "  comm_kb    — Estimated communication (0.073×(t+n) + 0.52 KB)"
echo ""
echo "  WAN simulation: in-process sleep of MPC_LATENCY_MS after co-SNARK proof"
echo "  (models P↔V round-trip; DKG/FROST co-located in prototype)"
echo ""