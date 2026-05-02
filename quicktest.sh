#!/usr/bin/env bash
# quicktest.sh — Clone-and-run smoke test for tls-cosnark.
#
# Usage (from repo root):
#   chmod +x quicktest.sh && ./quicktest.sh
#
# Optional flags:
#   --mode2      Run the full TLS-PRF circuit (~3min setup + ~10min prove)
#   --skip-build Skip rebuilding if binaries already exist

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[..]${NC}  $*"; }
fail() { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

# ── Repo URL ──────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/CanDenizGokgedik/collusion-resistant-zktls-cosnark"
REPO_DIR="collusion-resistant-zktls-cosnark"

# ── Auto-clone if not inside the repo ────────────────────────────────────────
if [ ! -f "Cargo.toml" ] || [ ! -d "crates/co-snark-prover" ]; then
  info "Not inside repo root — attempting to clone..."
  command -v git &>/dev/null || fail "git not found. Install git first."
  if [ -d "$REPO_DIR" ]; then
    info "Directory '$REPO_DIR' already exists — skipping clone."
  else
    git clone --recurse-submodules "$REPO_URL" "$REPO_DIR" \
      || fail "Clone failed. Check your internet connection or run manually:
  git clone --recurse-submodules $REPO_URL"
    ok "Cloned into $REPO_DIR"
  fi
  cd "$REPO_DIR"
  ok "Changed into $(pwd)"
fi

# ── Flags ─────────────────────────────────────────────────────────────────────
RUN_MODE2=0
SKIP_BUILD=0
for arg in "$@"; do
  case $arg in
    --mode2)      RUN_MODE2=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
  esac
done

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║         tls-cosnark — quick smoke test                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Rust ───────────────────────────────────────────────────────────────────
info "Checking Rust toolchain..."
command -v rustup &>/dev/null || fail "rustup not found. Install from https://rustup.rs"
RUST_VER=$(rustc --version 2>/dev/null || echo "unknown")
ok "Rust: $RUST_VER"

# ── 2. Submodule ──────────────────────────────────────────────────────────────
info "Checking collaborative-zksnark submodule..."
if [ ! -f "collaborative-zksnark-main/algebra/ff/Cargo.toml" ]; then
  if [ ! -d ".git" ]; then
    fail "No .git directory found. You must clone the repo — do NOT download as ZIP.

  Run:
    git clone --recurse-submodules <repo-url>
    cd tls-cosnark
    ./quicktest.sh

  GitHub ZIP downloads do not include the collaborative-zksnark submodule."
  fi
  info "Submodule missing — running: git submodule update --init --recursive"
  git submodule update --init --recursive \
    || fail "Submodule init failed. Try: git submodule update --init --recursive"
fi
ok "Submodule present"

# ── 3. Build co-snark-prover (ark 0.2 / BLS12-377) ───────────────────────────
PROVER_BIN="crates/co-snark-prover/target/release/co-snark-prover"

if [ "$SKIP_BUILD" = "1" ] && [ -f "$PROVER_BIN" ]; then
  ok "co-snark-prover binary found (--skip-build)"
else
  info "Building co-snark-prover (ark 0.2 / BLS12-377) — may take 2-5 min..."
  (cd crates/co-snark-prover && cargo build --release) \
    || fail "co-snark-prover build failed. Check output above."
  ok "co-snark-prover built"
fi

# ── 4. Build main workspace (ark 0.4 / BN254) ─────────────────────────────────
if [ "$SKIP_BUILD" = "1" ]; then
  ok "Main workspace build skipped (--skip-build)"
else
  info "Building main workspace (ark 0.4 / BN254)..."
  cargo build --release \
    || fail "Main workspace build failed. Check output above."
  ok "Main workspace built"
fi

# ── 5. Unit tests ─────────────────────────────────────────────────────────────
info "Running unit tests..."
cargo test --release --quiet \
  || fail "Unit tests failed. Run 'cargo test --release' for details."
ok "Unit tests passed"

# ── 6. Benchmark: Mode 1 (fast, ~30s) ────────────────────────────────────────
echo ""
echo "─── Benchmark: Mode 1 (TlsKeyCircuit, 769 R1CS) ───────────────────────"
info "Expected: Attest ~200-300ms, total <1s per config"
echo ""

BINARY="$(pwd)/$PROVER_BIN"
cargo run --package tls-attestation-bench --bin bench_full_pipeline --release \
  -- --binary "$BINARY" \
  || fail "Mode 1 benchmark failed. Run without 2>/dev/null to see stderr."

ok "Mode 1 benchmark complete"

# ── 7. Isolated Mode 2 prove timing (ark 0.4 / BN254, ~30s) ──────────────────
echo ""
echo "─── Isolated Mode 2 prove: bench_dctls (ark 0.4 / BN254) ──────────────"
info "Expected: CRS setup ~60s (one-time), prove ~23s — matches paper [19] numbers"
echo ""

COSNARK_FULL_CIRCUIT=1 \
cargo run --package tls-attestation-bench --bin bench_dctls --release \
  || fail "bench_dctls failed. Run without 2>/dev/null to see stderr."

ok "bench_dctls complete"

# ── 8. Benchmark: Mode 2 full pipeline (optional, ~15-20min) ──────────────────
if [ "$RUN_MODE2" = "1" ]; then
  echo ""
  echo "─── Benchmark: Mode 2 full pipeline (TlsPrfCircuit, 1.9M R1CS) ────────"
  info "CRS setup ~3min (one-time). Prove ~60s per config. 9 configs total."
  echo ""

  COSNARK_FULL_CIRCUIT=1 \
  cargo run --package tls-attestation-bench --bin bench_full_pipeline --release \
    -- --binary "$BINARY" \
    || fail "Mode 2 benchmark failed."

  ok "Mode 2 benchmark complete"
else
  echo ""
  info "Mode 2 full pipeline skipped (~15-20min). Enable with: ./quicktest.sh --mode2"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  All checks passed.                                              ║"
echo "║                                                                  ║"
echo "║  Useful flags:                                                   ║"
echo "║    --mode2        Full Mode 2 pipeline  (~15-20 min)            ║"
echo "║    --skip-build   Skip rebuild, run tests only                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""