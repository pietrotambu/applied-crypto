#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python3.12}"

TRIALS="${TRIALS:-3}"
MESSAGE_KB="${MESSAGE_KB:-1}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Python not found at $PYTHON_BIN"
  echo "Set PYTHON_BIN or run: make venv && make install"
  exit 1
fi

if ! [[ "$TRIALS" =~ ^[0-9]+$ ]] || [[ "$TRIALS" -lt 1 ]]; then
  echo "TRIALS must be a positive integer."
  exit 1
fi

if ! command -v tc >/dev/null 2>&1; then
  echo "tc was not found. Install iproute2."
  exit 1
fi

if [[ "${EUID}" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "This script needs root for tc netem."
  echo "Run with sudo, or enable passwordless sudo for tc."
  exit 1
fi

as_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

cleanup() {
  as_root tc qdisc del dev lo root 2>/dev/null || true
}
trap cleanup EXIT

cd "$ROOT_DIR"

profiles=(
  "0.02ms 0.005ms"
  "0.05ms 0.01ms"
  "0.10ms 0.02ms"
)

run_trials() {
  local label="$1"
  local successes=0
  local output
  local rate

  for trial in $(seq 1 "$TRIALS"); do
    echo "[$label] trial $trial/$TRIALS"
    output="$("$PYTHON_BIN" -m padding_oracle.cli timing --message-kb "$MESSAGE_KB")"
    if grep -q "success: YES" <<<"$output"; then
      successes=$((successes + 1))
    fi
  done

  rate="$(awk "BEGIN {printf \"%.5f\", $successes / $TRIALS}")"
  echo "[$label] success=$successes/$TRIALS rate=$rate"
}

echo "[task4] baseline (no netem)"
cleanup
run_trials "task4 netem=off"

for profile in "${profiles[@]}"; do
  read -r delay jitter <<<"$profile"
  echo "[task4] netem delay=$delay jitter=$jitter"
  as_root tc qdisc replace dev lo root netem delay "$delay" "$jitter" distribution normal
  run_trials "task4 delay=$delay jitter=$jitter"
done
