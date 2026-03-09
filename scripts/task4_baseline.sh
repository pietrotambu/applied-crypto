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

cd "$ROOT_DIR"

successes=0
for trial in $(seq 1 "$TRIALS"); do
  echo "[task4 baseline] trial $trial/$TRIALS"
  output="$("$PYTHON_BIN" -m padding_oracle.cli timing --message-kb "$MESSAGE_KB")"
  if grep -q "success: YES" <<<"$output"; then
    successes=$((successes + 1))
  fi
done

rate="$(awk -v s="$successes" -v t="$TRIALS" 'BEGIN { printf "%.5f", s / t }')"
echo "[task4 baseline] success=$successes/$TRIALS rate=$rate"
