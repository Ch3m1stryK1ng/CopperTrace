#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 FIRMWARE.elf OUT.json [function1,function2,...]" >&2
  exit 2
fi

ELF=$(realpath "$1")
OUT=$(realpath -m "$2")
FUNCTIONS=${3:-}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GHIDRA=${GHIDRA_INSTALL_DIR:-}
JAVA_HOME=${JAVA_HOME:-}

if [[ -z "$GHIDRA" ]]; then
  echo "GHIDRA_INSTALL_DIR must point to a Ghidra installation" >&2
  exit 2
fi
export JAVA_HOME
export GHIDRA_INSTALL_DIR="$GHIDRA"

KEY=$(printf '%s' "$ELF" | sha256sum | cut -c1-16)
PROJECT_ROOT=${CT_MINI_GHIDRA_PROJECT_ROOT:-/tmp/coppertrace-mini-ghidra-projects}
PYTHON=${CT_MINI_PYGHIDRA_PYTHON:-python3}
PROJECT="$PROJECT_ROOT/ct_source_${KEY}"
mkdir -p "$PROJECT_ROOT" "$(dirname "$OUT")"

CMD=(
  "$PYTHON" "$ROOT/scripts/ghidra_export_source_facts.py" "$ELF"
  --out "$OUT"
  --project-dir "$PROJECT"
  --project-name "ct_source_${KEY}"
  --fresh
)
if [[ -n "$FUNCTIONS" ]]; then
  IFS=',' read -ra NAMES <<< "$FUNCTIONS"
  for name in "${NAMES[@]}"; do
    CMD+=(--function "$name")
  done
fi
"${CMD[@]}"

test -s "$OUT"
