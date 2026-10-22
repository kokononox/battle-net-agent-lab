#!/usr/bin/env bash
set -euo pipefail
: "${INPUT_FILE:?Set to the matching wow_loader.dll}"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
OUT="${OUTPUT_DIR:-$HERE}"
mkdir -p "$OUT"
python3 "$HERE/trace_callee.py" --input "$INPUT_FILE" --out "$OUT" > "$OUT/summary.json"
python3 "$HERE/scan_slot_references.py" --input "$INPUT_FILE" --out "$OUT" > "$OUT/slot-scan-summary.txt"
python3 "$HERE/extract_crt_contexts.py" --input "$INPUT_FILE" --out "$OUT"
python3 "$HERE/verify_callee.py" --input "$INPUT_FILE" --out "$OUT"
