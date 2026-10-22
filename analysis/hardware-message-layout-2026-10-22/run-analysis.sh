#!/usr/bin/env bash
set -euo pipefail
: "${INPUT_FILE:?Set to matching Wow.exe}"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
OUT="${OUTPUT_DIR:-$HERE}"
mkdir -p "$OUT"
python3 "$HERE/map_message_layout.py" --input "$INPUT_FILE" --out "$OUT"
python3 "$HERE/scan_message_references.py" --input "$INPUT_FILE" --out "$OUT" > "$OUT/reference-scan-summary.txt"
python3 "$HERE/verify_message_layout.py" --input "$INPUT_FILE" --out "$OUT"
python3 "$HERE/test_layout_report.py" --input "$INPUT_FILE" --out "$OUT"
