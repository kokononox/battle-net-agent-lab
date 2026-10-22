#!/usr/bin/env bash
set -euo pipefail
: "${ARCHIVE_FILE:?Set to the supplied old ZIP}" "${BASELINE_DIR:?Set to earlier matching binaries}" "${OLD_INPUT_DIR:?Set to extraction directory}"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
OUT="${OUTPUT_DIR:-$HERE}"
mkdir -p "$OUT"
python3 "$HERE/inspect_archive.py" --archive "$ARCHIVE_FILE" --extract "$OLD_INPUT_DIR" --baseline "$BASELINE_DIR" --out "$OUT" > "$OUT/initial-summary.txt"
python3 "$HERE/compare_descriptors.py" --old "$OLD_INPUT_DIR/Wow.exe" --baseline "$BASELINE_DIR/Wow.exe" --out "$OUT" > "$OUT/descriptor-summary.txt"
python3 "$HERE/compare_registration.py" --old "$OLD_INPUT_DIR/Wow.exe" --baseline "$BASELINE_DIR/Wow.exe" --out "$OUT" > "$OUT/registration-summary.txt"
python3 "$HERE/verify_comparison.py" --archive "$ARCHIVE_FILE" --old "$OLD_INPUT_DIR" --baseline "$BASELINE_DIR" --out "$OUT" > "$OUT/qa-summary.txt"
