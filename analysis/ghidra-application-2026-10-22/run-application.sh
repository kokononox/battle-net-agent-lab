#!/usr/bin/env bash
set -euo pipefail
: "${GHIDRA_HOME:?}" "${JAVA_HOME:?}" "${INPUT_DIR:?}"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
WORK="${WORK_DIR:-$HERE}"
mkdir -p "$WORK/projects" "$WORK/output" "$WORK/logs"
export PATH="$JAVA_HOME/bin:$PATH" GHIDRA_HEADLESS_MAXMEM=1800M
python3 "$HERE/normalize_application.py" --input-dir "$INPUT_DIR" --output-dir "$HERE" > "$WORK/logs/cfg-summary.json"
"$GHIDRA_HOME/support/analyzeHeadless" "$WORK/projects" ApplicationVerifiedCFG -import "$INPUT_DIR/wow_loader.dll" -noanalysis -scriptPath "$HERE/scripts" -postScript VerifiedApplicationReview.java "$HERE/output" "$HERE/scripts" -max-cpu 2 > "$WORK/logs/application-console.log" 2>&1
python3 "$HERE/verify_application.py" --input-dir "$INPUT_DIR" --output-dir "$HERE"
# Use a fresh project directory; existing project is not overwritten.
