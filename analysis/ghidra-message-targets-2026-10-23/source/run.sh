#!/usr/bin/env bash
set -euo pipefail
: "${GHIDRA_HOME:?}" "${JAVA_HOME:?}" "${INPUT_DIR:?}" "${WORK_DIR:?}"
HERE="$(cd -- "$(dirname -- "$0")/.." && pwd)"
test ! -e "$WORK_DIR/projects" || { echo 'Choose a fresh WORK_DIR'; exit 1; }
mkdir -p "$WORK_DIR/projects" "$WORK_DIR/output"
export PATH="$JAVA_HOME/bin:$PATH" GHIDRA_HEADLESS_MAXMEM=1800M
# No global autoanalysis, imported external libraries, overwrite, or native input execution.
timeout 240 "$GHIDRA_HOME/support/analyzeHeadless" "$WORK_DIR/projects" MessageTargets -import "$INPUT_DIR/Wow.exe" -noanalysis -scriptPath "$HERE/source" -postScript MessageTargets.java "$WORK_DIR/output" "$HERE/reference/targets.tsv" -max-cpu 2 > "$WORK_DIR/headless.log" 2>&1
