#!/usr/bin/env bash
set -euo pipefail
# Requires Ghidra 12.2 and a supported JDK. Input PE files must already be rebuilt.
: "${GHIDRA_HOME:?Set GHIDRA_HOME}"
: "${INPUT_DIR:?Set INPUT_DIR to the directory containing the verified PE files}"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
WORK="${WORK_DIR:-$PWD/ghidra-pilot-work}"
mkdir -p "$WORK/projects" "$WORK/output"
H="$GHIDRA_HOME/support/analyzeHeadless"
"$H" "$WORK/projects" RetailProbe -import "$INPUT_DIR/libxell.dll" -scriptPath "$HERE/scripts" -postScript Probe.java "$WORK/output" -analysisTimeoutPerFile 120 -max-cpu 2
"$H" "$WORK/projects" RetailProbe -process libxell.dll -noanalysis -scriptPath "$HERE/scripts" -postScript ExportProbe.java "$WORK/output"
GHIDRA_HEADLESS_MAXMEM=2500M "$H" "$WORK/projects" WowProbe -import "$INPUT_DIR/Wow.exe" -scriptPath "$HERE/scripts" -postScript Probe.java "$WORK/output" -analysisTimeoutPerFile 180 -max-cpu 2
# Use an empty WORK_DIR for a fresh rerun; no overwrite is enabled.
