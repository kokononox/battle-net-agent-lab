#!/usr/bin/env bash
set -euo pipefail
: "${GHIDRA_HOME:?Set GHIDRA_HOME}" "${INPUT_DIR:?Set INPUT_DIR}" "${JAVA_HOME:?Set JAVA_HOME to full JDK}"
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
WORK="${WORK_DIR:-$HERE}"
mkdir -p "$WORK/projects" "$WORK/output" "$WORK/logs"
export PATH="$JAVA_HOME/bin:$PATH" GHIDRA_HEADLESS_MAXMEM=1800M
H="$GHIDRA_HOME/support/analyzeHeadless"
# No global auto-analysis, no external DLL import, no native input execution.
"$H" "$WORK/projects" LoaderTargeted -import "$INPUT_DIR/wow_loader.dll" -noanalysis -scriptPath "$HERE/scripts" -postScript TargetedReview.java "$WORK/output" -max-cpu 2 > "$WORK/logs/loader-console.log" 2>&1
"$H" "$WORK/projects" ExeTargeted -import "$INPUT_DIR/Wow.exe" -noanalysis -scriptPath "$HERE/scripts" -postScript TargetedReview.java "$WORK/output" -max-cpu 2 > "$WORK/logs/exe-console.log" 2>&1

"$H" "$WORK/projects" LoaderVerifiedCFG -import "$INPUT_DIR/wow_loader.dll" -noanalysis -scriptPath "$HERE/scripts" -postScript VerifiedExportReview.java "$WORK/output" "$HERE/scripts" -max-cpu 2 > "$WORK/logs/export-verified-console.log" 2>&1
# Use a fresh WORK_DIR: these commands intentionally do not overwrite existing projects.
