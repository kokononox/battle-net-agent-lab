#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
: "${PWSH:=pwsh}"
"$PWSH" -NoProfile -File "$ROOT/tests/Test-SessionJournal.ps1" -Root "$ROOT"
