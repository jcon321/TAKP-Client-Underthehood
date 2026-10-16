#!/usr/bin/env bash
# Re-apply the Zeal/MQ2 struct layouts + re-export decompiled C on the
# already-analyzed binary in ghidra-projects/takp (no re-import/re-analysis).
# Use after editing headers in ../Zeal or ../MyAKMQ2, or eqstructs_to_json.py.
#   tools/refine.sh eqgame.exe
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
source "$HERE/env.sh"
source "$HERE/sources.sh"
NAME="$1"
OUT="$REPO/decomp/$NAME"
mkdir -p "$OUT"
python3 -I "$HERE/scripts/eqstructs_to_json.py" "$HERE/eqstructs.json" "${STRUCT_HEADERS[@]}"

analyzeHeadless "$REPO/ghidra-projects" takp \
	-process "$NAME" -noanalysis \
	-scriptPath "$HERE/scripts" \
	-postScript ApplyEqStructs.java "$HERE/eqstructs.json" "$MQ2_GLOBALS" \
	-postScript ExportDecompiled.java "$OUT" \
	-log "$REPO/ghidra-projects/$NAME.refine.log" \
	-scriptlog "$REPO/ghidra-projects/$NAME.refine.script.log"
