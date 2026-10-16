#!/usr/bin/env bash
# Headless: import a TAKP binary into a Ghidra project, apply the TAKP function
# list BEFORE auto analysis, analyze, apply class/global refinements
# (ApplyTakpTypes.java), Zeal/MQ2 struct layouts (ApplyEqStructs.java), then
# export per-function decompiled C.
#   tools/analyze.sh eqgame.exe [function_list.txt]
# Output: ghidra-projects/takp.gpr (open in Ghidra GUI) and decomp/<binary>/
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
source "$HERE/env.sh"

BIN="$(realpath "$1")"
NAME="$(basename "$BIN")"
LIST="$(realpath "${2:-$REPO/${NAME}_takp_function_list.txt}")"
OUT="$REPO/decomp/$NAME"
source "$HERE/sources.sh"
mkdir -p "$REPO/ghidra-projects" "$OUT"
python3 -I "$HERE/scripts/eqstructs_to_json.py" "$HERE/eqstructs.json" "${STRUCT_HEADERS[@]}"

analyzeHeadless "$REPO/ghidra-projects" takp \
	-import "$BIN" -overwrite \
	-scriptPath "$HERE/scripts" \
	-preScript ImportTakpFunctionList.java "$LIST" \
	-preScript FixMsvcHelpers.java \
	-postScript ApplyTakpTypes.java "$MQ2_H" "$ZEAL_H" \
	-postScript ApplyEqStructs.java "$HERE/eqstructs.json" "$MQ2_GLOBALS" \
	-postScript ExportDecompiled.java "$OUT" \
	-log "$REPO/ghidra-projects/$NAME.headless.log" \
	-scriptlog "$REPO/ghidra-projects/$NAME.script.log"
