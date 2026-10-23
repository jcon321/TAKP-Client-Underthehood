# Headless Ghidra pipeline for the TAKP client

Scripts that turn `eqgame.exe` + the TAKP function list into a named, typed
Ghidra project and a greppable per-function C dump. The toolchain is portable
(no sudo); the downloaded installs, `ghidra-projects/` and `decomp/` are
git-ignored and fully regenerable.

## Setup (Linux x64)

```bash
cd tools
# Ghidra 12.1.4 (sha256 ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db)
curl -LO https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
unzip -q ghidra_12.1.4_PUBLIC_20260921.zip && ln -sfn ghidra_12.1.4_PUBLIC ghidra
# Temurin JDK 21 (Ghidra 12 requires 21+)
curl -L "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse" | tar xz
ln -sfn jdk-21* jdk
# Node 24 + REA (only needed for the REA MCP server)
curl -L https://nodejs.org/dist/v24.22.0/node-v24.22.0-linux-x64.tar.xz | tar xJ && ln -sfn node-v24.22.0-linux-x64 node
source env.sh && npm install --global rea-agents@6.5.0
```

Reference headers are read from sibling clones (paths in `sources.sh`):
`../Zeal` (Zeal client mod) and `../MyAKMQ2` (MQ2 for the EQMac client).
Copy `eqgame.exe` into the repo root before running `analyze.sh`.

| Path | What |
|------|------|
| `ghidra` -> `ghidra_12.1.4_PUBLIC` | Ghidra 12.1.4 (sha256 verified) |
| `jdk` -> `jdk-21.0.12.1+1` | Temurin JDK 21 (Ghidra 12 requires 21+) |
| `node` -> `node-v24.22.0-linux-x64` | Node 24 LTS (for REA) |
| `npm-global/` | `rea-agents` 6.5.0 install (`rea` CLI / MCP server) |
| `scripts/ImportTakpFunctionList.java` | Java port of `ghidra_memory_address_function_name_import.py` (Ghidra 12 no longer ships Jython by default); headless-friendly |
| `scripts/FixMsvcHelpers.java` | Pre-analysis: finds MSVC helpers by bytes, names them and attaches Ghidra call-fixups. The TAKP list mislabels `__EH_prolog` (0x5c6394) as `CXWnd_OnProcessFrame` and `__alloca_probe` (0x5c6c20) as `malloc`; uncorrected, ~2400 functions lose `this`/EBP |
| `scripts/ApplyTakpTypes.java` | Post-analysis: global labels from `../MyAKMQ2/MQ2Main/eqgame.h` (pinst*/__*) and `../Zeal/Zeal/game_addresses.h` (`Zeal_*`); moves `Class_Method` functions into C++ classes as `__thiscall`; reverts ones whose `this` is unused; auto-fills class structs from `this->` accesses (embedded-struct guesses dropped) |
| `scripts/eqstructs_to_json.py` | Extracts `/*0xOFF*/`-annotated struct layouts from Zeal (`game_structures.h`, `game_ui.h`) and MyAKMQ2 (`EQData.h`, `EQUIStructs.h`) into `eqstructs.json` (header list in `sources.sh`) |
| `scripts/ApplyEqStructs.java` | Builds those layouts under `/TAKP`, merges named fields into matching class structs only when the class's observed `this->` accesses agree (match report in the script log; `TAKP_STRUCT_DEBUG=1` prints conflicts), and types `pinst*` globals from `MQ2Globals.cpp` |
| `scripts/ExportDecompiled.java` | Decompiles every function to `decomp/<bin>/funcs/<addr>_<name>.c` + `index.tsv` (with TAKP signature, callers, callees) |
| `analyze.sh` | Import -> TAKP names + MSVC fixups (pre-analysis) -> auto analysis -> ApplyTakpTypes -> export (~30 min for eqgame.exe) |
| `refine.sh` | Re-extract headers + ApplyEqStructs + export on the existing project (~10 min); use after header edits |
| `sources.sh` | Paths to the sibling Zeal / MyAKMQ2 reference headers |
| `rea-mcp.sh` | MCP entry point: sources env.sh then `rea mcp` (node isn't on the system PATH) |
| `env.sh` | `source` to put java/ghidra/node/rea on PATH |

### Misleading names in the TAKP lists

Besides the two MSVC helpers above (which `FixMsvcHelpers.java` corrects), these
names from the TAKP function lists don't describe what the code does. They're
left as they are in the project and dumps:

| Address | TAKP name | What it is |
|---------|-----------|------------|
| eqgame 0x004d7a21 | `initializeHotkeyLabels` | Fills the animation table: animation number -> track code (1..11 `C01`..`C11`, 12..16 `D01`..`D05`, 17..25 `L01`..`L09`, 32..38 `P01`..`P07`...), the ids `CDisplay::PlayAnimationTrack` and the server's OP_Animation use |
| eqgame 0x0049ec7e | `CEverQuest_loadOptions` | The `CDisplay` constructor (called from `CEverQuest::CEverQuest`); Ghidra types its `this` as `CEverQuest`. Among other defaults it stores 0.18 at +0x3c, the minimum ambient `CDisplay::SetAmbientLight` clamps each channel to |
| eqgfx 0x10050b50 | `processPhysicsEffects` | Light selection, nothing physical: from the region's light list, the lights whose flags share a bit with the mask (0x30000000 actors and uncolored meshes, 0x20000000 meshes with baked colors), ranked by 0.05 r^2 / (d^2 + 1), the brightest N kept (3 for actors, 64 for zone meshes) |
| eqgfx 0x1004b750, 0x1004b9c0, 0x1004bb40 | `processPhysicsEffects` | Prepare that selected list for one mesh: each light's color x 0.05 r^2 (/ scale^2) and its position (or a directional light's direction) in the mesh's space |
| eqgfx 0x1004d750 | `applyPhysicsAndLightingEffects` | Adds the selected point and directional lights to a 0x36 mesh's vertex light (point: color x cos / d^2; directional: color x cos, times the actor's floor exposure) |
| eqgame 0x005726b0 | `CXWnd_DrawMinimizeButton` | Draws the **close** box: hit test piece 5, the WindowDrawTemplate's CloseBox (+0x190, Normal at +0x194); `DrawWindowAndContents` calls it for style bit 0x8 |
| eqgame 0x005727b0 | `CXWnd_DrawTitleBar` | Draws the **minimize** box: piece 3, the MinimizeBox (+0x1bc, Normal at +0x1c0); called for style bit 0x20, and its failure traces `DrawMinimizeBox_Failed` |
| eqgame 0x005728b0 | `CXWnd_DrawCloseButton` | Draws the **tile** box: piece 4, the TileBox (+0x1e8, Normal at +0x1ec); called for style bit 0x10 |
| eqgame 0x00575060 | `isSpecialEntityActive` | The window's CloseBox template (draw template +0x190) when it has a titlebar and close box (style & 0xc), else 0 |
| eqgame 0x00575080 | `getEntityWeaponOffset` | The MinimizeBox template (+0x1bc) when style & 0x24 (titlebar, minimize box), else 0 |
| eqgame 0x005750a0 | `GetTargetPointerIfActive` | The TileBox template (+0x1e8) when style & 0x14 (titlebar, tile box), else 0 |
| eqgame 0x00571540 | (not in the list; not decompiled) | `CXWnd::GetHitTestRect(piece)`, vtable +0xd0 (`CXWnd` vtable 0x5eaa94). Starts from the rect inside the border (vtable +0xd4, 0x5714b0 `GetInnerRect`). Minimize box (piece 3) is 8 in from the left and 2 down. Close box (piece 5) ends 7 short of the right and is 1 down. Tile box (piece 4) sits just left of the close box. `HitTestUIElement` walks pieces 2..6, then 0x11..0x1c, 7..0xb and 0xc..0x10 by style |
| eqgame 0x00594b00 | `RenderEntityNameplate` | `CButtonWnd::Draw` (slot +0xc of the vtable 0x5eaf00 that 0x594930 `InitializeCustomWindow`, the button constructor, sets; its traces cite `ButtonWnd.cpp`): the state's template (Normal at +0x124), then the decal (+0x138) at its offset, then the text (grey when disabled, yellow when checked or hovered). `CItemDisplayWnd::SetItem` sets +0x124 to `A_DragItem` and clears +0x138, so an item icon fills the button in place of the XML's `RedIconBackground` |

## Usage

```bash
source tools/env.sh
tools/analyze.sh eqgame.exe                      # uses eqgame.exe_takp_function_list.txt
tools/analyze.sh eqmain.dll                      # needs the binary copied in first
ghidraRun                                        # GUI; open ghidra-projects/takp.gpr
```

Function files are named by qualified name (`00401bc3_CAAWnd__Init.c`); the
original TAKP name is in each file's `// TAKP:` header line. `types.h` holds
all data types. Class structs carry Zeal/MQ2 field names where a layout was
verified (83 classes, e.g. `EQ_Character` <- Zeal `GAMECHARINFO`, `EQPlayer` <-
`Entity`, window classes <- `BasicWnd`/`SidlWnd`); remaining fields keep
auto-filled `field193_0x13c` names (offsets real, names placeholders).

Re-running `analyze.sh` overwrites that binary in the project (`-overwrite`),
so GUI edits to it are lost; rename/retype in the GUI and re-export with
`ExportDecompiled.java` from the Script Manager instead (add `tools/scripts`
to the script directories).

## REA (MCP for Claude Code)

```bash
source tools/env.sh
rea setup --client claude_code --yes   # adds MCP entry to ~/.claude.json (backup: ~/.claude.json.rea.backup)
# setup registers npm-global/bin/rea directly, which fails (no node on PATH); point it at the wrapper:
claude mcp remove rea -s user && claude mcp add rea -s user -- "$PWD/tools/rea-mcp.sh"
rea doctor                             # ghidra/java should show healthy
```

Restart Claude Code afterwards. Undo with `rea uninstall`.
