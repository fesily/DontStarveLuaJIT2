---
name: windows-pdb-symbols-without-image
description: "Resolve Windows PDB function symbols with no image on disk (DbgHelp fails); llvm-pdbutil route, hex/decimal traps, exact-start matching, cmd quoting."
---

# Windows PDB symbols without the image

Use when a tool needs C function names from a `.pdb` but the matching `.exe`/`.dll` is
not available (analysis on another machine), or when `SymFromAddr` keeps naming
internal functions after the nearest export.

## Decision table (verified on Win10/11 x64, DbgHelp 10.0.26100-era)

| Route | Needs image | Verdict |
|---|---|---|
| `SymLoadModuleExW(h, NULL, ImageName, NULL, base, size, NULL, 0)` | yes | works; PDB found next to image or in `SymInitializeW` search path, matched by GUID/age |
| `SymLoadModuleExW(h, NULL, NULL, pdb_path, base, size, NULL, SLMFLAG_VIRTUAL)` | no | **returns base, loads 0 symbols**; `SYMOPT_LOAD_ANYTHING`, no `DEFERRED_LOADS`, search path: all still 0 |
| DIA (`msdia140.dll`, `IDiaDataSource::loadDataFromPdb`) | no | works, but COM server registration + FFI vtable calls; `dia2.h` in newer VS puts `get_lastError` first, so index-based FFI is version-fragile |
| `llvm-pdbutil` (LLVM native reader) | no | **preferred**: no COM, cross-platform, exact |

## llvm-pdbutil recipe

```text
llvm-pdbutil dump -section-headers <pdb>   # section name, virtual size, virtual address
llvm-pdbutil dump -symbols <pdb>           # per module: S_GPROC32 / S_LPROC32 records
```

Symbol record layout (two lines):

```text
 148 | S_LPROC32 [size = 52] `CALL_MUNMAP`
       parent = 0, end = 584, addr = 0001:18256, code size = 171
```

Rules:

- **Section headers are hex; the record `addr` (section index and offset) is decimal.**
  Mixing them produces plausible-but-wrong RVAs (`0x19256` instead of `0x5750`).
  `RVA = section_virtual_address + tonumber(offset, 10)`.
- `code size` is decimal; function symbols carry exact extents, statics included
  (`S_LPROC32` = static, `S_GPROC32` = global). No `S_*_ID` variants are printed by
  current llvm-pdbutil.
- `-publics` is cheap but externs-only; `-symbols` is complete (≈7 MB text and
  ≈1.4 s for a 580 KB LuaJIT DLL). `-section-contribs` gives address+size but no names.
- Build the table once per module; index by function **start** and match a frame by
  the start of the function that contains it, never by floor lookup (symbol tables
  have no sizes for publics; nearest-symbol naming is the bug being fixed).

## Invoking a tool whose path has spaces from LuaJIT `io.popen`

`io.popen('"C:\\Program Files\\...\\tool.exe" args')` fails with
`'C:\Program' is not recognized`. cmd.exe needs a doubled outer pair:

```lua
local cmd = string.format('""%s" %s"', tool, args)   -- then append " 2>&1"
```

Keep redirects outside the closing quotes.

## Ground truth for validation

Do not validate the PDB reader against itself. Parse the image's PE export directory
(optional header data dir #0 → `AddressOfNames`/`AddressOfNameOrdinals`/
`AddressOfFunctions`) and check that exported names resolve to the same RVAs from the
PDB alone. `/OPT:ICF` can make an export point at a folded twin, so a mismatch on one
name is not proof of a bad reader — check several (8 exported LuaJIT functions matched
exactly after the decimal fix).

## Integration notes (LuaJIT sysprof tools, `tools/utils/symresolver.lua`)

- Sources, first hit wins: `pdb` (DbgHelp, image present) → `pdb file` (llvm-pdbutil,
  image missing) → `map` → `embedded`.
- Accept a DbgHelp name only when `Address <= entry` and `addr < Address + Size`
  (`entry` = start of the containing function from the profile's `func-off`);
  `SYMBOL_INFO.Address` is a VA and `Size` is set for function and often public symbols.
- Report `SYMBOL_INFO.Address` (not the image base) as the displayed address.
- Cache negatives per (addr), but never pre-resolve without `entry`: a cached miss
  computed without the function start poisons the real pass.
- Match `--pdb=file` to a module by file stem (`lua51.pdb` → `lua51.dll`); load address
  and image size come from the profile's module table / PE header.
