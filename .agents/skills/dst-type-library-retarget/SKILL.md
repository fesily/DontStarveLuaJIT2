---
name: dst-type-library-retarget
description: "Retarget DST arm64 C++ type library (types_android.hpp) to a new libDontStarve build via local ELF fact extraction + Ghidra MCP audit agents; covers ctor-store-set diffing, patch validation, and the parsing gotchas."
---

# Retarget `types_android.hpp` to a new libDontStarve build

Goal: regenerate the arm64 C++ type library (inheritance + virtuals + member signatures + field offsets) from a new `.so`, keeping human semantic comments and proving each delta.

## 1. Get both binaries
- New: `C:/Users/fesil/Downloads/lib/arm64-v8a/libDontStarve_2.2.1.so`.
- Old: extract from the APK backup, e.g.
  `python -c "subprocess.run([r'C:\Program Files\7-Zip\7z.exe','e', r'...apk.7z','split_config.arm64_v8a.apk','-oC:/tmp/dst221','-y'])"` then `7z e split_config.arm64_v8a.apk lib/arm64-v8a/libDontStarve.so -oC:/tmp/dst221/old`.
- Keep a pristine copy of the current hpp (`git checkout -- <hpp>` then copy to `types_android.orig.hpp`). **Never regenerate from a generated file** — provenance lines and merged patches cascade into garbage.

## 2. Extract facts locally (fast, no MCP)
`C:/tmp/dst221/extract.py <so> <outdir>` → `facts.json`:
- `.dynsym` (name/addr/size/type), demangled via `llvm-cxxfilt`;
- RTTI: `_ZTV*` symbols + scan of `.data.rel.ro` relocations for non-exported vtables → bases (`__si`/`__vmi`), slot order, typeinfo names (demangle nested `N…E` with `_Z`+name);
- per-function store/load sets through `this` from `llvm-objdump -d` filtered lines (register tracking, `stp` splitting, `bl _Znwm` size capture).

Gotchas that cost hours:
- Symbolic relocations (`R_AARCH64_ABS64`) resolve via `dynsym[r_info_sym]`, not `r_addend`.
- Scope parsing must accept `_ZNK` (const) and `_ZNV`: start the length-prefixed scan at index 4 when `name[3]=='K'` — otherwise every const method/virtual silently disappears.
- Ctor/dtor leaves are `C1/C2/C3`, `D0/D1/D2` — they follow the class name with **no length prefix**; parse `rest[:2] in SPECIAL`.
- Never treat a constant loaded into `x0` as a `this` offset (only `0` means this); use store-only extents for size, keep load extents as separate evidence.

## 3. Diff old vs new
`diffreport.py` (struct ↔ class-scope mapping by mangled-name overlap + RTTI typeinfo; class keys are mangled for scanned classes, so always compare against both key and typeinfo) then `classify.py`.
Verdicts: `identical` (ctor store set + vtable + symbol set equal → layout unchanged), `symbols_only`, `vtable_changed`, `stores_changed`, `unresolved`.
`fieldmap.py` computes hpp-implied field offsets (arm64 ABI incl. vptr/bases) and flags accesses not covered by any field.

## 4. Audit the flagged structs with agents
- Build slices of ≤7 structs each (`mkslices.py`), brief file `C:/tmp/dst221/AGENT_BRIEF.md`: Ghidra program `libDontStarve_2.2.1.so`, **ghidra_addr = elf_addr + 0x100000**, constructor-first method, output JSON schema `{struct, verdict, size_2_2_1, fields|null, notes, evidence[]}`.
- 14 structs per agent → repeated `length`-stop failures; 6–7 works.
- `scout` agents cannot write files: have them persist via `local://sliceN.json` or a Ghidra `run_script_inline` + `java.nio.file.Files.write`, then `cp local://x.json slices/`.
- Agent `fields` are sometimes a **complete flat layout from offset 0** (includes `<vptr>` and base fields) and sometimes only the changed lines. Never trust either: validate.

## 5. Regenerate with validation gates (`build.py`)
- `regen.py` rewrites member/virtual sections from the 2.2.1 vtables (own-scope slots only), refreshes every `_Zsym @0x…` to 2.2.1 (unresolved ones get re-tagged `1.1.28:0x…`), re-emits virtuals only where the original modelled a vptr (else absolute field offsets shift), and appends new classes.
- Patches: flat patches drop the base clause and use the list verbatim; measure each patch with clang (`Probe_*` struct + `-fdump-record-layouts-complete`) and **reject** any patch whose measured sizeof ≠ claimed (partial list) — annotate the struct instead of corrupting it (`audited: … field list NOT re-derived`). Two passes: generate → measure → reject → regenerate.
- Guard: if a regenerated vtable yields fewer named own slots than the original virtual list (pure-virtual/shared vtables), keep the original virtual lines.

## 6. Verify before installing
- `clang++ -std=c++17 -fsyntax-only -target aarch64-linux-android24` on the header (and from the repo path after install).
- Dump layouts with `-fdump-record-layouts-complete`; assert every struct with ctor evidence has `sizeof >= extent` (exclude decompiler-proven artifacts such as ctor store-width mismatches).
- Audit all `_Z… @0x…` refs against `facts.json` → 0 mismatches.
- Spot-decompile 2–3 addresses in Ghidra to confirm the mapping.

## 7. Docs
Regenerate `CORE_TYPES_2.2.1.md` (sizeof/bases/virtuals/methods/verdict) and `CORE_FUNCS_2.2.1.md` (exported function counts by class scope) from the same facts; exclude `bt*`/`RakNet*`/`SDL*`/`std*`/`boost*`.
