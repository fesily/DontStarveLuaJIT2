---
name: dst-android-type-library-version-retarget
description: "Retarget DST Android arm64 C++ type library (types_android.hpp) to a new libDontStarve version using an old/new A/B, ctor store sets, RTTI/vtables and clang layout validation"
---

# Retarget DST arm64 type library to a new libDontStarve build

Use when `3rd/dst/game_decompiler/types_android.hpp` (or `.h`) must be updated for a newer DST Android build.

## 0. Get both binaries
- New: the APK split `lib/arm64-v8a/libDontStarve_2.2.1.so` (and Ghidra program of the same name).
- Old: `C:/Users/fesil/Downloads/DontStarveTogether_1.1.28.apk.7z` is a **zip**; extract `split_config.arm64_v8a.apk`, then `lib/arm64-v8a/libDontStarve.so`.
- The bash tool cannot exec paths containing spaces: run `llvm-objdump`/`llvm-nm`/`7z`/`clang++` through `python -c "subprocess.run([...])"`.

## 1. Bulk fact extraction (local, ~10 s per binary)
`C:/tmp/dst221/extract.py <so> <outdir>` → `facts.json`:
- `.dynsym` (demangle with `llvm-cxxfilt`), RTTI (`_ZTI` name, `__si`/`__vmi` base edges), vtable slot names from `_ZTV` + `.data.rel.ro` reloc scan,
- per-function `this`(x0)-relative **store** set, widths, memset size, loads.
- Relocs: `R_AARCH64_ABS64` carries a symbol index → resolve via dynsym, not the addend.
- Register-tracking gotchas: a constant loaded into `w0/x0` is a call argument, never a `this` offset; `stp w?,w?` = two 4-byte slots; only **stores** bound the object size (loads drift); drop negative/unaligned offsets.

## 2. Per-struct verdicts
`diffreport.py` + `classify.py`: ctor-store-set equality + vtable-slot equality + symbol-set equality → `identical` / `symbols_only` / `vtable_changed` / `stores_changed`; `fieldmap.py` gives hpp field offsets; unresolved structs fall back to RTTI typeinfo name match (class dict keys are mangled, e.g. `N6RakNet16PluginInterface2E` — always alias key↔typeinfo).

## 3. Audit the flagged structs with agents
Slice the flagged structs (≈7 per agent; 14 caused length-stop failures). Brief must state: Ghidra addr = **ELF VA + 0x100000**, program `libDontStarve_2.2.1.so`, ctor-first method, no `switch_program`.
`scout` agents cannot write `C:/…`; have them persist to `local://sliceN.json` (copyable with `cp local://sliceN.json …`) or fall back to inline JSON.

## 4. Generate, then validate — never trust a patch
`regen.py` rewrites from a **pristine** baseline (copy of `git show HEAD:…`), never the already-generated file:
- refresh every `_Zsym @0x…` from new facts, re-tag unknown ones as `1.1.28:0x…`;
- regenerate member lists and vtable-ordered virtuals **only** for structs that already modelled a vptr (otherwise absolute offsets shift);
- agent field lists are complete flat layouts from offset 0 → drop the `: public Base` clause; `<vptr>` lines are replaced by the rendered virtual dtor;
- `build.py` loops: generate → `clang++ -target aarch64-linux-android24 -Xclang -fdump-record-layouts-complete` → accept a patch only if `sizeof == audited size`; otherwise reject it and emit the struct with an in-file note `field list NOT re-derived`.

## 5. Acceptance
- header compiles with `clang++ -std=c++17 -fsyntax-only -target aarch64-linux-android24`;
- every `_Z… @0x…` reference matches new-build dynsym/vtable addresses (script check == 0 mismatches);
- `sizeof(struct) >= ctor extent` for every struct with ctor evidence (allow-list the few decompiler-proven measurement artifacts);
- spot-decompile 2-3 regenerated addresses with Ghidra MCP to confirm the mapping.
