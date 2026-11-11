---
name: ghidra-mcp-symbol-table-export-markdown
description: "Export a Ghidra (MCP headless) binary's full symbol table to Markdown aggregated by type/class, with third-party libraries (lua/zlib/RakNet/bullet/SDL/OpenSSL...) bucketed separately."
---

# Ghidra MCP: symbol table → Markdown, aggregated by type

Use when asked to "导出二进制的符号表", "按类型聚合", "全局函数单独分类", "第三方库单独分类" for one or more binaries in a Ghidra headless project (Android .so, Mach-O, PE).

## 0. Resolve the program, not the filename
- `list_open_programs` first. Beware name collisions: `load_program` reports `success` even when the name matches an already-open program and nothing new is imported — confirm the program list actually grew.
- Ghidra `executable_path` often points at a file the user already deleted. Keep verified copies under `build/symexport/<versioned>.macho` and import those.
- Version identity: DST Mach-Os embed `PRODUCTION\0OSX_STEAM\0<rev>\0<build>` (e.g. `578406`/`865`, `181048`/`646`). Grep printable runs for `\b\d{6}\b` before guessing which file is which revision.

## 1. Import correctly
- Let `load_program` **auto-detect** the format (`language` omitted). Passing `language` explicitly on a 32-bit Mach-O produced a raw-blob import (image_base 0, 0 functions); auto-detect gave `x86:LE:32:default` with proper segments.
- `run_analysis` times out the MCP call (~30 s) but keeps running server-side. Poll `analysis_status(program)` until `analyzed:true`; **do not dump before that** — early dumps were 600–3,500 functions short.

## 2. Dump: the count trap
`getFunctionCount()` includes external functions; `getFunctions(true)` does **not**. Dump both:

```java
for (Function f: currentProgram.getFunctionManager().getFunctions(true)) { /* LOCAL rows */ }
for (Function f: currentProgram.getFunctionManager().getExternalFunctions()) { /* EXT rows, ns = dylib path */ }
```
Verify `local + ext == getFunctionCount()` in the script output — this is the acceptance check.

Script gotchas in `run_script_inline` (GHIDRA_MCP_ALLOW_SCRIPTS=1):
- Snippet is injected into a class body: declare locals (`HashMap<String,Integer> m=new HashMap<>()`), and `println` needs a String (`m.toString()`).
- Write TSV to a real disk path; return only counts, never 40k lines.

Row format: `FUNC <addr> <name> <namespace> <size> <EXT|LOC>` and `SYM <addr> <name> <ns> 0 <SymbolType> <EXT|LOC>` (skip auto names `LAB_/DAT_/caseD_/default/INIT_n/thunk_FUN_*`).

## 3. Aggregate offline (Python)
- Demangle in one batch: pipe unique `_Z`-names (strip ONE leading Mach-O `_` when the name starts `__Z`) through `C:\ProgramData\mingw64\mingw64\bin\c++filt.exe`; map back by original name.
- Classify by `name.lstrip('_')` + namespace prefixes, ordered specific→generic. Reliable buckets: Lua, zlib, minizip (`^zip`), RakNet, Bullet (`^bt[A-Z]`), SDL2 (incl. `Cocoa_/HIDAPI_/DARWIN_/DUMMYAUDIO_/COREAUDIO_/Blit/yuv/hashtable_`), HarfBuzz (incl. ns `OT`, `AAT`), OpenSSL (long prefix list + all-caps fallback `^[A-Z][A-Z0-9]{2,}_`, excluding `JNI_/DEV_/VORO/UPNP/TTV/FMOD`), Vorbis/theora (`floor0_/res0_/oc_/th_`), cJSON (`json_/jsonp_`), FreeType, curl, EOS, miniupnpc, FMOD, TTV, Steamworks, Voro++ (`VORO/vp_`), C++ std (`std/__gnu_cxx/boost/eastl`), libc/system names (exact set — never prefix-match `str_/f_/io_`, those are Lua internals), static init (`GLOBAL__sub_I`).
- Engine buckets: namespace empty/`Global` → global functions; non-empty → per-class; `+[`/`-[` → ObjC; `EXT` or ns `<EXTERNAL>` or `/usr/lib…`/`*.dylib` → external imports.
- vtable/typeinfo labels appear twice (Ghidra `vtable` + mach-o `__ZTV…`) — **dedupe by address**; demangle `_ZTV/_ZTI/_ZTS` to `vtable for X` / `typeinfo for X`.

## 4. Markdown shape
metadata table → 分类总览 (libs + top 40 classes + "其余 N 个类") → 第三方库/系统库 (one `### lib（N）` + fenced `addr  name` block each) → ObjC → **引擎全局函数** → 引擎类/命名空间 (sorted by class name) → 外部导入 (per dylib) → 数据符号 (vtable/typeinfo per class).
State in the header: addresses are per-build Ghidra image addresses, Mach-O names lost one leading underscore, Itanium names demangled, unnamed `FUN_*` counted not listed.

## 5. Verify
Spot-check one address per file with `get_function_by_address` and compare name/entry against the generated block. Report per-file totals and confirm they equal `getFunctionCount()`.
