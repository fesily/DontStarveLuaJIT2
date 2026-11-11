---
name: luajit-sysprof-profile-symbolization
description: "LuaJIT/Tarantool sysprof profile parsing and Windows frame symbolization (module!func, --pdb/--map, ljs v7 sizes); use when frames print as raw addresses or PDB/PDB-less naming is wrong."
---

# LuaJIT sysprof: parse a profile and symbolize its frames

Tree: the tarantool/luajit fork with the Windows sysprof port (`src/lj_sysprof.c`,
`src/lj_symtab.c`, `tools/sysprof.lua`, `tools/utils/{symtab,symresolver,evread}.lua`).

## 1. Collect a profile

```lua
local sp = require("misc").sysprof
assert(sp.start{ mode = "C", path = "p.bin", interval = 1 })  -- C = callgraph stream, L = leaf, D = counters only (NO stream, path ignored)
-- workload with GC, pcall, FFI, a compiled loop
assert(sp.stop())
print(sp.report().samples)
```

`mode="D"` ignores `path` (upstream semantics: counters only) — a missing output
file with samples > 0 is not a bug.

## 2. Parse

```bash
export LUA_PATH="./?.lua;./tools/?.lua;./tools/?/init.lua;./src/?.lua;./src/?/init.lua;;"
<abs>/src/luajit.exe -ts [--pdb=<file>]... [--map=<file>] p.bin      # prints chain<TAB>count
```

Frames must read:

| frame | meaning |
|---|---|
| `module!function` | image export / COFF / map / PDB symbol |
| `module+offset` | inside an image, no symbol covering it |
| `@chunk:line`, `[TRACE n]`, `ffi.meta.__call` | Lua / JIT / VM — never module-qualified |

Module attribution needs ljs **version 7** (symbol size; the image entry carries
the image size). Older profiles fall back to "nearest base", which steals JIT
mcode and heap addresses.

## 3. When frames show raw hex or the wrong name

Check in this order:

1. **Resolver value truncation.** `local _, name = resolver and resolver:resolve(...)`
   yields ONE value (a conjunction is not a multi-value expression) → `name` is
   always nil and every `--pdb`/`--map` answer is dropped. Call first, then take
   the 2nd return.
2. **Cache key.** Cache symbol results by function start (`entry`), not by
   address; a lookup with a stale frame start otherwise caches a miss and hides
   every later answer for that function.
3. **DbgHelp is per-process.** `SymLoadModuleExW` binds symbols to the module list
   of the analysing process, so a foreign load address resolves only by luck and
   in whichever order images were loaded. Read the PDB standalone first
   (`llvm-pdbutil dump -section-headers` + `dump -symbols`; in `addr = SSSS:OOOO`
   section index and offset are HEX, code size decimal), DbgHelp only as fallback.
4. **Accept a name only if the function extent covers the address** — otherwise a
   PDB of another build names a neighbour function.

Probe the resolver directly before touching the parser:

```lua
local r = require("utils.symresolver").new{ embedded = symbols, pdb = { pdbpath } }
print(r:pdb_lookup(addr, entry))          -- entry = function start, not the PC
```

## 4. Verify

- counters: modes C/L/D, JIT on and off (`jit.off()` must give cfunc > 0, trace = 0)
- `jit.mixprof`: ticks == sum of chain counts
- soap soak: start/stop in a loop with GC/pcall/FFI/`jit.flush`, every kept
  profile must parse
- both toolchains build the same sources

## 5. Build pitfalls (same tree)

- Never mix MSVC and MinGW artifacts: `jit/vmdef.lua` embeds a build stamp
  (`assert(require("jit").version == "LuaJIT 2.1.<stamp>")`) → "core/library
  version mismatch" once the other toolchain relinks, and mixed `.o`/`.obj` crash
  the exe with 0xC0000005 at startup. Rebuild the toolchain whose artifacts you
  want, last.
- `mingw32-make clean && mingw32-make -j4` races on the generated `luajit.h`
  (`lj_mixprof.c: fatal error: luajit.h: No such file`): run
  `mingw32-make luajit.h` first, then `-j4`.
- `./src/luajit.exe` in a shell whose cwd is a *workspace root* may resolve to
  another tree's binary; use absolute Windows paths for the tree under test.
