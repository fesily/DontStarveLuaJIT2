---
name: luajit-sysprof-profile-to-flamegraph
description: "Turn a LuaJIT/Tarantool sysprof .bin profile into flame graph data or a structured dataset with luajit -ts (--format=folded|json|samples), symbolize via --pdb/--map, and verify end to end with flamegraph.pl; includes the Windows CR LF trap."
---

# sysprof profile -> flame graph / dataset

Works on the sysprof Windows port of the Tarantool LuaJIT fork (worktree
with `tools/sysprof.lua`, `tools/sysprof/parse.lua`, `tools/utils/*`).
Default text output is `chain<TAB>count`; the flame graph needs folded
stacks instead.

## 1. Collect

```lua
local sp = require("misc").sysprof
assert(sp.start{ mode = "C", path = "p.bin", interval = 1 })  -- "D" = counters only!
-- workload; make it last >= a few ms, a fully JIT-compiled loop can be
-- faster than one 1 ms tick and gives 0 samples
assert(sp.stop())
print(sp.report().samples)
```

`mode="D"` (default) streams nothing and ignores `path`; only `C`/`L` write
the stream.

## 2. Run the tool

Set `LUA_PATH` to include `<root>/?.lua`, `<root>/tools/?.lua`,
`<root>/tools/?/init.lua`, `<root>/src/?.lua`, `<root>/src/?/init.lua`
(the tool needs `jit.vmdef`), then:

```console
luajit -ts --format=folded --pdb=luajit.pdb p.bin > p.folded
luajit -ts --format=json   --pdb=luajit.pdb p.bin > p.jsonl
luajit -ts --format=samples p.bin > p.samples.jsonl
luajit -ts --map=luajit.map p.bin          # linker map instead of a PDB
```

- `--pdb=<file>`: symbol file, matched to the image by name (`lua51.pdb`
  belongs to `lua51.dll`). Read standalone via `llvm-pdbutil` first, DbgHelp
  only as fallback; a name is accepted only when the function extent covers
  the address.
- Option values work both as `--pdb=x` and `--pdb x`.

## 3. Flame graph

```console
flamegraph.pl p.folded > p.svg      # inferno / flamegraph-rs take the same file
```

Frames are `module!function`, `module+offset`, `@chunk:line`,
`@chunk:line [TRACE n]`, `ffi.meta.__call`.

## 4. Verify (do not trust the file by eye)

- Every line matches `^(.*) (\d+)$` (flamegraph.pl splits at the LAST space).
- Sum of counts == `report().samples` == total of `--format=text`.
- Prefix sums over `;`-split frames build one root (usually
  `ntdll.dll!RtlUserThreadStart`).
- Run the real consumer once: `flamegraph.pl` must exit 0 and the SVG must
  contain expected frame labels.

```python
rx = re.compile(r"^(.*) (\d+)$")
total = 0; nodes = {}
for line in open("p.folded"):
    m = rx.match(line.rstrip("\n"))
    assert m, line
    frames, cnt = m.group(1).split(";"), int(m.group(2))
    total += cnt
    for k in range(1, len(frames) + 1):
        p = ";".join(frames[:k]); nodes[p] = nodes.get(p, 0) + cnt
```

## Windows traps

- **CR LF breaks flamegraph.pl**: the CRT turns `\n` into `\r\n`, and
  `flamegraph.pl` chomps only `\n`, so every line fails `\d+$` ->
  "Ignored N lines with invalid format / Stack count is low (0)". The tool
  now calls `_setmode(1, O_BINARY)` on stdout through `ffi.C._setmode`
  (fallback `ucrtbase`, then `msvcrt`). It must hit the CRT that owns the
  stdout FILE: MSVC builds link ucrt, MinGW builds msvcrt — calling only
  `msvcrt` on an MSVC build silently does nothing. Confirm with
  `b"\r" in output`.
- Never resolve the tool as `./src/luajit.exe` from a shell whose cwd is
  elsewhere: use an absolute path, or you run another checkout's binary.
- Never mix MSVC and MinGW builds in one tree: `jit/vmdef.lua` embeds a
  build-version stamp and the other toolchain's exe then reports
  "LuaJIT core/library version mismatch"; mixed `.o`/`.obj` can crash at
  startup (0xC0000005). After `mingw32-make clean`, build `luajit.h`
  before `-j4` or the parallel build races.

## Limits

- Folded format has no escaping: a `;` inside a chunk name splits the frame.
- Flame graphs count samples; for a timeline use `--format=samples`
  (`time_us` fields, microseconds since 1970, monotonic within a profile).
