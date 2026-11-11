---
name: luajit-dasc-macro-port-parity
description: "Port an asm macro/site change from a reference LuaJIT dasc backend (usually vm_x64.dasc) to the other six dynasm backends with per-class site coverage, delegated parallel edits, and a verification gate that includes one real alternate-backend build."
---

# Port a dasc change from the reference backend to all others

Use when a change exists only in `src/vm_x64.dasc` (e.g. sysprof `set_vmstate_*`, VM hooks, mcode bookkeeping) and must reach `vm_x86/arm/arm64/mips/mips64/ppc`.

## 1. Enumerate site *classes*, not lines

Build the class list from the reference file (the diff hunks), e.g. return-to-C, continuation, result adjustment, trace exit, ccallback enter, `BC_CALL`, function headers, each `BC_RET` tail, `BC_FUNCC`. Then measure how many copies each backend has:

```bash
grep -nE 'vmstate[^\n]*(,|\s)C(\b|$)|~LJ_VMST_C\b' src/vm_$a.dasc   # pristine count
git show HEAD:src/vm_$a.dasc | grep -nE 'LJ_VMST_(C|CFUNC|FFUNC|LFUNC)\b'
```

Backends differ in structure, not just syntax: MIPS/PPC/ARM/ARM64 have **two** `BC_RET` tails where x64 shares one, so class coverage counts differ legitimately (10 vs 11 sites).

## 2. Hand each backend to one agent, never to yourself

Six independent files = one `tasks[]` batch. Give every agent: the reference macro text, the class table, and these hard rules:

- place the macro next to the file's existing vmstate helpers, same name, same `#if` guard;
- keep the reference *semantics* exactly (not "improved" coverage — see §5);
- choose scratch registers per site from the file's conventions and **prove liveness** in the report;
- keep delay-slot and address-base constraints (MIPS: no branch-creating insert, use `AT` when `TMP0` holds a live value; PPC: `r0` cannot be an address base; ARM64: `cleartp`-equivalent, `st_vmstate` needs a register);
- run `host/minilua.exe ../dynasm/dynasm.lua <flags> -o tmp.h vm_<arch>.dasc` for the arch and report the exit code;
- no C-level aliasing hacks to make a backend compile.

## 3. Machine-check what a host can check

```bash
for a in x64 x86 arm arm64 mips mips64 ppc; do ... dynasm ... done
grep -o 'LJ_VMST_C\b' tmp.h | wc -l   # must be 0
grep -c 'top_frame_info' tmp.h        # one per stash macro
grep -n 'LJ_VMST_C\b' src/*.dasc src/*.c src/*.h | grep -v CFUNC   # must be empty
```

`buildvm` only *emits text*: `DISPATCH_GL(x)` / `GL->x` offsets are resolved by the target assembler, so compiling `buildvm_arch.h` on the host proves nothing about them. Do not claim cross-assembly validation; say "dynasm + emitted-text inspection".

## 4. Build and run one *real* alternate backend

The only trustworthy runtime evidence is a second backend you can execute: build `vm_x86.dasc` as x64-non-GC64 and run the full harness on it.

```bash
cd src && mingw32-make clean && mingw32-make -j1 luajit.exe          # x86 dasc, X64=1, LJ_FR2=0
# then rebuild the default GC64 build and re-run everything
mingw32-make clean && mingw32-make -j1 "XCFLAGS=-DLUAJIT_ENABLE_GC64"
```

Quote `XCFLAGS` as one argument in **git-bash**, not through `cmd.exe` (cmd mangling turns `-D...` into make switches: "no rule to make target"). Reduced configs: `-DLUAJIT_DISABLE_JIT`, `-DLUAJIT_DISABLE_PROFILE`, both, and the `amalg` target.

## 5. Restore strict parity before committing

Agents improve coverage where the reference has a gap (e.g. stashing in `.ffunc_1/.ffunc_2` when x64 only stashes in bare `.ffunc`). Cross-platform behaviour drift in a diagnostics path is a bug report waiting to happen: revert the extras instead of extending the reference, and note the pre-existing limitation in the commit message.

## 6. Commit

Two commits: the behavioural port, then any harness/test fix found while verifying. Message style in this fork: `Area: Sentence.` (`Profiler: Port the sysprof vmstate split to the other backends.`), body = why the data is needed, macro semantics, per-class site list, and a "Verified:" paragraph naming builds + harness results, plus what could not be verified.

## Environment traps

- `bash script.sh` here runs a **WSL** bash rooted at `/mnt/c`; scripts must use `/mnt/c/...`. Git-bash's own command line uses `C:/...`.
- `python - <<'PY'` heredocs can execute in a temporary shell whose cwd differs: after every scripted edit, verify with `grep -c`/`git diff` in a *separate* command.
- `mingw32-make clean` deletes the generated `src/buildvm-arch.h`; regenerate it from `vm_x64.dasc` with the GC64 flags before a direct `gcc` of `buildvm`.
