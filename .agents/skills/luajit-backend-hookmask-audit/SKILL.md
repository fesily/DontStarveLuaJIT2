---
name: luajit-backend-hookmask-audit
description: "Audit a new hookmask/dispatch bit across all 7 LuaJIT VM backends, separating executable backends from assemble-only ones"
---

# Auditing a new hookmask / dispatch bit across all VM backends

Use when a LuaJIT fork change adds a bit to `global_State.hookmask` (or to
`lj_dispatch_update`'s mode computation) that must reach a dispatcher callback
(`lj_dispatch_ins`, `lj_dispatch_call`, `lj_trace_hot`, `lj_trace_exit`).
Motivating failure: `HOOK_INT3` was wired into `vm_inshook` on x64, arm64, mips,
mips64 and ppc but omitted on **x86 and arm**. Symptom: the feature worked on
the developer's backend and silently degraded to "first event only" on the
other, because the inner mask test took the early `jz` exit before the C
dispatcher (which also planted deferred state) ever ran.

## 1. Enumerate, don't assume

There are **two** mask tests inside `vm_inshook` on every backend, and they are
not interchangeable:

```
test mask, HOOK_ACTIVE            → already inside a hook: skip
test mask, LINE|COUNT|<new bit>   → first gate; missing the new bit = never dispatch
dec hookcount; jz call            → count exhausted
test mask, LINE|<new bit>         → only bypasses the count
```

`arm64` and `ppc` restructure this (early `tbnz #7` / `andix.` on the new bit
before the line/count test), so equivalence must be reasoned per backend, not
pattern-matched. Also check `vm_record`, `vm_rethook`, `pcall`/`xpcall`:
`pcall` remembers `HOOK_ACTIVE` only and must **not** see a feature bit.

## 2. Separate the two layers

- `lj_dispatch_update()` decides whether the table points at `vm_inshook` at
  all (e.g. `DISPMODE_INS` for `LUA_MASKLINE|LUA_MASKCOUNT|HOOK_INT3`). A
  session can therefore reach `vm_inshook` and still be dropped by the inner
  test. Verify both layers independently before blaming either.
- Prove the mechanism before editing: revert only the dasc change under test and
  confirm the same failures persist (that distinguishes "my edit broke it" from
  "pre-existing backend gap").

## 3. Only two backends are executable on a Windows host

| backend | verification available |
|---|---|
| x64 GC64 (`-DLUAJIT_ENABLE_GC64`) | full harness |
| x86 (`-DLUAJIT_DISABLE_GC64`, `DASM_ARCH=x86`) | full harness; also MSVC 32-bit via `vcvars32` + `msvcbuild.bat` |
| arm / arm64 / mips / mips64 / ppc / ppc64 | **assembly only** — no runtime |

A test that passes on x64 is *not* evidence for the other five. State the
executed/unexecuted split explicitly in reports; never imply coverage you did
not run.

## 4. Assembling a non-host backend

`buildvm -m <arch>` is an **output format** selector (`elfasm`, `coffasm`,
`machasm`, …), not an architecture — it prints usage for `-m arm`. The real
generator is dynasm driven by the host `minilua`:

```
minilua dynasm/dynasm.lua -D ENDIAN_LE -D P64 -D FPU -D HFABI -D JIT -D FFI \
        -D VER=80 -o vm_arm64.h vm_arm64.dasc
```

Copy the `DASM_FLAGS` from the `Makefile` target for each arch. Success proves
the instruction encodings are valid (e.g. a new mask must still be a legal ARM
modified immediate after the bit is added), not that the semantics are right.

## 5. Prefer one definition over seven copies

If the same mask expression appears in all backend files, a missed copy is a
silent defect class. A single `HOOK_INS_MASK`-style macro removes it; the
trade-off is churn in seven `.dasc` files, so raise it as a proposal when the
omission happens a second time rather than pre-emptively rewriting.

## 6. Report template

- audit table: backend × (first test, second test, verdict)
- which backends executed the harness, which were assembled only
- the A/B that proves the mechanism (revert-only run, then one-bit fix)
- corrected historical claims: if an earlier verification note for a backend
  cannot be reproduced, say so and supersede it
