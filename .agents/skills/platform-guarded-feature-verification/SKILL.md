---
name: platform-guarded-feature-verification
description: "When a C/C++ change is gated by platform/feature macros (Windows vs Linux vs \"plain\" targets), verify every guarded configuration on the host instead of trusting the one you can run"
---

# Verifying a change that is gated by target/feature macros

Motivating failure (MIR Linux-CFI work): a green Linux suite hid (a) a *compile
break* in the `#else` branches and (b) a reverted Windows epilogue that made 13
Windows tests segfault. Both were found only by re-running the other platform.

## 1. Enumerate the configurations before editing

List every branch the guard selects, as compile+run pairs:

- primary target (e.g. Linux x86-64, feature ON)
- the *other* platform that shares the source file (Windows, feature=B)
- the "plain" path (`#if !A && !B`: macOS, *BSD, x32, Android, ...)

Write them down; each needs a different check.

## 2. Give the feature a test-only disable hook

If the plain path is otherwise unreachable on your host, add one documented hook
in the single header that defines the guards:

```c
#ifndef MIR_UNWIND_DISABLE
#if ...target condition...
#define MIR_FEATURE 1
#endif
#endif
```

Then build the library **twice** in the test setup: the normal object library and
a second OBJECT library (`add_library(mir_plain OBJECT mir.c mir-gen.c)` with
`target_compile_definitions(... MIR_FEATURE_DISABLE)`), link a small program
against it and assert both that it runs and that the feature is *off* (e.g.
`_Unwind_Find_FDE(code) == NULL`). This turns "only compiles on macOS" into a
failing test on Linux, and it immediately found a signature referencing a
Windows-only struct in the plain build.

## 3. Re-run the other platform after EVERY edit in a shared file

A comment/guard edit in a file shared by both platforms can drop a branch
silently. Keep a one-command check per platform (CMake build + `ctest`) and run
both before claiming done. Never trust "the Linux suite is green".

## 4. Prefer assertions on artifacts and bytes over on faith

- A host program cannot prove a shared library's link dependency: the C driver
  appends `-lgcc_s` (or equivalent) to every executable link. Assert the artifact
  instead: `add_test(NAME x-needed COMMAND sh -c "readelf -d '$<TARGET_FILE:mir_shared>' | grep -q libgcc_s")`.
- To test a code-generation decision (e.g. "the thunk reserves 128 bytes"),
  read the emitted bytes/relocations, or follow the real redirect chain; do not
  assert only "it runs", because a benign misalignment still runs.

## 5. Keep the two build routes in parity

If both CMake and a hand-written Makefile build the same tests, every new test
dependency must be added to both. Adding c2mir usage to a test broke only the
`make` route (`undefined reference to c2mir_init`) because the rule listed
`mir.o mir-gen.o` but not `c2mir/c2mir.o`; CMake hid it (the OBJECT library
already contained c2mir).

Same trap with per-target variables: `make debug2` sets `CFLAGS`/`LDFLAGS` for
that target *and its prerequisites*, so a separate goal (`dwarf-unwind-test`)
gets none of them — make it a prerequisite of `debug2` instead of relying on
`$(LDFLAGS)`.

## 6. When a guard is duplicated, hoist it once

Three translation units that each `#define` the same target guards will drift
silently (one TU then compiles the plain path while another emits the feature).
Put the conditions in one header and include it from all of them; a test hook
(step 2) also lives there.

## 7. Report honestly which fixes have teeth

For every review finding, state whether an automated check fails without the fix.
Mutation-check the important ones (revert the fix, watch the test go red). Call
the rest *known gaps* with the reason (asynchronous-only effect, unreachable
input, needs a harness the repo does not have).
