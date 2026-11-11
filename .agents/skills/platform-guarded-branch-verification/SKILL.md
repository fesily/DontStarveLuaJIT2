---
name: platform-guarded-branch-verification
description: "Compile and run platform-guarded (macOS/BSD/x32/Android) code branches on the host via a documented test-only guard-disable macro, plus artifact-level link-contract assertions"
---

# Verifying platform-guarded branches on a single host

## When
A feature is compiled only on some targets (`#if defined(_WIN32) && x86-64`, `#if linux && __x86_64__ && __LP64__`), so every other target's branches are written but never built by the local CI. Reviewers correctly flag them as unverified; reasoning is not enough.

## Recipe
1. Put the platform predicates in **one** small header (e.g. `mir-unwind-target.h`) that every TU needing them includes. Duplicated `#if` blocks in several files drift silently and make the fix below impossible.
2. Wrap the predicate block in a test-only kill switch:
   ```c
   /* Testing hook: with -DMIR_UNWIND_DISABLE both guards stay undefined, i.e. the
      plain paths (macOS, *BSD, x32, Android) are compiled and can be run here. */
   #ifndef MIR_UNWIND_DISABLE
   ...#define MIR_DWARF_UNWIND 1 / MIR_WIN64_UNWIND 1...
   #endif
   ```
3. Add a second build of the *library objects* with that define (a separate CMake OBJECT library over the same sources, or a second make target), plus a tiny test program also built with the define. It must assert the feature is really off (e.g. `_Unwind_Find_FDE(entry) == NULL`) and do one runtime smoke of the code those branches emit (legacy thunk/wrapper, plain publish).
4. Add `#error "... did not disable ..."` in the test program when the guards are still defined, so a broken hook is loud.

## What this catches
Undeclared identifiers, unused variables/parameters and prototype mismatches in branches the host never compiles - the exact class that produced real blockers here (locals declared under one guard but used in another; a prototype naming a Windows-only struct). It does not prove cross-platform *semantics*; say so in the test comment.

## Pitfall seen here
`publish_stub(ctx, code, len, const void *b)` - untyped parameter keeps the Windows unwind type out of the plain-target signature; cast to the concrete struct only inside the `#if defined(MIR_WIN64_UNWIND)` branch.
