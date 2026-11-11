---
name: asm-fix-regression-teeth-check
description: "When a fix touches hand-written assembly or a supposedly-unreachable path: enumerate the invariant across all backends, prove each new test fails when the defect is reintroduced, add anti-vacuity guards, and build ABI/register probes for state C cannot see."
---

## When to use

A defect was fixed in hand-written assembly (VM backend handler, ABI trampoline, JIT stub) or in a code path you believe is unreachable. Before reporting it done, you must be able to answer: "which run turns red if someone reintroduces this?" If the answer is "none", either build a probe or say explicitly that it is uncovered — never claim "untestable".

## 1. Enumerate the defect class, not the instance

Write down the invariant, e.g.:
- "handler X preserves every non-volatile register"
- "every backend reaches the C dispatcher for this event"
- "slot Y is never patched by the tracer"

Then check the invariant at **every** site it applies to, on every backend/POR. A one-site fix plus a one-site test leaves the same class live elsewhere — the common failure mode is fixing x64 and forgetting x86/arm because the harness only executes x64.

## 2. Prove each new test has teeth (mandatory)

Never ship a regression test you have not seen fail:

1. Temporarily restore the defect (re-add the instruction, drop the enum case, remove the mask bit).
2. Clean rebuild (`mingw32-make clean` — stale objects hide asm-table changes; dynasm output is a generated header).
3. Run the suite; record the failing lines. They must be **exactly** the new checks — extra failures mean the revert was broader than intended.
4. Revert the source and prove it: `git diff <file>` empty and the blob hash matches HEAD.

Report the teeth output verbatim; it is the only evidence that the test is not decoration.

## 3. Anti-vacuity guards

A test that passes when the behaviour never happens is worse than no test:
- assert the triggering event occurred (`hits >= N`, `samples == 2*N`) **before** asserting the absence (`mask == 0`);
- assert the helper actually located its target (no "not found" early return);
- keep the "skipped" path loud (`printf(... skipped)`) so a silently disabled probe cannot be mistaken for a pass.

## 4. Testing ABI/register state from C

C cannot see callee-saved registers, but assembly can:
- naked function, push the non-volatile set, `sub rsp, 40` on Win64 (32-byte shadow space + 16-byte alignment), seed distinct sentinels, call the target through the C ABI, build a bitmask with `cmp`/`setne`/`shl`/`or`, restore, `ret`;
- **check downcall wrappers first**: `lua_pcall` and friends save/restore some of those registers themselves, so the outer compare can miss the clobber. Add samples taken from inside the call (Lua-callable naked C functions) bracketing the instruction under test;
- do not sample registers that are live VM state between instructions (e.g. rbx/rsi/rdi hold KBASE/PC/DISPATCH in the Win64 interpreter) — that produces false positives;
- gate on toolchain and build variant (`_WIN32 && __x86_64__ && __GNUC__`; skip when the loaded library uses a different interpreter, e.g. detect GC64 from the dump header flag), and print the skip.

## 5. Classify what remains uncovered

Three honest categories:
- **Unreachable by construction** (defence in depth): no black-box path distinguishes presence from absence. Say so; do not add a tautological test.
- **No runtime on this host** (foreign arch backends): assembler/dynasm validation only. State it as a support-matrix limitation.
- **Out of scope for the harness**: name where it would be caught (CI, other platform).

## 6. Squashing follow-ups without changing content

`git reset --soft <base>` then one commit; the message lists every folded change with its rationale plus the verification matrix. Accept only if `git rev-parse HEAD^{tree}` is unchanged and `git diff <old-HEAD> HEAD` is empty; no rebuild is needed (tree identical), but re-run the existing binary as a smoke.
