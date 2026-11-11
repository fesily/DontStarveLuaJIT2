---
name: win64-callee-saved-regression-probe
description: "Regression-test that native/VM code preserves Win64 non-volatile registers (rbx,rsi,rdi,r12-r15) from a C harness, using a naked seeding wrapper plus in-call checkpoints when the API itself saves them."
---

# Purpose

Prove from a C test harness that a native code path (interpreter loop, JIT trampoline, signal/exception handler) does not clobber Win64 callee-saved registers. A C caller cannot observe this directly, but a small assembly wrapper can.

# Why the naive probe is not enough

A wrapper that seeds rbx/rsi/rdi/r12–r15, calls the public API, and compares afterwards detects only leaks that survive the API's own epilogue. Many APIs (e.g. LuaJIT's `lua_pcall`) push/pop r12–r14 themselves, so the write is masked: the outer compare reports clean even when the inner code wrote r12. Verified case: the built `lua_pcall` contains `push r14/r13/r12 ... pop r12`, and a handler that wrote r12 still produced `mask=0x0` from the outer probe alone.

Therefore use two layers.

# Layer 1 — outer probe (naked function, GCC/MinGW x64)

```c
typedef int (*ApiRef)(lua_State *L, int a, int b, int c);

__attribute__((naked)) static int probe(ApiRef fn, lua_State *L, int a, int b)
{
  __asm__ __volatile__(
    ".intel_syntax noprefix\n\t"
    "push rbp\n\tpush rbx\n\tpush rsi\n\tpush rdi\n\t"
    "push r12\n\tpush r13\n\tpush r14\n\tpush r15\n\t"
    "sub rsp, 40\n\t"                 /* 32B shadow + 8 to align */
    "mov rbx, 0x1122334455667788\n\t" /* distinct sentinel per reg */
    "mov rsi, 0x2122334455667788\n\t"
    "mov rdi, 0x3122334455667788\n\t"
    "mov r12, 0x4122334455667788\n\t"
    "mov r13, 0x5122334455667788\n\t"
    "mov r14, 0x6122334455667788\n\t"
    "mov r15, 0x7122334455667788\n\t"
    "mov r11, rcx\n\t"                /* fn */
    "mov rcx, rdx\n\t"                /* arg0 = L */
    "mov rdx, r8\n\t"                 /* arg1 */
    "mov r8,  r9\n\t"                 /* arg2 */
    "xor r9d, r9d\n\t"                /* arg3 = 0 */
    "call r11\n\t"
    "xor eax, eax\n\t"                /* build mask: bit0 rbx .. bit6 r15 */
    "mov r10, 0x1122334455667788\n\t"
    "cmp rbx, r10\n\tsetne r10b\n\tmovzx r10d, r10b\n\tor eax, r10d\n\t"
    /* ... repeat with shl 1..6 for rsi,rdi,r12,r13,r14,r15 ... */
    "add rsp, 40\n\t"
    "pop r15\n\tpop r14\n\tpop r13\n\tpop r12\n\t"
    "pop rdi\n\tpop rsi\n\tpop rbx\n\tpop rbp\n\t"
    "ret\n\t"
    ".att_syntax prefix\n\t");
}
```

Frame rules: entry `rsp ≡ 8 (mod 16)`; 8 pushes keep it ≡ 8; `sub rsp, 40` restores 16-byte alignment and provides the 32-byte shadow space. `eax` is intentionally overwritten by the mask (save/ignore the API's return value; assert results from the C side).

# Layer 2 — in-call checkpoints

Add two naked C-callable functions that snapshot the registers into globals and return 0, and call them from the scripted code immediately before and after the suspected instruction:

```c
static unsigned long long before[4], after[4];

#define SAMPLE(p) __asm__ __volatile__( \
  ".intel_syntax noprefix\n\t" \
  "mov qword ptr " p "[rip], r12\n\t" \
  "mov qword ptr " p "+8[rip], r13\n\t" \
  "mov qword ptr " p "+16[rip], r14\n\t" \
  "mov qword ptr " p "+24[rip], r15\n\t" \
  "xor eax, eax\n\tret\n\t.att_syntax prefix\n\t")

__attribute__((naked)) static int sample_before(lua_State *L) { SAMPLE("before"); }
__attribute__((naked)) static int sample_after(lua_State *L)  { SAMPLE("after"); }
```

Compare `before[i] != after[i]` between the two calls; that observes the registers while the interpreter frames are still live, which is exactly where a trampoline clobber happens.

Sample only registers that the callee-frame code does not *legitimately* use: in a Win64 interpreter, rbx/rsi/rdi commonly hold KBASE/PC/DISPATCH, so they change between two instruction boundaries by design — restrict the checkpoint set to r12–r15 (or to whatever is provably unused).

# Anti-vacuity

Always assert that the trap/path under test actually executed (call counter ≥ iterations) and that every checkpoint ran (`samples == 2*iterations`). Otherwise a clean mask proves nothing.

# Teeth check

Reintroduce the clobber (e.g. put the offending `mov r12, ...` back), rebuild, and confirm the probe fails reporting exactly that register's bit plus the symbolic name; then revert and confirm the source blob is unchanged.

# Limits

- GCC/MinGW x64 only; MSVC x64 has no inline asm — print an explicit "skipped" line instead of silently passing.
- POSIX x64 has a different savereg/CFI layout; do not assume the Win64 result carries over.
- Guard the test so it skips when the loaded binary is not the architecture variant being probed (e.g. a non-GC64 x64 LuaJIT uses the x86 backend, so probe a build-configuration flag detected at runtime instead of assuming).
