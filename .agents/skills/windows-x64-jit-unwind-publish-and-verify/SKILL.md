---
name: windows-x64-jit-unwind-publish-and-verify
description: Add or debug Windows x64 UNWIND_INFO publishing for JIT code and verify it with real RtlVirtualUnwind walks (MIR/mir-win64-unwind.h as the reference implementation).
---

# Windows x64 JIT unwind info: publish and verify

Reference implementation: MIR (`mir-win64-unwind.h`, `_MIR_publish_code_with_unwind` in
`mir.c`, Win64 branches of `mir-gen-x86_64.c` / `mir-x86_64.c`).

## 1. Encode version-1 UNWIND_INFO

- Builder collects ops in *prologue execution order* with the code offset of each
  instruction's **end**; encode back-to-front (descending `CodeOffset`).
- Slots per op: `PUSH_NONVOL`/`ALLOC_SMALL`/`SET_FPREG` = 1, `ALLOC_LARGE` info 0 and
  `SAVE_NONVOL`/`SAVE_XMM128` = 2, `ALLOC_LARGE` info 1 and `*_FAR` = 3. Pad the slot
  array to a multiple of 4 bytes; `CountOfCodes` excludes the padding.
- Limits: `CountOfCodes` <= 255 slots, `SizeOfProlog` <= 255, `FrameOffset` multiple of
  16 and <= 240. Failure = error, never truncated metadata (`bad_p`).
- XMM register number = xmmN -> N; GPR numbers are Windows' rax..r15 = 0..15.
- Inherited variant (fragments/thunks whose prologue already ran): same ops and frame
  register, `SizeOfProlog = 0`, every `CodeOffset = 0`, encoded in the same order.

## 2. Prologue shapes that are representable

- With a frame pointer: `push rbp; sub rsp,B; lea rbp,[rsp+F]` (`B` 16-aligned,
  `F = min(B,240)`), saves at `FrameBase+k`, epilogue `lea rsp,[rbp+B-F]; pop rbp; ret`.
  Rebase every FP-relative displacement of the body by `B-F` after register allocation,
  so args/varargs/spills keep their addresses. Metadata save offsets are `k`.
- Without a frame pointer: `sub rsp,block(+pad); mov [rsp+k],reg ...`, epilogue
  `add rsp,...; ret`. SAVE offsets are relative to the post-allocation RSP.
- A function that changes neither RSP nor a non-volatile register is a leaf: no entry.
- Epilogue must be the exact mirror; nothing but restores/stack release/ret/tail-jmp.

## 3. Publish

- Copy the xdata right after the code into the same code holder and compute DWORD RVAs
  from the holder base; keep a stable, never-reallocated `RUNTIME_FUNCTION` array.
- Prefer `RtlAddGrowableFunctionTable(EntryCount=0) + Grow(n)` (resolve from ntdll);
  use `RtlAddFunctionTable` per publish only when the whole growable API is missing.
  A failing registration is an error, not a silent leaf.
- `range.end` covers the whole executable body (not the prologue end), otherwise
  `RtlLookupFunctionEntry` returns NULL and the leaf rule mis-unwinds.
- Entries must be added with increasing `BeginAddress`; delete tables (`RtlDelete…`)
  before the code is unmapped, and keep the tables tied to the code allocator, not to
  the JIT generator (generated code may still run/be unwound after generator teardown).
- Serialize publishing/registration/patching with one lock; never re-enter it
  (public wrapper + no-lock helper).

## 4. Verify with the real OS, not by inspection

- Walk: `RtlCaptureContext` in a host probe callable from generated code, then loop
  `RtlLookupFunctionEntry` -> `RtlVirtualUnwind`, handling the leaf rule (`[Rsp]`).
  Record PC + non-volatile registers per step.
- Call the generated function through a hand-written machine-code caller that saves,
  sets and after the call XOR-checks rbx/rsi/rdi/r12..r15 (and sets xmm0/xmm1), so
  both the callee's ABI and the unwinder's register restoration are tested. Publish
  that caller with its own unwind record.
- Capture the probe's return address with `_ReturnAddress()` / `__builtin_return_address(0)`
  **in the function the generated code calls**; inside an inlined helper MSVC returns an
  inner address.
- Boundary test: publish a template with the same encoder/publisher, reproduce the state
  at each prologue instruction end on a private stack, and require the caller's RIP/RSP/
  RBP (and saved registers) back. For offsets at/after the prologue end the OS unwinder
  deliberately does not restore registers — set them already-restored and expect them
  unchanged.
- Cover: full / lazy / lazy-bb interfaces, optimize 0 and 2, big frames (>240), varargs,
  alloca, inlined `bstart/bend`, floats through the wrapper, a hook that clobbers its
  32-byte home area, MSVC `__try/__except/__finally`, interpreter + `ff_call`, 600+
  functions across holders/grow steps, callable after `MIR_gen_finish`, lookup == NULL
  after context destruction, and a custom code allocator whose unmap callback asserts
  the table is already gone.
- Extra builds: (a) resolver returns NULL -> fixed-table path must pass the same suite;
  (b) registration forced to fail -> error handler reports it and no callable address is
  returned. Keep injections in throwaway copies of the source, not runtime switches.

## 5. Toolchain pitfalls

- `RUNTIME_FUNCTION` field names differ (MinGW `UnwindData`, SDK `UnwindInfoAddress`):
  use an own `{DWORD begin,end,info;}` struct and cast at the API boundary.
- MSVC: no `__attribute__((aligned))` (use `__declspec(align(16))`), and an all-`#ifdef`-
  empty static array is error C7757 — guard the whole declaration instead.
- MinGW has no `_ReturnAddress`/`_AddressOfReturnAddress` symbols; use the GCC builtins.
- Keep the repo's line endings: python text-mode writes on Windows turn LF files into
  CRLF and produce whole-file diffs — normalize back to the HEAD blob's endings and
  re-check `git diff --stat`.
