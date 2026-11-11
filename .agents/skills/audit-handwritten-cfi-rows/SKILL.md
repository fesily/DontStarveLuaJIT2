---
name: audit-handwritten-cfi-rows
description: "When hand-written DWARF CFI/UNWIND_INFO rows beside generated machine code misbehave: dump the bytes + parse the FDE, decode rows, check instruction-end offsets and CFA arithmetic"
---

# Verify a hand-written CFI row table against the emitted machine code

Use when a DWARF (`.eh_frame`/FDE) or `UNWIND_INFO` row table is written by hand
beside hand-built machine code and unwinding misbehaves, crashes inside libgcc
(`movaps` fault), or the walk stops one frame early.

## 1. Get the bytes and the stream out of the process

Write a throw-away C/C++ program that links the library, builds/calls the
target stub (or `_MIR_publish_code_with_unwind` equivalent), and prints:

* every byte of the published blob (numbered, e.g. 20 per line),
* the FDE for that address, parsed manually:
  `length(4) cie_ptr(4) initial_location(8) address_range(8) ULEB auglen` then
the instruction stream (including the encoder's `DW_CFA_nop` padding).

Locate instructions in the dump programmatically (search for the opcode
pattern) instead of counting bytes by eye — `48 81 ec` / `ff d0` / `push`
patterns give exact offsets:

```python
for i in range(len(b)):
    if b[i:i+3] == [0x48,0x81,0xec]: print("sub rsp,imm32 at", i, "imm", i+3, "ends", i+7)
```

## 2. Decode the rows and check both invariants

Decode the stream into `(offset, ops)` rows and for each row assert:

1. **the offset is an instruction END** — libgcc looks up `return PC - 1`, so a
   row one byte early still "works" synchronously but violates the contract;
2. **the CFA value equals the real `rsp + n`** at that point, where `n` counts
   `push` = +8 each, `sub rsp,imm` = +imm, `movdqu`/store = +0.

Compute the expected CFA independently from the byte dump, never from the same
expression the emitter uses.

## 3. Check alignment at every `call`

RSP must be 0 mod 16 at the call. Track parity from the entry (`≡8` for a
function entry, `≡0` for a tail-jumped body) through every push/sub. A
non-multiple-of-8 adjustment (e.g. `sub $13`) silently breaks it and the fault
appears as `movaps` inside `_Unwind_Backtrace`, not at your code.

## 4. Make the test able to fail

* Never assert a *count* of matching frame descriptions unless the set is
  closed (minimal program, known holders) — otherwise the check is a false pass.
* Recognising a thunk/range by an exact stream length fails when the encoder
  pads: compare the **prefix** and require the remainder to be `DW_CFA_nop`.
* Mutation-test each new assertion: change one byte of the input rule (e.g. drop
  a register-offset opcode) and confirm the test fails.
* Remember `_Unwind_GetCFA` in a callback reports the *previous* frame's CFA, so
  "the CFA of frame X" is asserted on `frames[X + 1].cfa`.

## 5. Re-run every platform that shares the file

A shared target file (one `foo-x86_64.c` included by several front-ends) breaks
silently per platform: run the Linux suite *and* the Windows suite after each
edit, and grep the strict-warning compile (`-Wall -Wextra -Wshadow`) for the
touched file only.
