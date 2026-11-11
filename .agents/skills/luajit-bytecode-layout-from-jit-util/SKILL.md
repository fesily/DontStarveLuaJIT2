---
name: luajit-bytecode-layout-from-jit-util
description: "Answer LuaJIT bytecode-layout/jump-target questions in this fork by decoding real prototypes with jit.util (cwd=src) instead of inferring from lj_parse.c and vm_*.dasc; includes int32 masking, J offset math and the ISNEXT/ITERN layout."
---

# Decode real bytecode layout instead of reasoning about parser→VM layouts

When a question is about LuaJIT bytecode instruction layout, jump targets, or "what instruction sits at index N" for this fork, measure the compiled prototype; do not derive it from `lj_parse.c` + `.dasc` reading. I got the ITERN companion slot wrong twice that way (claimed loop body / claimed `JMP`; it is the loop-head `ISNEXT`).

## Procedure

1. Use a built interpreter; run with **cwd = `src/`** so `require('jit.vmdef')` resolves (`src/jit/vmdef.lua`). Running from the repo root fails.
2. Define the function but **never call it**, so the prototype stays unpatched (no `JLOOP`/`IFORL` rewriting).
3. Decode each instruction:

```lua
local bit = require('bit')
local util = require('jit.util')
local v = require('jit.vmdef')

local function fields(i)
  local u = i % 4294967296            -- funcbc() returns a signed int32
  local op = u % 256
  local a  = bit.band(bit.rshift(u, 8), 0xff)
  local c  = bit.band(bit.rshift(u, 16), 0xff)
  local b  = bit.band(bit.rshift(u, 24), 0xff)
  local d  = bit.band(bit.rshift(u, 16), 0xffff)
  local j  = d - 0x8000               -- signed jump offset, valid for ISNEXT/JMP/ITERL/LOOP/FORL
  return op, a, b, c, d, j
end

for i = 0, util.funcbc(f, -1) and 0 or 0 do end -- index 0..nbc-1; nbc via util.funcbc(f, -1)? see notes
```

Note: obtain the instruction count first (`jit.util.funcinfo` / `funcbc` until nil), then iterate `i = 0 .. nbc-1` printing `v.bcnames[op+1]` (the name table is 1-based), `D`, and `J`.
4. Compute jump targets as `index + J` for forward/backward jumps (BCIns units, not bytes). For `pc+1+bc_j(pc[1])`-style expressions, remember `pc+1` is the **index of the next instruction**, so the result is `(pc+1) + J(pc[1])` — off-by-one here is what produced the wrong answer.

## Reporting

Give a per-function table (index, opcode, D, J, computed target) plus a one-line verdict ("targets opcode X at index N, which is/is not in `int3_mutable_op`"). State explicitly that the prototype was never called, so the dump is pristine.

## Gotchas

- `funcbc()` returns a signed 32-bit value; instructions with the high bit set (e.g. `FORI`/`FORL`) come back negative — mask with `% 4294967296` (or `bit.band(x, 0xffffffff)`) before extracting fields.
- `ISNEXT`+`ITERN` is emitted only when the generic-for prediction holds (nvars ≤ 5, i.e. up to 2 visible variables); 3+ visible variables fall back to `JMP`+`ITERC`.
- Do not use `buildvm -m <arch>` to "assemble another backend": `-m` selects an output format. The real generator is `minilua dynasm/dynasm.lua -o vm_<arch>.h vm_<arch>.dasc`.
