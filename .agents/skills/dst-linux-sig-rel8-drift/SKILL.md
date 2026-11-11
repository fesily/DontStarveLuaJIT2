---
name: dst-linux-sig-rel8-drift
description: Diagnose why a DST Linux x64 byte signature (rel8 jump displacement) changed across game builds; confirm PIE/CET codegen drift vs real Lua change.
---

# Diagnose DST Linux signature rel8-displacement drift

When a byte signature that used to match the engine's Lua module stops matching (e.g. `7D 60` -> `7D 68`), decide whether it's a real Lua change or just compiler codegen churn.

## Procedure
1. Search the signature in the Ghidra program `dontstarve_dedicated_server_nullrenderer_x64` (Linux x64 dedicated server) with `mcp__ghidra_mcp_search_byte_patterns`; note the hit address. `get_function_by_address` may say "no function" — these are cold/hot-split fragments; use `disassemble_bytes` on the surrounding range and `get_xrefs_to`.
2. Decode the pattern: `81 FE imm32` = `cmp esi, imm32`. In Lua 5.1 `index2adr`: 0xFFFFD8F1=REGISTRYINDEX+1 guard, 0xFFFFD8EF=ENVIRONINDEX(-10001), 0xFFFFD8F0=REGISTRYINDEX(-10000), 0xFFFFD8EE=GLOBALSINDEX(-10002), 0xFFFFD8ED for upvalue math. A `7D`/`74` byte after is a rel8 jump displacement.
3. Get the newest binary from the WSL Steam tree:
   `//wsl.localhost/Ubuntu/home/fesily/.steam/debian-installation/steamapps/common/Don't Starve Together/bin64/dontstarve_dedicated_server_nullrenderer_x64`. Copy it out with a Python `shutil.copyfile`, then search the raw bytes for `81FEF1D8FFFF7D` to read the actual displacement byte.
4. Map file offset -> vaddr via ELF program headers (`struct` parse e_phoff/e_phnum, LOAD segments). For these builds vaddr==fileoffset in the big text segment.
5. Disassemble both with `wsl objdump -d --start-address=.. --stop-address=.. <file>` and diff the block between the `jge` and its target.

## Root-cause checklist (codegen vs logic)
- `readelf -h <file> | grep Type` -> `DYN` = PIE; old DST builds are non-PIE `EXEC` (evidence: absolute `mov eax, imm32` for constants like nilobject).
- Search raw bytes for `F3 0F 1E FA` (endbr64). Zero matches = no CET; presence = `-fcf-protection` build.
- PIE turns absolute `mov eax,imm32` (5B) into `lea rax,[rip+disp]` (7B), reorders/hoists instructions, and lets some jumps shrink to short form -> block grows/shrinks -> rel8 displacement shifts.
- If the `81 FE` immediates are byte-identical and their order is unchanged, it's NOT a Lua change; it's a toolchain rebuild.

## Fix: robust signature
Never pin rel8/rel32 displacement bytes. Keep the `81 FE xx D8 FF FF` compares (immediates are invariant Lua pseudo-index constants) as anchors and wildcard every `jXX` displacement (replace the byte after `7D`/`74` with `??`) or the whole relative operand.

## Reference case
Build 740477 (non-PIE, no CET): `0x7FD318` `7D 60`. Build 756039 (PIE ET_DYN + endbr64): `0x487728` `7D 68`, `74 60`->`74 48`. Net block growth +8 bytes; same pseudo-index constants.
