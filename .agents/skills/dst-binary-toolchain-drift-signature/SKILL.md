---
name: dst-binary-toolchain-drift-signature
description: Use when a byte signature for a heavy/engine function (e.g. embedded Lua 5.1 index2adr) stops matching after a DST build update; explains GCC/Ubuntu toolchain drift (PIE/CET) and how to make signatures robust.
---

# DST binary toolchain drift vs byte signatures

When a signature that located a statically-linked engine function suddenly stops matching
after a DST version update, the cause is almost always a **compiler/toolchain change**, not a
logic change. rel8/rel32 jump displacements and addressing encodings are codegen artifacts.

## Diagnose toolchain change

Read the `.comment` section (exact compiler string):
- On-disk file: `readelf -p .comment <binary>` (or `strings -a <bin> | grep 'GCC:'`).
- Old binary only in Ghidra DB: `search_strings "GCC:"` → returns the `.comment` address space value.

Known DST Linux `dontstarve_dedicated_server_nullrenderer_x64` builds:
- build 740477: `GCC: (Ubuntu 4.8.4-2ubuntu1~14.04.4) 4.8.4` → `ET_EXEC` non-PIE, no CET,
  absolute `mov reg,imm32` addressing, image base 0x400000.
- build 756039 (Steam buildid 25643519): `GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0`
  → `ET_DYN` PIE, CET on (`endbr64` at entries), RIP-relative `lea reg,[rip+disp]`.

Confirm at binary level:
- `readelf -h` → `Type: DYN` = PIE vs `EXEC`.
- `search_byte_patterns "F3 0F 1E FA"` → `endbr64` presence = CET (`-fcf-protection`).
- absolute `mov eax,<imm32 addr>` vs `lea rax,[rip+disp]` = non-PIE vs PIE.

Ubuntu defaults drive this (since 17.10 `-pie`; GCC 9.x on 20.04 `-fcf-protection`), so a
distro image bump flips both at once.

## Fix the signature

Don't pin jump displacement bytes. Anchor on **invariant immediates** and wildcard the branch encodings.

Lua 5.1 `index2adr` (lapi.c pseudo-index dispatch) constants (stable across builds):
- `81 FE F1 D8 FF FF` = `LUA_REGISTRYINDEX+1` guard (-9999)
- `81 FE EF D8 FF FF` = `LUA_ENVIRONINDEX` (-10001)
- `81 FE F0 D8 FF FF` = `LUA_REGISTRYINDEX` (-10000)
- `81 FE EE D8 FF FF` = `LUA_GLOBALSINDEX` (-10002)
- `B8 ED D8 FF FF` = -10003 (upvalue arithmetic)

Compare order is invariant (guard → ENVIRON → REGISTRY → GLOBALS); only the intervening
`lea`/`jXX` layout moves. So wildcard `jge`/`je` displacement bytes (`??`) — e.g. observed
`JGE rel8` drifting `7D 60` → `7D 68` and `je` `74 60` → `74 48`.

## Verify

Search old pattern in old binary (1 hit) and confirm the offending byte differs in the new
binary; re-search with wildcarded displacements to re-locate the function.
