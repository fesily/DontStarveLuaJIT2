# Engine execution-error storage — locating the data slots

Recon for wiring the host-side hooks `extern_error_message_buffer` /
`extern_had_execution_error` (see `src/lua51original/src/ldo.c` and the
`luajit` submodule's `lj_api.c`).

## Engine shape (all platforms)

The engine's `lua_setexecutionerror`-equivalent (statically compiled into the
game image, no symbol name) is:

```
cmp  qword/dword ptr [flag], 0        ; armed already? -> return
jne  <ret>
...  strncpy(dst, msg, 0x1000)        ; dst = the 0x1000-byte message block
mov  [flag], dst                      ; flag stores the block pointer
```

`flag` and the block are plain `.data` globals; `flag` is NULL until armed and
doubles as the message pointer (same semantics as the mac client).

## Manifestation per operand form

| form | platforms | how to read the address |
|---|---|---|
| `lea reg,[rip+disp32]` | x64 (win64 client/server, linux x64) | `target = next_insn_addr + disp32` |

32-bit forms (`push imm32`, `mov [imm32], reg`, `mov reg,[imm32]`) are no longer
decoded — 32-bit targets are unsupported and fail compilation.

## Measured slots (verified with a capstone sweep; unique hit per binary)

| engine | cmp site | flag | buffer | Δ |
|---|---|---|---|---|
| `bin64/dontstarve_steam_x64.exe` | RVA 0x4f0224 | RVA 0x6b7c80 | RVA 0x6ba2e0 | 0x2660 |
| `bin64/dontstarve_dedicated_server_nullrenderer_x64.exe` | RVA 0x48a3e4 | RVA 0x630ac0 | RVA 0x6310a0 | 0x2660 |
| `bin/dontstarve_steam.exe` (win32 — unsupported, recon only) | VA 0x7ef230 | VA 0x92c7c8 | VA 0x92db80 | 0x13b8 |
| `bin/dontstarve_dedicated_server_nullrenderer.exe` (win32 — unsupported, recon only) | VA 0x79cfa0 | VA 0x8c0748 | VA 0x8c0ac0 | 0x378 |
| `bin64/dontstarve_dedicated_server_nullrenderer_x64` (linux, ELF VAs) | 0x48b344 | 0x5fdd60 | 0x5fdd80 | 0x20 |
| mac 32-bit client (`lua51::_lua_setexecutionerror` 0x0032e348) | — | 0x467d68 | 0x468000 (via ptr var 0x450dbc) | 0x298 |
| Android (`libDontStarve.so`) | — | n/a — the trio is an exported API of the same `.so`; nothing to wire |

Addresses are per-build; always resolve per binary and add the module base at
runtime.

## Resolution path (pattern + wiring)

The pattern lives with the other fixed engine signatures — `luaSetExecutionErrorSignature`
in `signature_load/GameSignature.cpp` (used through `GameSignature.hpp`) — so the
resolver never touches the signature table.  The wiring runs in
`GameLuaContextImpl::HotfixApis`, called once per VM switch right after
`LoadLuaModule` / `LoadMyLuaApi` / `ReplaceApis`:

1. `luaSetExecutionErrorSignature` is scanned with `only_one = false` and
   `targets.clear()` first, then `scan(mainPath.c_str())` — **exactly one** hit is
   required (no first/last-match ambiguity); zero or several → warn, nothing written.
2. `ds::core_vm::detail::decode_execution_error_storage(hit)` (defined beside the
   pattern in `signature_load/GameSignature.cpp`) decodes both slots from the matched
   window — the `cmp [flag], 0` slot (cross-checked by the `mov [flag], …` store to
   the same address) and the `lea` destination of the 0x1000-byte copy.  A missing
   0x1000, no store back into the compared slot, or `flag == buffer` → fail closed.
3. `find_export_by_name(LuaModule, …)` then publishes the pair into the loaded VM:

| VM export | receives |
|---|---|
| `extern_error_message_buffer` | the engine's 0x1000-byte message block |
| `extern_had_execution_error` | the engine's flag slot (the VM's `lua_setexecutionerror` stores the block pointer there, exactly like the engine's own helper) |

Any miss (pattern, decode, missing export — e.g. a stale VM DLL) keeps both
`extern_*` NULL: the VM's private no-op storage stays, nothing is written.

```cpp
// luaSetExecutionErrorSignature, GameSignature.cpp (win64/linux-x64; #error otherwise)
// win64 (client + server: identical bytes)
"48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 75 2A 48 8B D1 48 89 5C 24 20 "
"48 8D 1D ?? ?? ?? ?? 48 8B CB 41 B8 00 10 00 00 FF 15 ?? ?? ?? ?? "
"48 89 1D ?? ?? ?? ?? 48 8B 5C 24 20 48 83 C4 28 C3"
// linux x64 (GCC shape: je +2 / ret / nop, mov rsi,rdi, strncpy called directly)
"F3 0F 1E FA 48 83 3D ?? ?? ?? ?? 00 74 02 C3 90 48 83 EC 08 48 89 FE "
"BA 00 10 00 00 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? "
"48 89 05 ?? ?? ?? ?? 48 83 C4 08 C3"
// macOS and any 32-bit target: #error (compilation forbidden)
```

Both VM flavours export the two pointer globals (checked on freshly built DLLs:
`lua51DS.dll` 499 exports, `lua51Original.dll` 140 — each includes all five
exec-error symbols; the Lua 5.1 variant through `lua.def`, the JIT variants
through `CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS`).

Pattern validation (scan replica over the supported engines; found helper,
decoded slots — exactly one hit each, all equal to the table above):
win64 client helper `0x1404f0220`, win64 server `0x14048a3e0`, linux server
`0x48b340` → flag `0x5fdd60`, buffer `0x5fdd80`.

Smoke run of the shipped code (throwaway harness linking `ds_signature`, engine PE
mapped in-process, `luaSetExecutionErrorSignature` + `decode_execution_error_storage`
called as in `HotfixApis`): win64 client → hits=1, helper rva `0x4f0220`, flag rva
`0x6b7c80`, buffer rva `0x6ba2e0`; win64 server → hits=1, helper `0x48a3e0`, flag
`0x630ac0`, buffer `0x6310a0`.

Live run (win64 client, jit VM, module base `0x7ff78ce90000`):

```
Attached Lua module (loadlib): lua51DS_fresh.dll
execution-error storage published to VM: flag=0x7ff793547c80 buffer=0x7ff79354a2e0
Reinitialized Lua VM runtime: ReplaceLuaModule startup vm=jit
lua_newstate created lua state=0x39d60380 vm=jit
```

`flag-buffer = 0x2660` and the RVAs (`0x6b7c80` / `0x6ba2e0`) are exactly the measured
client slots.  Before the VM was refreshed the same path logged the fail-safe branch
`execution-error storage not published (storage=true buffer-export=false flag-export=false)`
— pattern + decode succeed in-game, only the stale VM's missing exports kept it off.

Dev launch recipe used for the live run (matches `.vscode/launch.json`): cwd = the game
`bin64`, args `-debug_random_data -offline`, `bin64/steamid.txt` = SteamID64 (else
`SteamAPI_Init` fails with `result=1`), plus `lua_vm_type=jit` and
`GAME_LUA_MODULE_NAME=lua51DS_fresh.dll` to bypass a stale, file-locked
`Mod/deps/lua51DS.dll`.  Accepted `lua_vm_type` values (`is_supported_lua_vm_type`): `jit`,
`game`, `lua51`, `51`, `5.1`, `jit_gen`, `_51` — `luajit` is rejected).
