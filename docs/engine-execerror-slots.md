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
...  copy 0x1000-bounded message      ; into the 0x1000-byte static block
mov  [flag], <block>                  ; flag stores the block pointer
```

`flag` and the block are plain `.data` globals; `flag` is NULL until armed and
doubles as the message pointer (same semantics as the mac client).

Two body generations exist, and both must decode:

| generation | copy | bounds check | slot store |
|---|---|---|---|
| pre-759671 | `strncpy(block, msg, 0x1000)` | `mov reg, 0x1000` (size argument) | `lea reg,[block]` + `mov [flag], reg` |
| 759671+ (linux) / build 26474873 (win64) | inlined `strlen` + CRT checked `memcpy` | `cmp len, 0x1000` / `mov len, 0xfff` (trailing-byte-safe truncation) | `mov [flag], reg`, where `reg` still holds a `lea` target |

The rewritten body also `lea`s a read-only empty string as the NULL-message
fallback **before** it loads the block, so "the first `lea` in the window" is no
longer the block — see the decode rule below.

## Manifestation per operand form

| form | platforms | how to read the address |
|---|---|---|
| `lea reg,[rip+disp32]` | x64 (win64 client/server, linux x64) | `target = next_insn_addr + disp32` |

32-bit forms (`push imm32`, `mov [imm32], reg`, `mov reg,[imm32]`) are no longer
decoded — 32-bit targets are unsupported and fail compilation.

## Measured slots (build 26474873; verified with a capstone sweep, unique hit per binary)

| engine | cmp site | flag | buffer | Δ |
|---|---|---|---|---|
| `bin64/dontstarve_steam_x64.exe` (win64) | RVA 0x488de4 | RVA 0x68ca08 | RVA 0x68f060 | 0x2658 |
| `bin64/dontstarve_dedicated_server_nullrenderer_x64.exe` (win64) | RVA 0x421f14 | RVA 0x5f59b8 | RVA 0x5f5fa0 | 0x5e8 |
| `bin64/dontstarve_steam_x64` (linux, ELF file offset = VMA) | 0x4aef64 | 0x6b7b60 | 0x6b7b80 | 0x20 |
| `bin64/dontstarve_dedicated_server_nullrenderer_x64` (linux) | 0x4233a4 | 0x5e5aa0 | 0x5e5ac0 | 0x20 |
| `bin/dontstarve_steam.exe` (win32 — unsupported, old-build recon only) | VA 0x7ef230 | VA 0x92c7c8 | VA 0x92db80 | 0x13b8 |
| `bin/dontstarve_dedicated_server_nullrenderer.exe` (win32 — unsupported, old-build recon only) | VA 0x79cfa0 | VA 0x8c0748 | VA 0x8c0ac0 | 0x378 |
| mac 32-bit client (`lua51::_lua_setexecutionerror` 0x0032e348) | — | 0x467d68 | 0x468000 (via ptr var 0x450dbc) | 0x298 |
| Android (`libDontStarve.so`) | — | n/a — the trio is an exported API of the same `.so`; nothing to wire |

Addresses are per-build; always resolve per binary and add the module base at
runtime.  Windows slot consumers in this build: the getter at RVA 0x488dc0
(`mov rax,[flag]`), the helper's own `cmp [flag],0` / `mov [flag],rbx`, and the
protected-call status override at RVA 0x489632 (`cmp [flag],0` + `cmovne`); the
helper is still called from the error path (RVA 0x495fd5 client, 0x42f105
server).  Linux has the same trio of users (getter 0x423384, override 0x423485
on the server).

Both slots must be writable: in this build they are both in `.data`
(win64 client `0x68ca08`/`0x68f060`), while the NULL-message fallback string
(`lea` at helper+0x11) sits in `.rdata`.  Decoding the block from the *first*
`lea` therefore produced a read-only "buffer" and would have made the VM's
0x1000-byte copy fault; the corrected rule resolves the block from the register
published into the flag.

## Resolution path (pattern + wiring)

The pattern lives with the other fixed engine signatures — the `core.vm.execution_error`
entry in `signature_load/CoreVmSignatures.cpp` (owner `core.vm`, resolved through the
signature providers) — so the resolver never touches the signature table.  The wiring
runs in `GameLuaContextImpl::HotfixApis`, called once per VM switch right after
`LoadLuaModule` / `LoadMyLuaApi` / `ReplaceApis`:

1. `ds::sig::host_resolve("core.vm.execution_error", &report)` asks the Injector's
   SignatureManager for the entry (definition revision 1, unique-hit rule); the
   provider's own verifier already ran the ::0x1000::/store/`lea` decode, so a
   non-resolved answer means "warn, nothing written".
2. `ds::core_vm::detail::decode_execution_error_storage(report.target_va)` (defined
   beside the entry in `signature_load/CoreVmSignatures.cpp`) decodes both slots from
   the matched
   window — the `cmp [flag], 0` slot, and the block as the `lea` target of the register
   that the `mov [flag], …` store publishes (register moves forward a known target, any
   other write to that register forgets it).  This is deliberately *not* "the first
   `lea`": the rewritten body loads a read-only empty-string fallback first.  A missing
   0x1000 bound, no store back into the compared slot, a stored value that does not
   trace back to a `lea`, or `flag == buffer` → fail closed.
3. `find_export_by_name(LuaModule, …)` then publishes the pair into the loaded VM:

| VM export | receives |
|---|---|
| `extern_error_message_buffer` | the engine's 0x1000-byte message block |
| `extern_had_execution_error` | the engine's flag slot (the VM's `lua_setexecutionerror` stores the block pointer there, exactly like the engine's own helper) |

Any miss (pattern, decode, missing export — e.g. a stale VM DLL) keeps both
`extern_*` NULL: the VM's private no-op storage stays, nothing is written.

```cpp
// core.vm.execution_error, CoreVmSignatures.cpp (win64/linux-x64; macOS not defined)
// win64, build 26474873 (client + server: identical bytes; strlen + checked memcpy)
"48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 75 76 48 85 C9 48 8D 15 ?? ?? ?? ?? "
"48 89 5C 24 30 48 8D 1D ?? ?? ?? ?? 48 0F 45 D1 48 3B D3 74 4B "
"48 83 C9 FF 48 89 7C 24 20 33 C0 48 8B FA F2 AE 48 F7 D1 48 FF C9 48 8B F9 "
"48 81 F9 00 10 00 00 72 15 BF FF 0F 00 00 0F B6 04 17 24 C0 3C 80 75 06 "
"48 83 EF 01 75 F0 4C 8B C7 48 8B CB E8 ?? ?? ?? ?? C6 04 1F 00 "
"48 8B 7C 24 20 48 89 1D ?? ?? ?? ?? 48 8B 5C 24 30 48 83 C4 28 C3"
// previous win64 body (pre-26474873: strncpy through the import table) — kept here
// only as history; it no longer matches a current build.
"48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 75 2A 48 8B D1 48 89 5C 24 20 "
"48 8D 1D ?? ?? ?? ?? 48 8B CB 41 B8 00 10 00 00 FF 15 ?? ?? ?? ?? "
"48 89 1D ?? ?? ?? ?? 48 8B 5C 24 20 48 83 C4 28 C3"
// linux x64 (GCC shape: endbr64, je +2 / ret / nop, strlen + __memcpy_chk)
"F3 0F 1E FA 48 83 3D ?? ?? ?? ?? 00 74 02 C3 90 "
"41 54 55 48 89 FD 53 48 85 FF 74 ?? "
"4C 8D 25 ?? ?? ?? ?? 4C 39 E7 74 ?? "
"E8 ?? ?? ?? ?? 48 89 C3 48 3D FF 0F 00 00 76 ?? "
"BB FF 0F 00 00 EB ?? 90 48 83 EB 01 74 ?? "
"0F B6 44 1D 00 83 E0 C0 3C 80 74 ?? "
"B9 00 10 00 00 48 89 DA 48 89 EE 48 8D 3D ?? ?? ?? ?? "
"E8 ?? ?? ?? ?? 41 C6 04 1C 00 5B 5D"
// macOS and any 32-bit target: #error (compilation forbidden)
```

Both VM flavours export the two pointer globals (checked on freshly built DLLs:
`lua51DS.dll` 499 exports, `lua51Original.dll` 140 — each includes all five
exec-error symbols; the Lua 5.1 variant through `lua.def`, the JIT variants
through `CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS`).

Validation, build 26474873.  The shipped `ds_signature` code was driven directly
(`MemorySignature::scan` over the mapped image, then
`decode_execution_error_storage` on the single hit), and the pattern strings were
read back out of the source, so this exercises the checked-in bytes rather than a
hand copy:

| engine | hits | helper | flag | buffer |
|---|---|---|---|---|
| win64 client | 1 | RVA 0x488de0 | 0x68ca08 | 0x68f060 |
| win64 server | 1 | RVA 0x421f10 | 0x5f59b8 | 0x5f5fa0 |
| linux client | 1 | 0x4aef60 | 0x6b7b60 | 0x6b7b80 |
| linux server | 1 | 0x4233a0 | 0x5e5aa0 | 0x5e5ac0 |

(The Windows probe mapped the PE file itself, so it reports file offsets —
uniformly 0xc00 below the RVAs above, helper, flag and buffer alike.)
The pre-26474873 win64 pattern scores **0 hits** against these binaries; that is
the regression this table exists to catch.  Every slot pair is consistent with
the module base (`flag = base + rva`) and both slots sit in writable `.data`.

Live run (linux dedicated server, rebuilt `plugin_core_vm`, `log_level=info`):

```
execution-error storage published to VM: flag=0x5c33d9debaa0 buffer=0x5c33d9debac0
```

`base = 0x5c33d9806000` → flag offset `0x5e5aa0`, buffer offset `0x5e5ac0`, Δ `0x20`:
exactly the measured linux server slots, so pattern + decode both survive the
rewritten helper body in-game.

Historical (win64 client, jit VM, before the body rewrite — the shape that proved the
wiring end-to-end):

```
Attached Lua module (loadlib): lua51DS_fresh.dll
execution-error storage published to VM: flag=0x7ff793547c80 buffer=0x7ff79354a2e0
Reinitialized Lua VM runtime: ReplaceLuaModule startup vm=jit
lua_newstate created lua state=0x39d60380 vm=jit
```

`flag-buffer = 0x2660` and the RVAs (`0x6b7c80` / `0x6ba2e0`) were exactly that
build's client slots.  Before the VM was refreshed the same path logged the
fail-safe branch `execution-error storage not published (storage=true
buffer-export=false flag-export=false)` — pattern + decode succeeded in-game, only
the stale VM's missing exports kept it off.

Dev launch recipe used for the live run (matches `.vscode/launch.json`): cwd = the game
`bin64`, args `-debug_random_data -offline`, `bin64/steamid.txt` = SteamID64 (else
`SteamAPI_Init` fails with `result=1`), plus `lua_vm_type=jit` and
`GAME_LUA_MODULE_NAME=lua51DS_fresh.dll` to bypass a stale, file-locked
`Mod/deps/lua51DS.dll`.  Accepted `lua_vm_type` values (`is_supported_lua_vm_type`): `jit`,
`game`, `lua51`, `51`, `5.1`, `jit_gen`, `_51` — `luajit` is rejected).
