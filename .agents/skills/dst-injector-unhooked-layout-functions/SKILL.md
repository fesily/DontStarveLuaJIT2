---
name: dst-injector-unhooked-layout-functions
description: Find PUC-Lua functions the DST LuaJIT injector leaves unhooked that hardcode VM layout (GameLua.def minus engine direct calls)
---

# Which PUC-Lua functions still run against a LuaJIT state?

Use when the DST LuaJIT injector works overall but individual engine features misbehave
(the item-server call-stack guard, chunk names, GC pacing), or before adding a new
gum-replace hook.

## Core principle

`GameLua.def` (125 entries) is the **replaced** API set. Any Lua-blob function that the
engine calls **directly** and that is *not* in that set still executes **PUC code on a
LuaJIT `lua_State`** — if it also dereferences VM internals, it reads/writes foreign memory.

## Procedure

1. Rebuild callee sets so names match the current DB (stale exports break the diff):
   `DstExportCalleeSets.java <out.tsv>` → `build/symmatch/vt2/calleesets_win.tsv`
2. Compute the exposure set:
   - callers: functions with entry outside `0x140482210..0x14049f790` (the Lua blob)
   - callees: blob functions **not** in `GameLua.def`
   - skip `thunk_` prefixes and `DLL::` qualifiers
3. For each exposed function, read the body and mark whether it touches
   `TValue.tt(+8)`, `Closure.isC(+0xA)`, `Closure->l.p(+0x20)`, `Proto.source(+0x40)`,
   Klei field `Proto+0x78`, `lua_State` offsets, or calls internal symbols
   (`index2adr`, `luaS_newlstr`, `luaD_throw`) — those are the dangerous ones.
4. Correct the name first: several "Klei" functions were previously mis-named
   (`lua_setupvalue_byname`→`lua_setchunkname`, `aux_upvalue`→`setproto_chunkname`,
   `luaL_geterrortext`→`lua_getexecutionerror`, `luaC_setglobalgcflag`→`lua_settimeslice`).

## Known result for r759671 (re-verify after a game update)

| addr | function | exposed | layout | action |
|---|---|---|---|---|
| `0x140483AB0` | `lua_setchunkname` | DoLuaFile, kleiloadlua | yes (tt/isC/l.p + Proto+0x78) | hook as **no-op** |
| `0x1404867A0` | `lua_settimeslice` | IncrementalGarbageCollect | no (global float) | leave |
| `0x140488BC0` | `lua_getexecutionerror` | CallLuaFunction | no (global ptr) | leave |
| `0x140488BD0` | `lua_clearexecutionerror` | CallLuaFunction | no (global) | leave |
| `0x140483B20` | `luaGetFuncChunkName` | traceback formatter | yes | already hooked |

## Signatures

Reader (existing hook):

```
48 83 EC 28 E8 ?? ?? ?? ?? 83 78 08 06 75 ?? 48 8B 00 80 78 0A 00 75 ??
48 8B 40 20 48 8B 40 78 48 85 C0 74 ?? 48 83 C0 18
```

Writer (missing hook, `sub rsp,0x20` variant):

```
48 89 5C 24 10 56 48 83 EC 20 4D 8B D0 48 8B F1
E8 ?? ?? ?? ?? 83 78 08 06 48 8B D8 75 ?? 48 8B 10 80 7A 0A 00 75 ?? 48 83 C9 FF
```

## Compatibility caveats

- `lua_setchunkname` writes only Klei's appended `Proto+0x78`; stock `source` is `+0x40`
  (`luaF_newproto` allocates 0x80 and zeroes +0x78). No-op hooking therefore loses nothing:
  the reader derives the same string from `lua_getinfo(">S")` plus '@' stripping.
- The reader hook returns a name for `loadstring`-created chunks where PUC returns NULL
  (`+0x78` unset → `[**untrusted** short_src]`). If the guard's expected trace covers such
  frames, gate the hook on a set of loader-registered paths instead.
- `lua_isunsafedataallowed` (+0xC1) and the `luaio_*` path guards are dead under the
  injector: `luaopen_io/os/…` are replaced, and +0xC1 is only initialized by the replaced
  `lua_newstate`/`luaE_newthread`.

## Do not mistake for Klei additions

Out-of-line macro copies (`luaC_checkGC`, `luaC_barrier`, `luaC_objbarrier`,
`luaD_checkstack`, `luaK_setmultret`, `luaK_codeAsBx`, `luaM_malloc`) and my own split
names (`luaD_poscall_hookret`, `luaH_resize_internal`, `lparser_enterscope`).
