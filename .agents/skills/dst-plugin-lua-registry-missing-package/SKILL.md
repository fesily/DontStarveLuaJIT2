---
name: dst-plugin-lua-registry-missing-package
description: "DontStarveLuaJIT2 plugin package missing from a platform package (init.lua registry abort): ship the Lua face cross-platform + when gate, verify offline"
---

# DontStarveLuaJIT2 Lua plugin registry: missing/gated package

## Symptom

Linux/macOS package logs a load error naming a plugin package
(e.g. `plugins/plugin_render_shadow/modinfo.lua: cannot open ...`), or all
AfterModMain plugins silently do not load.

## Root cause (check first)

- `Mod/plugins/init.lua` is an **explicit registry**: every `load_package(stem)`
  must find `Mod/plugins/<stem>/modinfo.lua` (loaded via `kleiloadlua`).
- `Mod/plugins/package_load.lua` raises `error()` when the chunk is unreadable.
- `Mod/modmain.lua` calls `run_mod_chunk("plugins/init.lua")` **without pcall**,
  so one missing package aborts the whole registry (10+ plugins lost).

## Fix pattern

1. Never let a registry-named package be absent from the package tree.
2. For Windows-only native modules (ANGLE/GLES stage, e.g. `plugin_render_shadow`),
   keep `add_subdirectory` under `if (WIN32)`, but install the Lua face on all
   platforms in `src/DontStarveInjector/CMakeLists.txt` (outside the gum block):

```cmake
if (NOT WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_<stem>/modinfo.lua")
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_<stem>/modinfo.lua"
        "${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_<stem>/modmain.lua"
        DESTINATION plugins/plugin_<stem>
        COMPONENT plugins)
endif()
```

3. Gate in package `modinfo.lua`: `when = function(ctx) if ctx and ctx.is_windows == false then return false end return true end`
   → host resolves `Disabled` (`when_false`), `modmain` never runs.
4. Do not hardcode the platform matrix in `init.lua`; keep registry explicit.

## Verify offline (Windows host, no Linux build needed)

Stage a simulated Linux tree under `builds/_sim/plugins`: tracked
`Mod/plugins/*.lua` + each package's `modinfo/modmain` (no `.so`). Harness: loader
= `io.open`/`loadstring` returning an error string when missing, env with
`MODROOT`, `kleiloadlua`, `GetModConfigData`, `IsWin32 = function() return false end`;
`setfenv(init_chunk, env)`; then `host:register_all(registry)` +
`host:resolve(fn, {is_windows=false, is_client=true, injector={}})`. Expect
`init_ok`, `render.shadow status=Disabled`. Repeat with the package dir removed to
reproduce the abort. Delete the sim dir afterwards.

Validate the install rule separately with a throwaway `project(x NONE)` that
repeats the same `install(FILES … DESTINATION … COMPONENT plugins)` and
`cmake --install --component plugins --prefix out`; and parse the real
CMakeLists via `cmake -P` (it stops at the first executed command but proves
syntax).

## Also

Update `docs/plugin-system.md` §3.4 (Windows-only module rule) and both
CHANGELOGs. Related latent case: missing Frida stage (`_ds_gum_stage_ok=false`)
skips 8 cross-platform packages → same registry abort.
