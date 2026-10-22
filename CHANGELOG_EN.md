# Changelog

## Unreleased

- Linux dedicated server boot: fixed `nucleus_analyze_file(lua51) failed: nucleus load_binary failed: .../deps/liblua51.so` followed by an immediate process exit. The build image has no `binutils-dev`, so `3rd/nucleus` compiled `NUCLEUS_LOADER_NO_BFD` into `libfunction_relocation.so` (the package ships neither `libbfd-2.42-system.so` nor any BFD symbol) and Linux `load_binary()` fell through to the "no binary loader available for non-raw type" stub. Linux no longer depends on libbfd: `loader.cc` now has a native ELF64 loader (sections from `SHF_EXECINSTR` / `SHF_ALLOC` and not `SHT_NOBITS`, `STT_FUNC` symbols from `.symtab`/`.dynsym`, `.eh_frame_hdr` FDE seeds as before). The resulting FunctionTable matches the BFD path entry for entry on `liblua51.so`, `liblua51DS.so`, `liblua51Original.so`, `dontstarve_dedicated_server_nullrenderer_x64` and `dontstarve_steam_x64` (25324 / 27236 spans identical for the two game executables). macOS still uses BFD.

- Linux boot: `libfrida-gum.so` is now linked with `-Wl,-z,noexecstack` (`tools/setup_frida_gum.py`). glibc >= 2.41 refuses to `dlopen` a DSO that requires an executable stack (`cannot enable executable stack as shared object requires`), and the shell loads the real Injector with `dlopen`, so Ubuntu 25.04+/WSL2 failed at boot (#45/#47).

- Injection diagnostics: `nucleus_analyze_file` failures now carry the loader's own reason (`nucleus load_binary failed: <path> (<loader reason>)`, likewise for disasm/CFG) instead of the bare wrapper string.

- On Windows, `lua51DS`/`lua51DS_gengc` can publish LuaJIT trace symbols through the Microsoft-JScript ETW provider (`57277741-3638-4a4b-bdba-0ac6e45da56c`) - no manifest install, no JIT PDB. The publisher is **off by default at runtime** and switched process-wide from Lua with `require("jit.profile").etw(true|false)` (query with `etw()`): `etw(true)` also flushes that VM's traces (equivalent to `jit.flush`, so every live trace ends up with a record and no stale identity survives) and `etw(false)` reports MethodUnload/SourceUnload/ScriptContextUnload at once and stops publishing, with the records freed by their owning VM instead of another thread. **A game or host must therefore call `etw(true)` in the injected VM** (the integration tests and `--hold-for-profile` do), otherwise the ETL carries no JIT names. Once on: every committed trace publishes one source and one method record, so `CPU Usage (Sampled)` in WPA/PerfView resolves a sampled PC inside `[T->mcode, T->mcode + T->szmcode)` to `LuaJIT::TRACE_<traceno>::<chunk>:<startline>`. `tests/performance/cpu.wprp` subscribes it with keyword `0x3` (runtime load/unload plus the start rundown), so attaching to a process that already compiled traces still resolves them, and its event collector buffers were raised because the GUID is shared with every Chakra host on the machine (Edge/WebView2 emit tens of thousands of their own JIT events). The symbol name is the trace's starting line; exit stubs and the interpreter dispatch path are not covered, and `RtlAddFunctionTable` is deliberately not called (`lj_err.c` identifies JIT frames by the absence of a `RUNTIME_FUNCTION`), so native unwinding across JIT frames is unchanged. The chunk part comes from the Lua side: `@`/`=` prefixes are stripped, bare paths are kept (`scripts/xxx.lua`, as the DST engine passes them, so game traces read `LuaJIT::TRACE_12::scripts/worldgen_main.lua:243`), and names that look like source text (newlines or over 512 bytes) collapse to `(string)`. Publishing never holds the symbol-cache lock across an `EventWrite` (the lock only covers list/flag updates: ~0.2 us per committed trace, ~15 ns per record), and the worker is joined outside the lifecycle lock with a 5 s timeout diagnostic, so a backpressured session cannot stall trace compilation or VM create/close. `--jit-diagnostics`/`analyze.py` remain a separate stdout/`jit.attach` path, not an ETW symbol consumer. It is **not compiled by default**: opt in with `-DLUAJIT_ENABLE_ETW=ON` (CMake) or `XCFLAGS+=-DLUAJIT_ENABLE_ETW` (Makefile); `-DLUAJIT_TEST_ETW=ON` (together with `LUAJIT_ENABLE_ETW=ON`) builds the real-ETW integration tests for both GC variants (`luajit_<variant>_etw_symbols`; exit code 77 = CTest SKIP when the shell has no sampling privilege, a missing event fails, and `--hold-for-profile` supports the live mid-session attach check).

- `install.bat` / `install_linux.sh` are shell-only now: on Windows it copies the packaged `bin64\windows\Winmm.dll` into game `bin64` (skipped when already identical), on Linux it puts the packaged `bin64/linux/lib64/libInjector.so` into game `bin64/lib64` and rewrites the `LD_PRELOAD` launchers (real binaries kept as `*_1`, re-runs skip); both no longer migrate or delete mod files, write the marker, or prune stale game-dir DLLs. The old scripts did not converge on in-place updates - `if exist Injector.dll` / `[ -f libInjector.so ]` kept the previous version's Injector at the mod root and robocopy (no `/MIR`) / `cp -a` kept deps/plugins the new package had dropped, pairing a new shell with an old Injector, which is a boot-crash source. Source/destination are derived from the script's own location (caller cwd independent), Windows error messages no longer break cmd parsing through `(`/`)` in absolute paths, and `uninstall` only removes the shell plus the legacy marker (on Linux it also renames the `*_1` originals back).

- `dev_init.sh` / `dev_init.bat` (`tools/update_steam_paths.py`) now complete one more init step: after locating the game dir they write `<game>/bin64/steam_appid.txt` with the app id (default `322330`), so the manual creation described in the debug docs is no longer needed.

- One-line install: `install.ps1` (Windows, `irm ... | iex`) and `install.sh` (Linux, `curl ... | sh`) - pick the newest release/preview (`DSJ_CHANNEL` / `--channel`), locate the game root through Steam using the same rules as `tools/steam_env.py` (registry / `libraryfolders.vdf` / `appmanifest_322330.acf`, overridable with `DSJ_GAME_DIR` / `--game-dir`), stage the package under `<game>/mods/<folder>` and run the packaged installer (shell deploy; on Linux the marker and self-check as well).

- Inject diagnostics: the shell (Winmm / InjectorStub) now writes the resolve source, module path, load/export results and its own outcome to `<game>/data/unsafedata/ds_luajit_boot.log` on every boot (stderr kept); `install_linux.sh` finishes with a `[CHECK]` summary (shell / real module / `ldd`) and gained `install_linux.sh selftest` (a one-process live probe of the stub -> real-module chain); the script now re-execs under bash when started via `sh` (dash) instead of dying with a syntax error and doing nothing.

- `plugin.manager`: added a cross-process plugin-tree lock (`plugins/.ds_plugin_update.lock`, `LockFileEx`/`flock`) - the boot update check and installs serialize on it, so a client + Master/Caves boot wave performs a single check and never writes the tree concurrently (unsupported locking falls back to the previous unlocked behaviour with a note; the lock file is stamped with the holder pid/host for diagnostics). The boot check is now part of `plugin_manager` (the separate `plugin.autoupdate` module and its three dedicated services are gone), the manager mutex is no longer held across checks or applies so `status_json` keeps answering, and a waiting apply rebuilds its plan under the lock after at most 30 s instead of re-downloading what another process just installed.

- Install layout is package-only: only `plugins/<stem>/<stem>.<ext>` is accepted (manifest slots carry `package=<stem>`, `module` must be `<package><ext>`, `files[]` are package-relative so nested members such as `modinfo.lua` and `scripts/*.lua` finally install); flat modules are no longer candidates (the loader ignores and warns, manifest validation and zip extraction were tightened); when a member is locked the whole package moves to `update_pending/<package>/` so a new Lua face never pairs with an old module.

- Manifest platform slots and packaged meta now carry a `build_config` build stamp: assets of an incompatible class (MSVC Debug vs the Release family) are refused before any download.

- Tooling/tests: cross-platform pre-push ctest gate (`.githooks/pre-push` + `tools/pre_push.py`, skippable via `git push --no-verify` / `PRE_PUSH_SKIP`); game-launching ctests share a `RESOURCE_LOCK(dst_game_server)` so `ctest -j` no longer collides on the fixed ports (10999/8766/27016); the Injector resolves/scans only the current layout (the real module in the mod root) - `bin64`/`lib64` legacy candidates and deps search fallbacks were dropped.

- Tooling/tests: fixed the phantom timeouts of the game ctests on a Chinese Windows code page (`plugin_dedicated_sim_pause` / `plugin_client_inject_smoke` / `plugin_client_host_smoke` / `game_mod_throw_abort`). The harness decoded child stdout as UTF-8 with `errors="replace"`; the resulting U+FFFD cannot be encoded by a GBK console, so the reader thread died with `UnicodeEncodeError` and stopped draining the pipe - the game then blocked writing to stdout until the test timed out. `harness.logs.safe_print` now degrades on encoding failure, and the three runner entry points set stdout/stderr to `errors="replace"`, so the reader thread can no longer die on a print failure.

- Tooling/tests: fixed the Windows loader failures in the `plugin_hash_zip` / `plugin_apply_offline` ctests (`0xc0000135` for `jvm.dll`, `0xc0000139` for entry point `zip_file_add`). Both statically import vcpkg's `zip.dll`, which was not deployed next to the test binaries, so the loader followed PATH and picked a JDK's `bin\zip.dll` - a JNI library that imports `jvm.dll` and does not export the libzip symbols. The build now copies `zip.dll` plus its `bz2d/zlibd1` deps (`bz2/zlib1` in Release) next to each test executable, independent of PATH.

- Fixed the `dump_lua_mods` chunk routing (engine `lua_load` hook): a chunkname is not always a file path - `loadstring`/buffer loads pass the code itself as the chunkname (the modoverrides table, the save-data wrapper, the `GameLuaInjector.forceEnableLuaMod(...)` injected block all take that path). Those previously hit `find("../mods/")` + `npos + strlen` out-of-range slicing (a code block shorter than 8 bytes threw `std::out_of_range`) and the bogus `!exists()` test, while the thunk fallback was shadowed by an inner `auto output_path` and never took effect - dumps silently failed or landed under an illegal file name. `ChunkDumpPath()` now maps only `../mods/<mod>/<file>` (optional `@` prefix, no illegal path characters, <= 255 chars) to `dumped_lua_mods/<file>` and sends everything else to `dumped_lua_mods/thunk.lua` (write policy is covered by the next entry; a warning is emitted when the file cannot be opened). Verified on a dedicated server with `lua_vm_type=game`: `plugin_lg_probe/modmain.lua` lands as a real file while the modoverrides / save-data code blocks land in thunk.lua.

- Fixed `dump_lua_mods` producing only the tail of encrypted-mod sources (hercules / MyxlHttps family, e.g. workshop-3014076942): their loader feeds the decrypted source to the reader in ~8-byte slices **inside a single `lua_load`** (e.g. `myxl_date.lua` 245 slices = 1960 bytes, `speech_moyuxuanli.lua` 43k slices = 344112 bytes) and **re-enters `lua_load` while that reader is still draining**; the shared `thread_local LuaReaderWrapper` was cleared by those re-entrant calls, so every accumulated slice but the last was dropped and the dump held a few trailing bytes. Each `lua_load` now gets its own wrapper (re-entrant calls build and dump their own), so the whole file is assembled into one write: the files above now dump as complete plaintext sources (344112 / 70920 / 36360 / 1960 bytes). The write policy is also three-state now: slices of a stream are appended, a payload at least as large as the dump replaces it (a complete chunk), and stray small payloads after a complete dump are skipped (the complete 80154-byte modmain is no longer clobbered by the 652-slice re-stream that follows it). Dumps are written in binary mode (text mode turned `\n` into `\r\n`, so dumps did not match the real source).

## 3.2.0

- Fixed the encrypted-mod (frostxx/daxsg family, e.g. workshop-1991746508) server worldgen hang/crash: their loader probes `require("jit")` and then takes a broken LuaJIT path (bytecode VM "K nil" or an infinite loop) that corrupts worldgen state. New `Mod/modworldgenmain.lua` drops `_G.jit` (`rawset`) and clears `package.loaded.jit` only in the real worldgen state (`WORLDGEN_MAIN`, set by `scripts/worldgen_main.lua`; the client front end and normal load paths have no such marker), gated by the `HideGlobalJIT` option (on by default).

- Fixed garbled frames when VBPool ran alongside an explicit ANGLE backend (e.g. `AngleBackend=vulkan`): GL entry points now resolve from the engine's own `libGLESv2.dll` IAT slots (i.e. the active renderer after `render.angle` rebinds), with a soft dep so `render.angle` loads first (priority 36); when the slots are unavailable the pool fails closed instead of targeting the module that has no current GL context.

- `render.shadow`'s silhouette batch resolves its GL entry points through the engine IAT slots too, picking the active renderer module (shared `util/engine_gles.hpp`).

- Fixed `render.shadow` silhouette shadows dying completely after the 2026-10 game update: `LoadShader` is pinned by signature instead of the hardcoded RVA (0x3e9f00 -> new 0x12170, scanned once per process); the two GLSL sources in `shaders/sil.ksh` are NUL-terminated as the engine expects (the missing byte compiled as `0:18: '?' : syntax error`); the shader asset now ships with the plugin (CMake install + debug deploy script).

- Engine 5.1 parity (macOS client used as the reference, with a parity audit and regression tests):
  - New Klei compat layer (process-wide execution-error sink, `luaD_pcall`'s `LUA_YIELD` override, a `lua_settimeslice` compatibility stub) and an engine-shaped `db_errorfb` traceback (`LUA ERROR stacktraceback:` header, 8-space frame indent, `(line,1)` instead of `%d:`, only a leading `@` dropped from the chunk name).
  - At every VM switch the engine's own execution-error slots (0x1000-byte message block + the flag storing its pointer) are located by signature and published into the swapped-in VM, so the engine's error display and `luaD_pcall` read the same storage; any miss (pattern, decode, export) leaves them unwired (fail closed).
  - `debug.getsize` is taken over with an implementation keeping only the observable contract (fetch the debug table and leave it on the stack) instead of the one-way ret patch, fixing the replayed boot's `lua_settable(L, 0)` -> "attempt to index a string value".
  - C/FF-callee tail calls (`LUA_COMPAT_TAILCALL_CFRAME`) and traceback naming/`(tail call)` lines were aligned to the engine - result forwarding, surviving caller frames, the KBASE restore and the dump-version boundary - with new `tests/lua_vm_parity` cases and `luajit_parity_*` guards (including the intentionally kept xpcall caller-frame difference).

- Fixed the root cause of the arena-GC wild `L->base` crash: the x64 barrierback macro kept its saved registers inside the Win64 shadow space, so `lj_gc_barrierback_arena`'s prologue overwrote the saved RA/BASE (luajit submodule `vm_x64.dasc`, 56d05799); the same bump fixes three GC white-box tests that parsed 64-bit object addresses as 32-bit, and the crash-investigation doc moved into the luajit submodule.

- The engine `lua_load` hook now also dumps the chunks loaded through the lauxlib paths (`luaL_loadbuffer` / `luaL_loadfile`) into `dumped_lua_mods/` (it previously only took reader-less loads); LuaJIT gained an `LJ_DS_LOADLOG` chunked source dump.

- ANGLE: with an explicit Vulkan backend the display is now requested through `eglGetPlatformDisplay` with `EGL_FEATURE_OVERRIDES_DISABLED_ANGLE` disabling `enablePrecisionQualifiers`, so DST's mediump/lowp shaders are not run at reduced precision (measured RelaxedPrecision 41 -> 0, D3D11 output unchanged; a missing API warns instead of silently falling back).

- Signature/injector fixes: the update pass zeroes the offset of a failed entry and re-infers it (falling back to that entry's stored pattern and an address+size module scan), fixing stale DBs that left `luaL_loadbuffer`/`luaL_loadstring` 0x20 too low and made every mod fail with "unexpected symbol near 'char(N)'"; the duplicate-RVA guard now only considers RVAs produced by the current pass; `signature_updater` was split into `create` and `update_signatures` targets (the update target used to mostly run the create path); startup hooks use `replace` again (on frida-gum 17.17 `replace_fast` has no on_enter trampoline and returns `GUM_REPLACE_WRONG_SIGNATURE`).

- Fixed `alloc_rpc_channel` erroring on a nil `namespace_or_code`.

- Moved Steam integration into host `sdk/steam/`: capture the client AccountID before config resolution and install dedicated Workshop hooks independently of VM enablement.

- Centralized Workshop directory caching and queries in the host for VM file IO; removed the obsolete Steam utility layer and experimental library target.

- Added offline decrypt/encrypt scripts and a handling procedure for Fengxun (frostxx) protected mods (`.opencode/skills/decrypt-encrypted-mods/`: CLI with `--selftest` and round-trip verification, plus shell-extraction/deobfuscation steps, writing all artifacts to a separate directory and leaving the mod bytes untouched).

- `BufferNamePool` unit test expectations now derive from the in-class cap constants (128/bucket, 1024, 64MiB).

- Test infrastructure: a game test harness (locates the game via `GAME_DIR`/`DST_GAME_DIR`, injects a mod with guaranteed cleanup, offline cluster writer, dedicated-server launcher, ctest skip mapping) + the first game fixture (modmain indexing nil -> asserts the engine MOD ERROR and the startup abort) + LuaJIT traceback parity guards.

## 3.0.0

- V3 architecture update - plugin packaging: plugins were unified into the DST mini-mod package layout, the loader discovers package subdirectories and supports `package_load` (with a DST modinfo sandbox); all dual-face packages such as `save.fork` were migrated.

- External plugin packs: enumerate enabled DST mods and load third-party luajit plugin packs behind the modinfo trust gate (path jail + in-package module listing), with a confirmation prompt before enabling.

- Plugin `configuration_options` baked into the parent modinfo: `configuration_options`, `host_gate` (AND of `all_of`+`any_of`) and AddSection dividers; config reads bind to the owning modname.

- Install layout: shell and core Injector split (shell stages into the game, the real Injector lives in the mod's `bin64`) and loads through mod/deps search paths; dynamic vcpkg linkage on all platforms with shared runtimes staged under `mod/deps`.

- Function location and signature stack: vendored Nucleus + shared shell over frida-gum 17.17.0; Windows `.pdata` / Linux `.eh_frame_hdr` function-start seeding (stripped DST has no lua dynamic symbols); soft-match (micro-window unique-const, short-body, match policies); graph-seed reverse plus transitive export recovery, with first-call dedupe so `luaL_loadbuffer`/`luaL_loadstring` no longer tie; 740477 client/server signatures 102/102.

- ANGLE as shared libraries: `libGLESv2`/`libEGL` ship as DLLs and are loaded with `LoadLibrary`, rebinding the engine IAT to the exports (no more static ANGLE).

- `core.vm` split: GameLua contexts moved into `game/` translation units with public types re-exported at the old location; new Frida Gum new-API interceptor wrappers.

- `render.shadow` plugin shipped (dual-face: EarlyNative registration + AfterModMain reads config and calls the exported API): the sun-driven `GenerateVB` hook with Lua state feed, SunModel math and unit tests, 360° cycle / hemisphere switch / integer Lua ABI; options include `ShadowSunDrive`, `ShadowSilhouetteBatch` (exclusive with the sun ellipse; silhouette wins), `ShadowLengthBoost` and `ShadowHemisphere`.

- Fixed the LuaJIT `debug.getlocal` crash at tail-call levels.

- Debug: allocate a console when `Debug.config` exists.

- Tooling/CI: added the debug+ASAN suite and a game smoke runner; macOS builds disabled in the release workflow.

## 2.9.1

- fork_save completed on Windows: win32 backend, usable from boot, child net no-ops for snapshot management, child process status polling, auto-kill on overtime, use master when exiting the server, plus Lua tests.

- LuaJIT Gen GC polish: gated fullgc O(live) verify cost (skipped by ASAN builds), ClearMarks chunking with arena-slice yield, slimmer T3b header, P4-mark quantum drain (step budget capped at 128 objects / 4KB), the pause assert step(1) fix, gengc tests and the LuaJIT variant registry / gengc build bridge.

- New `HideGlobalJIT` option: the global `jit` is injected only for mods declaring `luajit_compatible` and hidden from the others; GameLua cleaned up its IO library references and unused JIT options.

- ANGLE decoupled from the main vcpkg manifest (`tools/angle` + prebuilt `3rd/angle`), with automatic binary-cache directory creation, so CI cache resets no longer rebuild ANGLE.

- Fixed an ASAN SEGV from static init order in `initialize_all_so` (a constructor ran before the namespace-scope `std::string` library names were constructed, handing nullptr to loadlib).

- Fixed a potential nil reference for TheWorld in a periodic task.

- Fixed Windows build/release and game VM issues; refreshed client/server signatures and CI.

## 2.8.0

- Added LuaJIT Gen GC support (generational GC, frame GC, disabled Full GC).
- Added game fork save support.
- Added a new vertex buffer (VB) pool.
- Added buffer pool statistics tracking with EMA hit rate.
- Updated Linux signatures.
- Fixed Linux recursive crash.
- Fixed lua-debug mode.
- Renamed local server config directory.
- Fixed profiler_push signature.

## 2.7.3

- Moved SlowTaICall checker to the C side.

## 2.7.2

- Fixed network simulator (netsim) bugs.

## 2.7.1

- Fixed GameLuaModule-related bugs.

## 2.7.0

- Added client-side render vertex caching.
- Added server-side lag compensation.
- Added a network packet loss simulator.
- Added a stress-test bot framework.
- Added visual disable support for mod configuration options.
- Injected platform environment into modinfo.
- Fixed network optimization bugs.
- Fixed handling for invalid configuration file reads.
