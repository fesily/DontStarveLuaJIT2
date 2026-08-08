# Task 6 Report: Pilot package save.fork (P2)

**Status:** DONE  
**Branch:** `feature/plugin-package-aggregation`  
**Worktree:** `C:/Users/fesil/DontStarveLuaJIT2/.worktrees/plugin-package-aggregation`  
**Date:** 2026-08-08

## Commits

| SHA | Subject |
|-----|---------|
| `ad06b60` | feat(save.fork): migrate to DST mini-mod package layout |

Full SHA: `ad06b60c402a9ba66ca4ccc66415ce32ff115138`  
Base: `a33217b` (Task 5 identity gate)

## Files

| Action | Path |
|--------|------|
| Create | `src/DontStarveInjector/plugins/plugin_save_fork/modinfo.lua` (spec §6.3) |
| Create | `src/DontStarveInjector/plugins/plugin_save_fork/modmain.lua` |
| Create | `src/DontStarveInjector/plugins/plugin_save_fork/scripts/fork_save.lua` |
| Create | `Mod/plugins/plugin_save_fork/{modinfo,modmain,scripts/fork_save}.lua` (runtime mirror) |
| Modify | `Mod/plugins/init.lua` — `load_package("plugin_save_fork")`; package_modenv + test-path fallback |
| Modify | `Mod/plugins/package_load.lua` — pass package env into `package_modimport` |
| Modify | `src/DontStarveInjector/plugins/plugin_save_fork/plugin_save_fork.cpp` (comment) |
| Delete | `Mod/plugins/save_fork.lua` |
| Delete | `Mod/scripts/fork_save.lua` (moved into package) |

## Interfaces / behavior

- Package SSOT under `src/.../plugin_save_fork/` with isomorphic `Mod/plugins/plugin_save_fork/` for in-repo runtime without cmake install.
- Registry: `load_package("plugin_save_fork")` replaces `load_flat("save_fork")`.
- Task2 minor: `package_modimport(package_root, rel, package_env)` setfenv’s imported chunks into package env so deferred `AddGamePostInit(function() modimport(...) end)` keeps package-local rebind.
- Test path: when `MODROOT` is nil, `load_package` loads from `REPO_ROOT/Mod/plugins/<stem>/`; `AddGamePostInit` late-binds `_G` so host stubs still work.

## Verification

```bash
export LUA_BIN='C:/Users/fesil/DontStarveLuaJIT2/builds/ninja-multi-vcpkg/luajit/Release/luajit.exe'
export REPO_ROOT="$PWD"
python tools/check_plugin_package_identity.py --source-root . --stem plugin_save_fork
python tests/plugin/run_package_load.py
python tests/plugin/run_lua_host.py
python tests/plugin/test_plugin_package_identity.py
```

Results:

```text
ok plugin_save_fork
identity gate OK: checked=1 skipped=0
IDENTITY_RC:0
ALL PASS package_load_spec
PKG_RC:0
PASS: save_fork_enable_matrix
...
plugin_host_lua_spec: all tests passed
HOST_RC:0
IDTEST_RC:0 (6 tests)
```

- L-G present: not run (game optional / SKIP OK).
- CMake install not rebuilt in this session; Task 4 already installs package Lua + scripts when present under plugin source dir.

## Concerns

- Dual content under `src/.../plugin_save_fork` and `Mod/plugins/plugin_save_fork` must stay in sync until install-only Mod tree is the sole runtime path.
- Host tests for remaining dual-face flats still clear `package.loaded["plugins.save_fork"]`; harmless until those migrate.
- Native DLL path still requires build/install for `plugins/plugin_save_fork/plugin_save_fork.dll`; only Lua package tree was staged in-repo.

## Review fix: fork_save_spec load path

**Finding:** `tests/fork_save/fork_save_spec.lua` still loaded the deleted flat path `Mod/scripts/fork_save.lua`.

**Change:** Point `loadfile` at package script path:
`Mod/plugins/plugin_save_fork/scripts/fork_save.lua`

`package.loaded["scripts.fork_save"]` left unchanged (module name still `scripts.fork_save`).

**Commit:** `fix(test): point fork_save_spec at package script path`

### Re-test

```text
# fork_save (direct luajit; run.py PATH miss on this shell)
PASS: unsupported falls back
PASS: parent postsaves after child idle
PASS: parent truncates when empty
PASS: child saves and exits
PASS: other result falls back
PASS: child save failure exits
PASS: isshutdown uses main process
PASS: isshutdown ignores child fork result
fork_save_spec: all tests passed
FORK_RC:0

ok plugin_save_fork
identity gate OK: checked=1 skipped=0
IDENTITY_RC:0
ALL PASS package_load_spec
PKG_RC:0
plugin_host_lua_spec: all tests passed
HOST_RC:0
IDTEST_RC:0 (6 tests)
```
