---
name: dst-pre-push-gate-triage
description: "Triage and fix DontStarveLuaJIT2 pre-push hook / ctest failures: reproduce with tools/pre_push.py, classify asserts vs game startup crashes vs port collisions, rebuild stale test targets, and honor repo-specific traps (lua51.dll reference layouts, duplicate FunctionRelocation logger, modal CRT dialogs)."
---

# Pre-push gate triage (DontStarveLuaJIT2)

## 1. Reproduce exactly what the hook runs

```bash
python tools/pre_push.py --dry-run      # build dir + config (usually Debug) + ctest cmd
python tools/pre_push.py -R <regex>     # one test, fast loop
python tools/pre_push.py                # full gate (~4-10 min)
```

The hook is `.githooks/pre-push` -> `tools/pre_push.py`; it runs ctest in the newest
`builds/*` dir with `-j $(nproc)`, preferring Debug. It only fails when a test
actually fails; missing tooling prints a skip.

## 2. Classify the failure

| Symptom | Meaning |
|---|---|
| `Subprocess aborted` + `REQUIRE failed: ...` | test's own assertion (often a build-dependent constant) |
| exit `3221226505` / `0xC0000409` + `Assertion Failed: Illegal termination of worker thread` | **the game** asserted while shutting down after a failed startup - not the python script |
| `SOCKET_PORT_ALREADY_IN_USE` / `RakNet UDP startup failed` | cluster port taken by a leftover or the user's own server |
| `Failed` after 3-6 min in `plugin_client_*` | game never reached the expected token; check its captured log |

## 3. Known traps in this repo

- Game-launching tests (`plugin_client_inject_smoke`, `plugin_client_host_smoke`,
  `plugin_dedicated_sim_pause`, `game_mod_throw_abort`) share
  `RESOURCE_LOCK dst_game_server` and must not hardcode UDP ports. They must call
  `tests/harness/ports.py::free_udp_port()` before `write_offline_cluster()` and
  pass the same port through `STRESS_CONNECT_PORT`.
- Tests that read `Mod/deps/lua51.dll` (training/reference library) must not pin
  byte sizes or span budgets that depend on one build of that DLL. Assert
  structural invariants instead (e.g. "span must not cross the next exported
  RVA", using `pe_exports()`).
- `function_relocation::init_ctx()` already creates the `FunctionRelocation`
  spdlog logger (rotating file next to the main module). Creating it again
  (`spdlog::create` / `stdout_color_mt`) throws and a Debug CRT shows a modal
  assert dialog that hangs batch runs. To get logs on the console, push an extra
  sink onto the existing logger instead (`spdlog::get("FunctionRelocation")`).
- Batch tools should disable modal CRT/WER dialogs
  (`SetErrorMode(SEM_*FAULTERRORBOX)`, `_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE)`)
  and make stdout/stderr unbuffered, otherwise a crash looks like a hang.

## 4. Verify before re-running the whole gate

```bash
# single test
python tools/pre_push.py -R nucleus_adapter
# rebuild the affected test target first if headers/structs changed
cmake --build builds/ninja-multi-vcpkg --config Debug --target <test_target>
# full gate
python tools/pre_push.py
```

Stale Debug binaries built before a struct/layout change are a common source of
phantom failures - rebuild the target under test before believing a failure.

## 5. Port check helper

```bash
netstat -ano | findstr ":10999"    # Windows
ss -lunp | grep 10999              # Linux
```

Also check for leftover `dontstarve_dedicated_server_nullrenderer_x64` / client
processes; the harness kills its own children but not other instances.
