---
name: run-debug-asan
description: "Build and run Debug+AddressSanitizer LuaJIT GC suite and DST dedicated server smoke (jit_gen). Use when user says: run asan, debug asan, asan game, asan tests, re-run asan, ASAN suite, debug+asan."
---

# Run Debug + AddressSanitizer (suite + game)

## Description

Rebuild LuaJIT under ASAN, run the ArenaGC GC regression suite, cmake-install Debug package into `Mod/` (`liblua51DS_gengc` + real Injector + InjectorStub) with `LUAJIT_ENABLE_FSANITIZE`, then smoke the Don't Starve Together dedicated server under ASAN with `lua_vm_type=jit_gen` using the portable bootstrap layout (stub PRELOAD + marker → Mod root).

## Trigger

Use when the user says any of:

- "run asan", "debug asan", "debug+asan"
- "asan game", "asan tests", "asan suite"
- "重新跑 asan", "重跑 debug+asan", "ASAN 测试集"

Prefer the **script** over hand-rolled commands.

## One command

```bash
# Full: suite + game
tools/run_debug_asan.sh

# Suite only / game only
tools/run_debug_asan.sh --suite-only
tools/run_debug_asan.sh --game-only

# Reuse binaries, longer soak after World gen
tools/run_debug_asan.sh --skip-build --soak 180

# Custom evidence dir / timeout
tools/run_debug_asan.sh --evidence .omo/evidence/my-run --timeout 300
```

Evidence lands in `.omo/evidence/debug-asan-<timestamp>/` (or `--evidence`).

## What the script does

| Lane | Action |
|---|---|
| 1. Suite build | `make -C luajit/src ASAN=1 XCFLAGS="-DLUAJIT_ENABLE_GCARENA -DLUA_USE_ASSERT"` |
| 1. Suite run | 14 GC tests under `ASAN_OPTIONS=detect_leaks=0:allow_user_poisoning=1:halt_on_error=1` |
| 2. CMake | `LUAJIT_ENABLE_FSANITIZE=ON`, build `luajit-5.1-gengc` (+`Injector`/`InjectorStub`), `cmake --install` → `Mod/` |
| 2. Deploy | Stage `Mod/libInjector.so` + `Mod/deps/liblua51DS_gengc.so`; game gets **stub only** at `bin64/lib64/libInjector.so` + marker `data/unsafedata/ds_luajit_injector.path` |
| 3. Game | Dedicated server Master/`Cluster_1`, `LD_PRELOAD=libasan:./lib64/libInjector.so` (stub), `lua_vm_type=jit_gen` |

## PASS criteria

### Suite

- All listed tests exit 0
- No `AddressSanitizer:` halt / UAF / poison / double-free
- `asan-suite-summary.txt` shows `fail=0`

Core suite (mirrors T9 ASAN lane):

1. `test/test_gc_adversarial.lua`
2. `test/test_gc_invariants.lua`
3. `test/test_weak_stacks.lua`
4. `test/test_finalizer_order.lua`
5. `test/gc/openuv_vector_v31_assert.lua`
6. `test/gc/openuv_dead_thread_mark_assert.lua`
7. `test/gc/thread_openupval_sweep_assert.lua`
8. `test/gc/thread_permgray_residual_assert.lua`
9. `test/gc/white1_free_assert.lua`
10. `test/gc/udata_finalize_assert.lua`
11. `test/gc/huge_swept_tag_assert.lua`
12. `test/gc/stale_gray_survivor_stress.lua`
13. `test/test_str_rehash_sweep.lua`
14. inline `leaf_mini` (hash resize + step GC churn)

### Game (dedicated server)

| Marker | Required |
|---|---|
| `LOADING LUA SUCCESS` | **yes** |
| `jit_gen` in log | preferred |
| `World generated` | preferred (smoke still PASS without if SUCCESS + clean ASAN) |
| Hard ASAN (`heap-use-after-free`, `heap-buffer-overflow`, `use-after-poison`, `double-free`) | **0** |
| `LuaJIT ASSERT` | **0** |
| `alloc-dealloc-mismatch` | **noise** (Injector C++ vs game malloc) — ignore unless GC frames appear |

Default: stop soon after SUCCESS+World (or `--timeout`, default 300s). Use `--soak N` for N-second post-SUCCESS hold. RSS hard-cap default 8GB.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `GAME_ROOT` | auto from `.vscode/settings.json` / Steam | DST install |
| `ASAN_LIB` | `/usr/lib/x86_64-linux-gnu/libasan.so.8` | ASAN runtime (must be first in `LD_PRELOAD`) |
| `CLUSTER` / `SHARD` | `Cluster_1` / `Master` | server args |
| `LUA_VM_TYPE` | `jit_gen` | forces gengc library |
| `GAME_TIMEOUT_SEC` | `300` | max wall time |
| `RSS_LIMIT_GB` | `8` | kill runaway |

## Agent workflow

1. Run `tools/run_debug_asan.sh` (or suite/game-only as requested).
2. Do **not** hand-rebuild unless the script fails on missing cmake preset.
3. Read `$EVIDENCE/SUMMARY.md` + `game-markers.md` + failing `asan-*.log`.
4. Report PASS/FAIL with evidence paths. Do not claim PASS without SUCCESS + zero hard ASAN.
5. Never `pkill -f` broadly; the script only kills `dontstarve_dedicated_server_nullrenderer_x64` with `Cluster_1`.

## Manual fallback (if script unavailable)

```bash
# Suite
cd luajit
make -C src clean
make -C src -j ASAN=1 XCFLAGS="-DLUAJIT_ENABLE_GCARENA -DLUA_USE_ASSERT"
rm -f src/host/buildvm_arch.h   # avoid shadowing classic cmake buildvm
export ASAN_OPTIONS=detect_leaks=0:allow_user_poisoning=1:halt_on_error=1:exitcode=99
./src/luajit test/test_gc_adversarial.lua
# ... remaining suite files ...

# Package (Mod/ is CMAKE_INSTALL_PREFIX)
cmake -DLUAJIT_ENABLE_FSANITIZE=ON -S . -B builds/ninja-multi-vcpkg
ASAN_OPTIONS=detect_leaks=0 cmake --build builds/ninja-multi-vcpkg --config Debug \
  --target luajit-5.1-gengc Injector InjectorStub
cmake --install builds/ninja-multi-vcpkg --config Debug
# Real: Mod/libInjector.so  VM: Mod/deps/liblua51DS_gengc.so  Stub: Mod/bin64/linux/lib64/libInjector.so
cp -f Mod/bin64/linux/lib64/libInjector.so "$GAME_ROOT/bin64/lib64/libInjector.so"
realpath Mod/libInjector.so > "$GAME_ROOT/data/unsafedata/ds_luajit_injector.path"
# Do NOT copy real Injector or VMs into game bin64

cd "$GAME_ROOT/bin64"
lua_vm_type=jit_gen \
ASAN_OPTIONS='detect_leaks=0:allow_user_poisoning=1:halt_on_error=0:alloc_dealloc_mismatch=0:quarantine_size_mb=32' \
LD_PRELOAD='/usr/lib/x86_64-linux-gnu/libasan.so.8:./lib64/libInjector.so' \
LD_LIBRARY_PATH=./lib64 \
./dontstarve_dedicated_server_nullrenderer_x64 -cluster Cluster_1 -shard Master
```

## Related

- Skill `launch-debug-game` — GDB launch **without** ASAN
- Docs: `docs/gengc-crash-debugging.md`, evidence template `T9-ASAN-game.md`
- CMake option: `LUAJIT_ENABLE_FSANITIZE` (see `luajit/CMakeLists.txt`)
- Makefile: `ASAN=1` (see `luajit/src/Makefile`)

## Notes

- ASAN must be **first** in `LD_PRELOAD`.
- Arena GC keeps its own poison helpers (`lj_asan.h`); do **not** combine suite `ASAN=1` with `LUAJIT_USE_SYSMALLOC` (disables GCARENA).
- Classic `buildvm-default` must not pick stale `luajit/src/host/buildvm_arch.h` left by suite `make` (GCMARK). CMake clears it; the script also `rm -f` before cmake.
- Portable layout: game PRELOAD is the **thin stub**; real Injector + `Mod/deps` stay under the mod package; marker points bootstrap at `Mod/libInjector.so` (`RUNPATH=$ORIGIN/deps`).
- `alloc-dealloc-mismatch` from Injector/`std::string` is pre-existing noise; only hard ASAN categories fail the game lane.
