# Task 3 report — SunModel math + unit tests

**Worktree:** `.worktrees/render-shadow`  
**Branch:** `feature/render-shadow`  
**Commit:** `feat(shadow): SunModel math + unit tests`

## Deliverables

| Path | Role |
|------|------|
| `src/DontStarveInjector/plugins/plugin_render_shadow/SunModel.hpp` | `ds::shadow` API: `Phase`, `SunSample`, `Evaluate` / `Publish` / `LoadPublished` |
| `src/DontStarveInjector/plugins/plugin_render_shadow/SunModel.cpp` | Terminus-like yaw/length math + lock-free snapshot |
| `tests/plugin/test_sun_model.cpp` | Plan Step 1 assertions (copied exactly) |
| `tests/CMakeLists.txt` | `test_sun_model` next to `test_config_schema` |
| `src/DontStarveInjector/plugins/plugin_render_shadow/CMakeLists.txt` | `SunModel.cpp` added to plugin sources |

No `GenerateVBHook.*`.

## Geometry

- Day: `leg = 2*(progress-0.5)`, `yaw = atan2f(leg, 0.8)`, `length_scale = hypotf(leg,0.8)/0.8 * boost`, always visible. Noon (`progress=0.5`) is shortest.
- Dusk: fixed `atan2f(1, 0.8)` / `hypotf(1,0.8)/0.8 * boost`; `visible = progress < 0.99`.
- Night: hidden unless `fullmoon`; fullmoon reuses the day curve on `progress`.
- Progress conceptually clamped to `[0,1]`; boost assumed pre-clamped.
- Publish/Load: three `std::atomic<uint32_t>` (yaw bits, length bits, visible) with release/acquire.

## Verification

TDD:

1. Test + header only → `clang++` link fail: undefined `Evaluate` / `Publish` / `LoadPublished`.
2. Implemented `SunModel.cpp`.
3. `clang++ -std=c++23 -I …/plugin_render_shadow tests/plugin/test_sun_model.cpp …/SunModel.cpp`
4. `cmd.exe /c tests\plugin\test_sun_model.exe` → `test_sun_model OK`

CMake preset build **not available** in this worktree:

- `cmake --build --preset ninja-vcpkg-release-dbg --target test_sun_model` → `builds/ninja-multi-vcpkg is not a directory`.
- Same gap as Task 2 (empty worktree `vcpkg/`, no configure). Sources are wired for when the tree is configured.

Standalone compile used only for this unit test; binary not committed.
