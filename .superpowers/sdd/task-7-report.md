# Task 7 Report — S3: Physical move injector / event / optional + include cleanup

## Status
COMPLETE.

## Change
Physical placement of remaining root TUs under module dirs, with root re-export shims for peer-facing headers.

### Moves
| From (plugin_core_vm root) | To |
|---|---|
| `GameLuaModule.cpp` | `injector/GameLuaModule.cpp` |
| `GameInjectorApply.cpp` / `.hpp` | `injector/GameInjectorApply.*` |
| `GameLuaInjectFramework.lua` (+ generated `.c`) | `injector/GameLuaInjectFramework.lua` / `.c` |
| `LuaEvent.hpp` / `LuaEventBus.cpp` | `event/LuaEvent.hpp` / `event/LuaEventBus.cpp` |
| `lua_debugger_helper.cpp` / `.hpp` | `optional/lua_debugger_helper.*` |
| `lua_fake.cpp` | `optional/lua_fake.cpp` |

### Root re-export shims (peer stability)
```cpp
// LuaEvent.hpp
#pragma once
#include "event/LuaEvent.hpp"

// GameInjectorApply.hpp
#pragma once
#include "injector/GameInjectorApply.hpp"

// lua_debugger_helper.hpp
#pragma once
#include "optional/lua_debugger_helper.hpp"
```

`plugin_debug_profiler` continues to include `plugins/plugin_core_vm/LuaEvent.hpp` unchanged.

### Include updates (internal)
- `event/LuaEventBus.cpp` → `#include "event/LuaEvent.hpp"`
- `injector/GameLuaModule.cpp` → `#include "injector/GameInjectorApply.hpp"`
- `optional/lua_debugger_helper.cpp` → `#include "optional/lua_debugger_helper.hpp"`
- `game/GameLuaContext.cpp` embeds `#include "../injector/GameLuaInjectFramework.c"`
- Existing `"LuaEvent.hpp"` / `"lua_debugger_helper.hpp"` includes in `game/*` and `plugin_core_vm.cpp` keep working via root re-exports

### CMake
```cmake
add_custom_command(OUTPUT ${PLUGIN_CORE_VM_DIR}/injector/GameLuaInjectFramework.c
        COMMAND ${PYTHON_EXECUTABLE_NAME} "${PROJECT_SOURCE_DIR}/tools/lua2c.py"
                "${PLUGIN_CORE_VM_DIR}/injector/GameLuaInjectFramework.lua"
                "${PLUGIN_CORE_VM_DIR}/injector/GameLuaInjectFramework.c"
        DEPENDS ${PLUGIN_CORE_VM_DIR}/injector/GameLuaInjectFramework.lua
        WORKING_DIRECTORY ${PLUGIN_CORE_VM_DIR}/injector
)
set(PLUGIN_CORE_VM_INJECTOR_SOURCES
    injector/GameLuaModule.cpp
    injector/GameLuaInjectFramework.c
    injector/GameInjectorApply.cpp
)
set(PLUGIN_CORE_VM_EVENT_SOURCES
    event/LuaEventBus.cpp
)
set(PLUGIN_CORE_VM_OPTIONAL_SOURCES
    optional/lua_debugger_helper.cpp
    optional/lua_fake.cpp
)
```

`src/DontStarveInjector/.gitignore` still ignores `GameLuaInjectFramework.c` by basename (covers nested path).

## Layout after Task 7
```
plugin_core_vm/
  GameLua.hpp / GameLua.def / GameLuaType.hpp / ...   # stable roots
  LuaEvent.hpp                 # re-export → event/
  GameInjectorApply.hpp        # re-export → injector/
  lua_debugger_helper.hpp      # re-export → optional/
  injector/
    GameLuaModule.cpp
    GameInjectorApply.cpp/.hpp
    GameLuaInjectFramework.lua (+ generated .c)
  event/
    LuaEvent.hpp
    LuaEventBus.cpp
  optional/
    lua_debugger_helper.cpp/.hpp
    lua_fake.cpp
  game/                        # already from Tasks 1–6
  io/ signature_load/
```

## External include audit
| Pattern | External consumer | Outcome |
|---|---|---|
| `LuaEvent.hpp` | `plugin_debug_profiler` (`plugins/plugin_core_vm/LuaEvent.hpp`) | Root re-export keeps path |
| `GameInjectorApply.hpp` | only `injector/GameLuaModule.cpp` | No external peer; re-export kept for symmetry |
| `lua_debugger_helper.hpp` | only `game/*` TUs | Root re-export keeps includes |
| `GameLuaModule` / framework | CMake + `GameLuaContext.cpp` embed | Paths updated |

## Verify
Worktree has no dedicated configured build dir. Fallback: `cl /c` key TUs with the MSVC flags from `_verify_cmd.txt`, prepending worktree `-I` roots and isolated `/Fd`.

Generated `injector/GameLuaInjectFramework.c` via `tools/lua2c.py` first.

| TU | rc |
|---|---|
| `event/LuaEventBus.cpp` | 0 |
| `optional/lua_debugger_helper.cpp` | 0 |
| `injector/GameInjectorApply.cpp` | 0 |
| `game/GameLuaContext.cpp` (embeds framework.c) | 0 |

Only pre-existing `LUA_GCCYCLE` macro-redefinition warning. Full `plugin_core_vm` link not run from worktree.

## Commit
`refactor(core.vm): place injector/event/optional modules on disk`

## Concerns
- Full multi-target build (`plugin_core_vm`, `plugin_debug_profiler`, `Injector`) still needs a configured worktree build dir / CI.
- Root re-exports are intentional one-release shims; later cleanup can point peers at `event/` / `optional/` directly.
- `GameLua.def` remains at plugin root (unchanged this task).
