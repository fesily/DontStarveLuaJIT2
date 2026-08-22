# Plugin Package Aggregation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Aggregate dual-face plugins into DST mini-mod package directories (`modinfo.lua` + `modmain.lua` + optional `scripts/` + optional DLL) with engine-compatible modinfo, Host sandbox marker, and native/modinfo identity SSOT gates.

**Architecture:** Package-isomorphic layout under `plugins/plugin_<stem>/`. Lua Host loads packages via thin `package_load` helper (engine-like modinfo sandbox + `ds_luajit_package_host` marker; modmain under `modimport` root rebind). Native loader scans package subdirs. Shared identity SSOT is package `modinfo.lua`; native `PluginManifest` is a projection enforced by CI gate (codegen preferred by end of P4).

**Tech Stack:** C++23, CMake, DynamicPluginLoader, Lua 5.1/LuaJIT (host tests via `tests/plugin/run_lua_host.py`), Python (manifest + identity gate), existing `Mod/plugins/host.lua`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-08-plugin-package-aggregation-design.md` (Approved; commits through `8a2af96`)
- **No nested plugin runtime** — only path rebind + modinfo sandbox helper
- Business Lua uses **game/mod APIs only** (`modimport`, `GetModConfigData`, `Add*PostInit`, …)
- Package `modinfo` must be **DST engine–compatible** (`InitializeModInfo` hard fields + explicit compat/role flags)
- Host injects **`ds_luajit_package_host = true`** (+ path/stem); top-level modinfo must be engine-safe
- **D5:** embedded user UI options remain parent `Mod/modinfo.lua` only
- Dual-face SSOT: `plugin_id` / `version` / option keys in modinfo; native must not drift (identity gate)
- Explicit registry: `load_package` / `load_flat` in `Mod/plugins/init.lua` (no auto-scan)
- Lua-only (`jit.*`, `network.entity`) stay flat this plan
- Clean cutover: delete old flat faces/scripts after each dual-face migrates
- Fail-fast missing engine hard fields / `plugin_id`; bad native DLL still skip (loader isolation)
- Tests: assert-style under `tests/plugin/`; Lua via `plugin_host_lua` / new package_load runner
- Do not FreeLibrary live plugins; sticky unload default

### Load ordering (unchanged phases)

```text
Inject → DynamicPluginLoader (package subdir DLLs) → resolve → EarlyNative
modmain → host.lua + init.lua (load_package/load_flat) → resolve → AfterModMain
  load() → package modmain under modimport rebind
```

---

## File map

| Path | Responsibility |
|------|----------------|
| `Mod/plugins/package_load.lua` | **New.** Engine-like modinfo sandbox, §6.0 validation, `load_package` / `load_flat`, modimport rebind for modmain |
| `Mod/plugins/init.lua` | Switch dual-face entries to `load_package`; keep `load_flat` for Lua-only |
| `Mod/modmain.lua` | Wire package_load into plugin env if needed (prefer package_load self-contained) |
| `src/DontStarveInjector/CMakeLists.txt` | `ds_add_dynamic_plugin` → `plugins/<name>/` output + install; helper to install package Lua |
| `src/DontStarveInjector/core/DynamicPluginLoader.cpp` | Scan `plugin_*/plugin_*.{dll,so,dylib}` |
| `src/DontStarveInjector/plugins/plugin_*/` | Per dual-face: add `modinfo.lua`, `modmain.lua`, move scripts; identity sync |
| `tools/gen_plugins_manifest.py` | Discover package-subdir modules; zip include package Lua |
| `tools/check_plugin_package_identity.py` | **New.** Identity gate: modinfo vs native man.* |
| `tests/plugin/package_load_spec.lua` | **New.** package_load unit tests |
| `tests/plugin/run_package_load.py` | **New.** Runner (mirror `run_lua_host.py`) |
| `tests/plugin/test_dynamic_plugin_loader.cpp` | Package-subdir candidate discovery |
| `tests/plugin/test_gen_plugins_manifest.py` | Package layout + zip Lua members |
| `tests/plugin/test_plugin_package_identity.py` | **New.** Wrapper/ctest for identity script |
| `tests/CMakeLists.txt` | Register new tests |
| `docs/plugin-system.md` | Dual-face = package how-to |
| `Mod/plugins/{save_fork,network_*,…}.lua` | **Delete** after package migrate |
| `Mod/scripts/{fork_save,netsim,lag_compensation}.lua` | **Move into packages**, then delete originals |

**Out of plan file map:** external multi-root discovery, manager whole-package pin UX, Lua-only packaging.

---

### Task 1: package_load helper + unit tests (P0)

**Files:**
- Create: `Mod/plugins/package_load.lua`
- Create: `tests/plugin/package_load_spec.lua`
- Create: `tests/plugin/run_package_load.py`
- Modify: `tests/CMakeLists.txt` (add `plugin_package_load` test like `plugin_host_lua`)

**Interfaces:**
- Produces:
  - `package_load.load_flat(name) → plugin_table | error`
  - `package_load.load_package(stem) → plugin_table | error`
  - `package_load.validate_modinfo(env) → ok, err_string`
  - Marker: `ds_luajit_package_host`, `ds_luajit_package_root`, `ds_luajit_package_stem`
- Consumes: `MODROOT`, `kleiloadlua` (injected by caller env), pure-Lua `loadfile`/`setfenv` in unit tests

- [ ] **Step 1: Write failing Lua tests** in `tests/plugin/package_load_spec.lua`

```lua
-- tests/plugin/package_load_spec.lua
local function repo_root()
    local r = os.getenv("REPO_ROOT")
    if r and #r > 0 then return r:gsub("\\", "/") end
    -- fallback: walk up from arg[0] if needed
    return "."
end

local ROOT = repo_root()
package.path = ROOT .. "/Mod/?.lua;" .. ROOT .. "/Mod/?/init.lua;" .. package.path

local PL = require("plugins.package_load")

local function assert_true(cond, msg)
    if not cond then error(msg or "assert_true failed", 2) end
end

local function write_fixture(dir, name, body)
    local f = assert(io.open(dir .. "/" .. name, "w"))
    f:write(body)
    f:close()
end

local function test_missing_api_version_fails()
    local tmp = os.getenv("TMP") or os.getenv("TEMP") or "/tmp"
    local dir = tmp .. "/ds_pkg_miss_api"
    os.execute('mkdir "' .. dir .. '" 2>nul')
    -- minimal incomplete modinfo
    write_fixture(dir, "modinfo.lua", [[
name = "X"
description = "d"
author = "a"
version = "1.0.0"
-- api_version missing
dst_compatible = true
dont_starve_compatible = false
reign_of_giants_compatible = false
client_only_mod = false
server_only_mod = true
all_clients_require_mod = false
plugin_id = "x.test"
]])
    write_fixture(dir, "modmain.lua", "print('hi')\n")
    local ok, err = pcall(function()
        return PL.load_package_from_root(dir, "plugin_x")
    end)
    assert_true(not ok, "expected fail without api_version")
    assert_true(tostring(err):find("api_version", 1, true), tostring(err))
    print("PASS: missing_api_version_fails")
end

local function test_host_marker_true()
    local tmp = os.getenv("TMP") or os.getenv("TEMP") or "/tmp"
    local dir = tmp .. "/ds_pkg_marker"
    os.execute('mkdir "' .. dir .. '" 2>nul')
    write_fixture(dir, "modinfo.lua", [[
name = "Marker"
description = "d"
author = "a"
version = "1.0.0"
api_version = 10
dst_compatible = true
dont_starve_compatible = false
reign_of_giants_compatible = false
client_only_mod = false
server_only_mod = true
all_clients_require_mod = false
plugin_id = "test.marker"
-- capture marker into a private field for the test via when unused:
_G_TEST_MARKER = ds_luajit_package_host
]])
    write_fixture(dir, "modmain.lua", "-- empty\n")
    -- Prefer package_load exposing last sandbox for tests, or read plugin_id success only.
    local plugin = PL.load_package_from_root(dir, "plugin_test_marker")
    assert_true(plugin.id == "test.marker", "id")
    assert_true(PL.last_modinfo_env and PL.last_modinfo_env.ds_luajit_package_host == true, "marker")
    print("PASS: host_marker_true")
end

local function test_engine_safe_without_marker()
    -- load file with only engine injects; must not error if top-level is data-only
    local chunk = assert(loadstring([[
name = "E"
description = "d"
author = "a"
version = "1.0.0"
api_version = 10
dst_compatible = true
dont_starve_compatible = false
reign_of_giants_compatible = false
client_only_mod = true
server_only_mod = false
all_clients_require_mod = false
plugin_id = "e.safe"
when = function(ctx) return TheNet:IsDedicated() end
]]))
    local env = {
        folder_name = "e",
        locale = "en",
        ChooseTranslationTable = function(t) return t[1] end,
    }
    setfenv(chunk, env)
    chunk()
    assert_true(env.plugin_id == "e.safe", "plugin_id assigned")
    print("PASS: engine_safe_without_marker")
end

local function test_modimport_rebind_on_load()
    local tmp = os.getenv("TMP") or os.getenv("TEMP") or "/tmp"
    local dir = (tmp .. "/ds_pkg_rebind"):gsub("\\", "/")
    os.execute('mkdir "' .. dir .. '" 2>nul')
    os.execute('mkdir "' .. dir .. '/scripts" 2>nul')
    write_fixture(dir, "modinfo.lua", [[
name = "R"
description = "d"
author = "a"
version = "1.0.0"
api_version = 10
dst_compatible = true
dont_starve_compatible = false
reign_of_giants_compatible = false
client_only_mod = false
server_only_mod = true
all_clients_require_mod = false
plugin_id = "test.rebind"
options = { all_of = { "EnableForkSave" } }
priority = 60
phases = "AfterModMain"
]])
    write_fixture(dir, "modmain.lua", [[
modimport("scripts/biz")
]])
    write_fixture(dir .. "/scripts", "biz.lua", [[
_G.BIZ_LOADED = true
]])
    local imported = {}
    local plugin = PL.load_package_from_root(dir, "plugin_test_rebind", {
        modimport = function(name)
            imported[#imported + 1] = name
            local path = dir .. "/" .. name .. ".lua"
            local c = assert(loadfile(path))
            c()
        end,
    })
    plugin.load({})
    assert_true(_G.BIZ_LOADED == true, "biz loaded")
    assert_true(imported[1] == "scripts/biz", "modimport path")
    print("PASS: modimport_rebind_on_load")
end

test_missing_api_version_fails()
test_host_marker_true()
test_engine_safe_without_marker()
test_modimport_rebind_on_load()
print("ALL PASS package_load_spec")
```

- [ ] **Step 2: Add runner** `tests/plugin/run_package_load.py` (copy `run_lua_host.py`, point `SCRIPT` at `package_load_spec.lua`).

- [ ] **Step 3: Register CTest** in `tests/CMakeLists.txt` next to `plugin_host_lua`:

```cmake
add_test(
    NAME plugin_package_load
    COMMAND ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_package_load.py
)
set_tests_properties(plugin_package_load PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    ENVIRONMENT "REPO_ROOT=${CMAKE_SOURCE_DIR}"
)
```

- [ ] **Step 4: Run tests — expect FAIL** (module missing)

```bash
python tests/plugin/run_package_load.py
```

Expected: `module 'plugins.package_load' not found` or similar.

- [ ] **Step 5: Implement `Mod/plugins/package_load.lua`**

Minimum surface (implement fully; no stubs):

```lua
-- Mod/plugins/package_load.lua
-- Thin package loader: DST-like modinfo sandbox + modmain modimport rebind.
-- Not a second PluginHost.

local M = {}
M.last_modinfo_env = nil

local ENGINE_HARD = { "name", "description", "author", "version", "api_version" }
local ENGINE_COMPAT = { "dst_compatible", "dont_starve_compatible", "reign_of_giants_compatible" }
local ENGINE_ROLE = { "client_only_mod", "server_only_mod", "all_clients_require_mod" }

local function is_nil(v) return v == nil end

function M.validate_modinfo(env)
    for _, k in ipairs(ENGINE_HARD) do
        if is_nil(env[k]) then
            return false, "missing engine field: " .. k
        end
    end
    for _, k in ipairs(ENGINE_COMPAT) do
        if is_nil(env[k]) then
            return false, "missing explicit compat field: " .. k
        end
    end
    for _, k in ipairs(ENGINE_ROLE) do
        if is_nil(env[k]) then
            return false, "missing role field: " .. k
        end
    end
    if env.client_only_mod and env.all_clients_require_mod then
        return false, "client_only_mod and all_clients_require_mod are mutually exclusive"
    end
    if is_nil(env.plugin_id) or env.plugin_id == "" then
        return false, "missing plugin_id"
    end
    return true
end

local function default_choose_translation(tbl)
    if type(tbl) ~= "table" then return tbl end
    return tbl[1]
end

local function make_modinfo_env(stem, package_root, extras)
    extras = extras or {}
    local env = {
        folder_name = stem,
        locale = extras.locale or "",
        ChooseTranslationTable = extras.ChooseTranslationTable or default_choose_translation,
        ds_luajit_package_host = true,
        ds_luajit_package_root = package_root,
        ds_luajit_package_stem = stem,
    }
    -- Allow assigning globals into env via setfenv (modinfo style).
    return env
end

local function load_chunk(path, env, loader)
    -- loader: function(path) -> chunk|err string  (kleiloadlua or loadfile)
    local chunk = loader(path)
    if type(chunk) == "string" then
        error(path .. ": " .. chunk, 2)
    end
    if type(chunk) ~= "function" then
        error(path .. ": expected function chunk, got " .. type(chunk), 2)
    end
    setfenv(chunk, env)
    return chunk()
end

local function build_plugin_table(env, package_root, stem, api)
    api = api or {}
    local plugin = {
        id = env.plugin_id,
        version = env.version,
        depends = env.depends or {},
        soft_depends = env.soft_depends or {},
        conflicts = env.conflicts or {},
        phases = env.phases or "AfterModMain",
        options = env.options,
        support_reload = env.support_reload and true or false,
        priority = env.priority or 100,
        when = env.when,
        load = function(ctx)
            local modmain_path = package_root .. "modmain.lua"
            local parent_modimport = api.modimport
            local bound_modimport = function(name)
                -- Prefer package-root relative paths (DST-style scripts/...).
                if parent_modimport then
                    -- Caller may implement join; default: strip leading, join package_root.
                    local rel = name
                    if rel:sub(-4) == ".lua" then
                        rel = rel:sub(1, -5)
                    end
                    -- If api provides package-aware modimport, use it.
                    if api.package_modimport then
                        return api.package_modimport(package_root, rel)
                    end
                    -- Fallback: call parent with package-relative path string for tests.
                    return parent_modimport(rel)
                end
                error("modimport not available in package load")
            end
            local mod_env = setmetatable({
                modimport = bound_modimport,
                MODROOT = package_root, -- package-local for this chunk only
                print = api.print or print,
                GetModConfigData = api.GetModConfigData,
                AddGamePostInit = api.AddGamePostInit or function(fn) fn() end,
            }, { __index = api.parent_env or _G, __newindex = api.parent_env or _G })
            local loader = api.kleiloadlua or function(p)
                local f, err = loadfile(p)
                if not f then return err end
                return f
            end
            load_chunk(modmain_path, mod_env, loader)
        end,
        unload = function(ctx) end,
    }
    return plugin
end

-- Production path uses MODROOT + kleiloadlua from caller env.
function M.load_package(stem, api)
    api = api or {}
    local root = api.MODROOT or error("MODROOT required")
    local package_root = root .. "plugins/" .. stem .. "/"
    return M.load_package_from_root(package_root, stem, api)
end

function M.load_package_from_root(package_root, stem, api)
    api = api or {}
    if package_root:sub(-1) ~= "/" and package_root:sub(-1) ~= "\\" then
        package_root = package_root .. "/"
    end
    package_root = package_root:gsub("\\", "/")
    local env = make_modinfo_env(stem, package_root, api)
    M.last_modinfo_env = env
    local loader = api.kleiloadlua or function(p)
        local f, err = loadfile(p)
        if not f then return err end
        return f
    end
    load_chunk(package_root .. "modinfo.lua", env, loader)
    local ok, err = M.validate_modinfo(env)
    if not ok then
        error("package " .. stem .. " modinfo: " .. err, 2)
    end
    return build_plugin_table(env, package_root, stem, api)
end

function M.load_flat(name, api)
    api = api or {}
    local root = api.MODROOT or error("MODROOT required")
    local path = root .. "plugins/" .. name .. ".lua"
    local loader = api.kleiloadlua or function(p)
        local f, err = loadfile(p)
        if not f then return err end
        return f
    end
    local env = setmetatable({}, { __index = api.parent_env or _G, __newindex = api.parent_env or _G })
    local result = load_chunk(path, env, loader)
    if type(result) ~= "table" then
        error("flat plugin " .. name .. " must return table", 2)
    end
    return result
end

return M
```

Adjust `modimport` joining so production paths match `modimport("scripts/fork_save")` → `package_root .. "scripts/fork_save.lua"` via wrapping parent `_modimport` when available (see Task 2).

- [ ] **Step 6: Run tests — expect PASS**

```bash
python tests/plugin/run_package_load.py
```

Expected: `ALL PASS package_load_spec`

- [ ] **Step 7: Commit**

```bash
git add Mod/plugins/package_load.lua tests/plugin/package_load_spec.lua tests/plugin/run_package_load.py tests/CMakeLists.txt
git commit -m "feat(plugins): package_load helper with DST modinfo sandbox"
```

---

### Task 2: Wire init.lua + modmain env for package_load (P0)

**Files:**
- Modify: `Mod/plugins/init.lua`
- Modify: `Mod/modmain.lua` (plugin_env: expose package_load inputs; keep trunk clean)

**Interfaces:**
- Consumes: `package_load.load_package` / `load_flat`
- Produces: registry list still returned from `init.lua` for `host:register_all`

- [ ] **Step 1: Update `init.lua`** to use package_load without migrating packages yet (dual-face still `load_flat` until Task 5+):

```lua
-- Mod/plugins/init.lua
local function get_api()
    local env = getfenv(1)
    local root = (type(env) == "table" and (rawget(env, "MODROOT") or env.MODROOT)) or rawget(_G, "MODROOT")
    local loadlua = (type(env) == "table" and (rawget(env, "kleiloadlua") or env.kleiloadlua)) or rawget(_G, "kleiloadlua")
    local modimport = (type(env) == "table" and (rawget(env, "modimport") or env.modimport)) or rawget(_G, "modimport")
    return {
        MODROOT = root,
        kleiloadlua = loadlua,
        modimport = modimport,
        parent_env = env,
        GetModConfigData = (type(env) == "table" and env.GetModConfigData) or GetModConfigData,
        AddGamePostInit = (type(env) == "table" and env.AddGamePostInit) or AddGamePostInit,
        print = print,
        package_modimport = function(package_root, rel)
            -- Prefer loading package-local file with kleiloadlua + package env.
            local path = package_root .. rel .. ".lua"
            local chunk = loadlua(path)
            if type(chunk) == "function" then
                setfenv(chunk, env)
                return chunk()
            end
            error("package modimport failed: " .. path .. " " .. tostring(chunk))
        end,
    }
end

local function load_package_load()
    local api = get_api()
    local path = api.MODROOT .. "plugins/package_load.lua"
    local chunk = api.kleiloadlua(path)
    if type(chunk) ~= "function" then
        -- test path
        return require("plugins.package_load")
    end
    setfenv(chunk, getfenv(1))
    return chunk()
end

local R = load_package_load()
local api = get_api()

local function load_flat(name)
    -- Keep existing kleiloadlua path behavior for flat faces during P0.
    local env = getfenv(1)
    local root = api.MODROOT
    local loadlua = api.kleiloadlua
    if root and loadlua then
        local path = root .. "plugins/" .. name .. ".lua"
        local chunk = loadlua(path)
        if type(chunk) == "function" then
            setfenv(chunk, env)
            return chunk()
        end
        error("failed to load plugin " .. path .. ": " .. tostring(chunk))
    end
    return require("plugins." .. name)
end

local function load_package(stem)
    return R.load_package(stem, api)
end

return {
    load_flat("jit_tailcall"),
    load_flat("debug_profiler"),
    load_flat("network_rpc"),
    load_flat("network_entity"),
    load_flat("fps_render"),
    load_flat("save_fork"),
    load_flat("sim_lagcomp"),
    load_flat("network_sim"),
    load_flat("jit_runtime"),
}
```

Note: `load_package` is defined but unused until Task 5 — that is intentional (API ready). Export both for tests if useful.

- [ ] **Step 2: Ensure `modmain` plugin_env still provides `MODROOT` / `kleiloadlua` / `modimport`** (already does). No feature hard-wires.

- [ ] **Step 3: Run existing Lua host + new package_load tests**

```bash
python tests/plugin/run_lua_host.py
python tests/plugin/run_package_load.py
```

Expected: both ALL PASS.

- [ ] **Step 4: Commit**

```bash
git add Mod/plugins/init.lua Mod/modmain.lua
git commit -m "feat(plugins): wire package_load into init registry helpers"
```

---

### Task 3: DynamicPluginLoader package subdirectory scan (P1)

**Files:**
- Modify: `src/DontStarveInjector/core/DynamicPluginLoader.cpp`
- Modify: `tests/plugin/test_dynamic_plugin_loader.cpp`

**Interfaces:**
- `load_directory` accepts:
  - flat `plugins/plugin_*.dll` (migration window)
  - package `plugins/plugin_<stem>/plugin_<stem>.dll` when directory name matches stem

- [ ] **Step 1: Extend unit test** — package subdir bad DLL skipped; noise in package ignored:

```cpp
static void test_package_subdir_bad_library_skipped() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_pkg");
    auto pkg = dir / "plugin_notalib";
    fs::create_directories(pkg);
#if defined(_WIN32)
    auto bad = pkg / "plugin_notalib.dll";
#else
    auto bad = pkg / "plugin_notalib.so";
#endif
    std::ofstream(bad, std::ios::binary) << "not a pe/elf";
    std::ofstream(pkg / "modinfo.lua") << "name='x'\n";
    auto r = loader.load_directory(host, dir);
    assert(r.loaded_modules.empty());
    assert(!r.skipped.empty());
    printf("PASS: package_subdir_bad_library_skipped\n");
}

// In main(): call test_package_subdir_bad_library_skipped();
```

- [ ] **Step 2: Run test — expect FAIL** (subdir not scanned)

```bash
# from build tree
ctest -R plugin_dynamic_loader --output-on-failure
```

- [ ] **Step 3: Implement scan** in `load_directory` loop:

After/alongside flat candidates:

```cpp
// Pseudo — integrate cleanly into existing iterator loop.
// 1) Keep flat is_plugin_candidate(entry) for regular files.
// 2) If entry.is_directory() and filename starts with "plugin_":
//      stem = filename
//      candidate = entry.path() / (stem + extension for platform)
//      if is_regular_file(candidate) → load same as flat path
// Skip if directory name != module stem.
```

Also run `configure_plugin_dll_search` with package dir when loading package DLL so deps resolve from package folder + plugins/deps.

- [ ] **Step 4: Run test — PASS**

- [ ] **Step 5: Commit**

```bash
git add src/DontStarveInjector/core/DynamicPluginLoader.cpp tests/plugin/test_dynamic_plugin_loader.cpp
git commit -m "feat(loader): discover plugin modules under package subdirectories"
```

---

### Task 4: CMake package install layout + Lua resources (P1)

**Files:**
- Modify: `src/DontStarveInjector/CMakeLists.txt` (`ds_add_dynamic_plugin`)
- Modify: each plugin `CMakeLists.txt` as needed via helper
- Optional helper function: `ds_install_plugin_package_lua(name)`

**Interfaces:**
- DLL output: `$<TARGET_FILE_DIR:Injector>/plugins/<name>/<name>.dll`
- Install: `plugins/<name>/`
- Lua: install `modinfo.lua`, `modmain.lua`, `scripts/**` when present in source dir

- [ ] **Step 1: Change `ds_add_dynamic_plugin`**

```cmake
function(ds_add_dynamic_plugin name)
    add_library(${name} MODULE ${ARGN})
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${DONTSTARVEINJECTOR_ROOT}
        ${DONTSTARVEINJECTOR_UTIL_DIR})
    target_compile_features(${name} PRIVATE cxx_std_23)
    target_link_libraries(${name} PRIVATE Injector)
    set_target_properties(${name} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${name}"
        RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
    )
    install(TARGETS ${name}
        RUNTIME DESTINATION plugins/${name} COMPONENT plugins
        LIBRARY DESTINATION plugins/${name} COMPONENT plugins
        ARCHIVE DESTINATION plugins/${name} COMPONENT plugins)

    # Package Lua (optional files)
    set(_pkg_lua_files "")
    foreach(_f IN ITEMS modinfo.lua modmain.lua)
        if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_f}")
            list(APPEND _pkg_lua_files "${CMAKE_CURRENT_SOURCE_DIR}/${_f}")
        endif()
    endforeach()
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/scripts")
        install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/scripts"
            DESTINATION plugins/${name}
            COMPONENT plugins
            FILES_MATCHING PATTERN "*.lua")
    endif()
    if (_pkg_lua_files)
        install(FILES ${_pkg_lua_files}
            DESTINATION plugins/${name}
            COMPONENT plugins)
    endif()
endfunction()
```

- [ ] **Step 2: Build + install smoke**

```bash
cmake --build <build> --config RelWithDebInfo --target plugin_dummy
# confirm: <InjectorDir>/plugins/plugin_dummy/plugin_dummy.dll
```

- [ ] **Step 3: Commit**

```bash
git add src/DontStarveInjector/CMakeLists.txt
git commit -m "build: install dynamic plugins into package subdirectories"
```

---

### Task 5: Identity gate tool (P1)

**Files:**
- Create: `tools/check_plugin_package_identity.py`
- Create: `tests/plugin/test_plugin_package_identity.py`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- CLI: `python tools/check_plugin_package_identity.py --source-root . [--stem plugin_save_fork]`
- Exit 0 if all dual-face packages consistent; 1 on drift
- Checks per stem that has both `modinfo.lua` and `plugin_*.cpp`:
  - `plugin_id` == `man.id`
  - `version` == `man.version`
  - for AllOf/AnyOf natives: option keys set equality with modinfo `options`

- [ ] **Step 1: Write failing test** with temp fixture where id mismatches.

```python
# tests/plugin/test_plugin_package_identity.py (excerpt)
def test_detects_id_drift(self):
    # create temp src tree with modinfo plugin_id=save.fork and man.id="save.other"
    # run script → returncode != 0
```

- [ ] **Step 2: Implement checker**

Parsing strategy (keep simple, deterministic):

- modinfo: run with luajit if available **or** regex:
  - `plugin_id%s*=%s*["']([^"']+)["']`
  - `version%s*=%s*["']([^"']+)["']`
  - `all_of%s*=%s*{%s*["']([^"']+)["']` (extend for multi-key later)
- cpp: existing `man.version = "x"`; `man.id = "x"`; collect `man.options.keys = { ... }`

Dual-face stems list (hardcode MODULE dual-face set from spec):

```python
DUAL_FACE = [
    "plugin_network_rpc",
    "plugin_network_sim",
    "plugin_save_fork",
    "plugin_sim_lagcomp",
    "plugin_debug_profiler",
    "plugin_fps_render",
]
```

Until packages have modinfo, checker **skips** stems without `modinfo.lua` (exit 0) — after Task 6+, they must exist.

- [ ] **Step 3: CTest**

```cmake
add_test(NAME plugin_package_identity
    COMMAND ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_package_identity.py)
```

- [ ] **Step 4: Commit**

```bash
git add tools/check_plugin_package_identity.py tests/plugin/test_plugin_package_identity.py tests/CMakeLists.txt
git commit -m "test: dual-face package identity gate (modinfo vs native)"
```

---

### Task 6: Pilot package `save.fork` (P2)

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_save_fork/modinfo.lua`
- Create: `src/DontStarveInjector/plugins/plugin_save_fork/modmain.lua`
- Move: `Mod/scripts/fork_save.lua` → `src/DontStarveInjector/plugins/plugin_save_fork/scripts/fork_save.lua`
- Modify: `Mod/plugins/init.lua` — `load_package("plugin_save_fork")` instead of `load_flat("save_fork")`
- Delete: `Mod/plugins/save_fork.lua`
- Delete: `Mod/scripts/fork_save.lua` after move
- Ensure CMake install picks scripts (Task 4)
- Native `plugin_save_fork.cpp` identity must match modinfo (hand-sync OK if gate green)

- [ ] **Step 1: Add DST-complete `modinfo.lua`** (copy from spec §6.3 exactly; engine fields + private Host fields).

- [ ] **Step 2: Add `modmain.lua`**

```lua
print("Dedicated server, load fork_save")
AddGamePostInit(function()
    modimport("scripts/fork_save")
end)
```

- [ ] **Step 3: Move business script into package `scripts/fork_save.lua`** (content unchanged).

- [ ] **Step 4: Point init at package; delete old face**

```lua
load_package("plugin_save_fork"),
-- remove load_flat("save_fork")
```

- [ ] **Step 5: Verify identity gate for save.fork**

```bash
python tools/check_plugin_package_identity.py --source-root . --stem plugin_save_fork
```

Expected: exit 0.

- [ ] **Step 6: Build + install package tree**

Confirm:

```text
plugins/plugin_save_fork/plugin_save_fork.dll
plugins/plugin_save_fork/modinfo.lua
plugins/plugin_save_fork/modmain.lua
plugins/plugin_save_fork/scripts/fork_save.lua
```

- [ ] **Step 7: Run unit tests**

```bash
ctest -R "plugin_package_load|plugin_package_identity|plugin_dynamic_loader|plugin_host_lua" --output-on-failure
```

- [ ] **Step 8: L-G present if game available** (`LG_REQUIRE_GAME=1` only when user has game; else SKIP OK)

```bash
python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

- [ ] **Step 9: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_save_fork Mod/plugins/init.lua
git add -u Mod/plugins/save_fork.lua Mod/scripts/fork_save.lua
git commit -m "feat(save.fork): migrate to DST mini-mod package layout"
```

---

### Task 7: Migrate remaining dual-face packages (P3)

**Files per plugin** (same pattern as Task 6):

| stem | face today | scripts today | notes |
|------|------------|---------------|-------|
| `plugin_network_rpc` | `Mod/plugins/network_rpc.lua` | none (inline) | modmain = former load body |
| `plugin_network_sim` | `network_sim.lua` | `Mod/scripts/netsim.lua` | |
| `plugin_sim_lagcomp` | `sim_lagcomp.lua` | `lag_compensation.lua` | |
| `plugin_debug_profiler` | `debug_profiler.lua` | none | AlwaysOn native; modinfo options list Lua keys |
| `plugin_fps_render` | `fps_render.lua` | none | AlwaysOn native |

**Interfaces:** each gets DST-complete modinfo + modmain; init `load_package`; delete old faces; identity gate green.

- [ ] **Step 1: For each stem, create modinfo/modmain from current face table** (engine fields required; map `id`→`plugin_id`, keep options/when/priority).

- [ ] **Step 2: Move scripts if any; update modmain `modimport("scripts/…")`.**

- [ ] **Step 3: Update `init.lua` order** (preserve priority band comments):

```lua
return {
    load_flat("jit_tailcall"),
    load_package("plugin_debug_profiler"),
    load_package("plugin_network_rpc"),
    load_flat("network_entity"),
    load_package("plugin_fps_render"),
    load_package("plugin_save_fork"),
    load_package("plugin_sim_lagcomp"),
    load_package("plugin_network_sim"),
    load_flat("jit_runtime"),
}
```

- [ ] **Step 4: Run identity gate for all dual-face**

```bash
python tools/check_plugin_package_identity.py --source-root .
```

Expected: exit 0.

- [ ] **Step 5: Unit tests + optional L-G**

- [ ] **Step 6: Commit** (one commit per plugin **or** one batch commit if reviewer prefers)

```bash
git commit -m "feat(plugins): migrate remaining dual-face packages to mini-mod layout"
```

---

### Task 8: Manifest zip includes package Lua + docs cutover (P4)

**Files:**
- Modify: `tools/gen_plugins_manifest.py`
- Modify: `tests/plugin/test_gen_plugins_manifest.py`
- Modify: `docs/plugin-system.md`
- Optional: codegen `tools/gen_plugin_identity.py` → `plugin_*_identity.inc` included by cpp (if not done earlier)

- [ ] **Step 1: Update module discovery**

```python
def iter_plugin_modules(plugins_dir: Path) -> list[Path]:
    found: list[Path] = []
    for p in sorted(plugins_dir.iterdir()):
        if is_plugin_module(p):
            found.append(p)
            continue
        if p.is_dir() and p.name.startswith("plugin_"):
            for ext in MODULE_EXTS:
                cand = p / f"{p.name}{ext}"
                if cand.is_file():
                    found.append(cand)
                    break
    return found
```

- [ ] **Step 2: When zipping, include package dir Lua**

```python
pkg_dir = module_path.parent if module_path.parent.name == stem else None
# if package layout:
#   zip arcnames relative to package dir: plugin_x.dll, modinfo.lua, modmain.lua, scripts/...
```

Prefer zip internal layout:

```text
plugin_save_fork.dll
modinfo.lua
modmain.lua
scripts/fork_save.lua
```

(not flat-only DLL).

- [ ] **Step 3: Extend `test_gen_plugins_manifest.py`** with package-subdir fixture + assert zip members include `modinfo.lua`.

- [ ] **Step 4: Update `docs/plugin-system.md`**

Replace dual-face how-to §3.4 with package steps:

1. Create `plugins/plugin_<stem>/` native module
2. Add DST-complete `modinfo.lua` + `modmain.lua` (+ scripts)
3. `init.lua` → `load_package("plugin_<stem>")`
4. Identity gate must pass
5. Do not add flat `Mod/plugins/<face>.lua` for dual-face

- [ ] **Step 5: Grep cutover checks**

```bash
# must not find old dual-face flats
rg -n "load_flat\\(\"(save_fork|network_rpc|network_sim|sim_lagcomp|debug_profiler|fps_render)\"" Mod/plugins/init.lua
# must not exist:
# Mod/plugins/save_fork.lua network_rpc.lua network_sim.lua sim_lagcomp.lua debug_profiler.lua fps_render.lua
# Mod/scripts/fork_save.lua netsim.lua lag_compensation.lua
```

- [ ] **Step 6: Prefer identity codegen (if time in P4)**

Generate header from modinfo:

```cpp
// plugin_save_fork_identity.inc
// AUTO-GENERATED — do not edit
inline constexpr const char *kPluginId = "save.fork";
inline constexpr const char *kPluginVersion = "1.0.0";
```

Native ctor uses constants. Document regen command in plugin-system.md.

- [ ] **Step 7: Full verification**

```bash
ctest -R "plugin_" --output-on-failure
python tools/check_plugin_package_identity.py --source-root .
python tools/gen_plugins_manifest.py --help  # sanity
```

- [ ] **Step 8: Commit**

```bash
git add tools/gen_plugins_manifest.py tools/check_plugin_package_identity.py tests/plugin docs/plugin-system.md
git commit -m "docs+tools: package layout manifest zips and dual-face checklist"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| Package dir layout modinfo+modmain+scripts+DLL | 4, 6, 7 |
| DST engine hard fields + explicit compat/role | 1, 6, 7 |
| `ds_luajit_package_host` sandbox inject | 1, 2 |
| Engine-safe top-level modinfo | 1, 6 |
| modimport rebind for modmain | 1, 2, 6 |
| Explicit init registry | 2, 6, 7 |
| Loader package subdir | 3 |
| CMake install package | 4 |
| Identity SSOT + gate | 5, 6, 7, 8 |
| Manifest zip package Lua | 8 |
| Delete old flats | 6, 7 |
| Docs | 8 |
| Lua-only flat retained | 2, 7 |
| No nested runtime | 1 (design) |
| Tests §13 | 1, 3, 5, 6, 7, 8 |

## Non-goals (do not implement in this plan)

- Auto-scan packages into registry
- Merge C++/Lua Host
- External multi-root loader
- Manager pin UX for whole mini-mod
- Packaging `jit.*` / `network.entity`

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-08-plugin-package-aggregation.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?
