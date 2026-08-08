# External Plugin Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover **enabled** DST mods marked `luajit_plugin_pack=true`, register their package DLLs into C `PluginHost` only after a modinfo trust gate, register Lua faces via discovery, and block silent client enable with a confirm dialog.

**Architecture:** Dual-phase symmetric discovery. C (`Inject` / `DynamicPluginLoader::load_all`) enumerates enabled mods from game enablement files, parses each mod’s `modinfo.lua` in a sandbox, and LoadLibrary’s `plugins/plugin_<stem>/plugin_<stem>.*` only if the trust gate passes. Lua (`modmain`) walks `KnownModIndex` enabled lists with the same marker rules and `load_package_from_root`. Client mods UI hooks enable path to require confirm/cancel for marked external packs. This mod’s own `plugins/` remains marker-exempt.

**Tech Stack:** C++23, sol2 (light modinfo parse), existing `DynamicPluginLoader` / `PluginPath`, Lua 5.1/LuaJIT host tests, DST Redux `ModsTab` / `PopupDialogScreen`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-08-external-plugin-discovery-design.md` (E1–E10)
- Package layout: `docs/superpowers/specs/2026-08-08-plugin-package-aggregation-design.md`
- **Only currently enabled** DST mods for external discovery
- Marker: `luajit_plugin_pack = true`
- **This mod marker-exempt**; external requires non-empty `plugin_id`
- **C: modinfo trust gate before any LoadLibrary** (no export-probe trust)
- Path jail: module path under `mod_root`; shape `plugins/plugin_<stem>/plugin_<stem>.{dll,so,dylib}`
- Fail-soft: bad external packs skip + log; never abort L0 inject
- Built-in loads first; duplicate `plugin_id` → skip later
- Client enable: **modal confirm before enable**; Cancel keeps disabled; v1 always prompt
- No nested plugin runtime; no FreeLibrary hot-unload
- TDD; tests under `tests/plugin/`; focused commits

---

## File map

| Path | Responsibility |
|------|----------------|
| `src/DontStarveInjector/core/PluginPackModinfo.hpp/.cpp` | Light sandbox parse of modinfo → pack flag + plugin_id |
| `src/DontStarveInjector/core/EnabledDstMods.hpp/.cpp` | Enumerate enabled mod names + resolve filesystem roots |
| `src/DontStarveInjector/core/ExternalPluginDiscovery.hpp/.cpp` | Trust gate + scan packages under external mod roots |
| `src/DontStarveInjector/core/DynamicPluginLoader.cpp` | Call external discovery after built-in `load_directory` roots |
| `src/DontStarveInjector/core/PluginPath.*` | Reuse workshop/local mod root bases if needed |
| `Mod/plugins/discover_external.lua` | Lua enabled-mod scan + `load_package_from_root` |
| `Mod/modmain.lua` | Wire discover_external into registry before `register_all` |
| `Mod/scripts/luajit_plugin_pack_enable_warn.lua` (or plugins/) | Client ModsTab enable confirm hook |
| `tests/plugin/test_plugin_pack_modinfo.cpp` | Trust parse unit tests |
| `tests/plugin/test_enabled_dst_mods.cpp` | Enable list parse fixtures |
| `tests/plugin/test_external_plugin_discovery.cpp` | Path jail + gate + no LoadLibrary without trust |
| `tests/plugin/discover_external_spec.lua` | Lua discovery unit tests |
| `tests/plugin/run_discover_external.py` | Runner |
| `tests/CMakeLists.txt` | Register new tests |
| `docs/plugin-system.md` | External pack authoring + enable warning |

---

### Task 1: parse_plugin_pack_modinfo + trust fields (D0)

**Files:**
- Create: `src/DontStarveInjector/core/PluginPackModinfo.hpp`
- Create: `src/DontStarveInjector/core/PluginPackModinfo.cpp`
- Create: `tests/plugin/test_plugin_pack_modinfo.cpp`
- Modify: `tests/CMakeLists.txt` (link sol2/Injector core pieces like other plugin tests)
- Modify: `src/DontStarveInjector/CMakeLists.txt` if core sources need listing for Injector target

**Interfaces:**
- Produces:

```cpp
namespace ds::plugin {
struct PluginPackModinfo {
    bool ok = false;
    bool luajit_plugin_pack = false;
    std::string plugin_id;
    std::string parse_error;
};
// Sandbox-executes modinfo.lua at path. Never LoadLibrary.
PluginPackModinfo parse_plugin_pack_modinfo(const std::filesystem::path &modinfo_path);
bool external_pack_trust_ok(const PluginPackModinfo &info); // pack && !plugin_id.empty() && ok
}
```

- [ ] **Step 1: Write failing tests** in `test_plugin_pack_modinfo.cpp`

```cpp
// Fixture writes temp modinfo.lua files then asserts:
// - missing file → ok=false
// - no luajit_plugin_pack → ok=true, pack=false
// - pack=true without plugin_id → external_pack_trust_ok false
// - pack=true plugin_id="vendor.x" → trust true
// - throw in modinfo → ok=false
// - top-level TheNet call should not be required; if present and errors, ok=false
```

- [ ] **Step 2: Run test — expect FAIL** (missing symbols)

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_plugin_pack_modinfo
# or add_executable then ctest -R plugin_pack_modinfo
```

- [ ] **Step 3: Implement parse with sol2**

```cpp
// PluginPackModinfo.cpp sketch
PluginPackModinfo parse_plugin_pack_modinfo(const std::filesystem::path &modinfo_path) {
    PluginPackModinfo out;
    std::ifstream in(modinfo_path);
    if (!in) { out.parse_error = "open_failed"; return out; }
    std::string content{std::istreambuf_iterator<char>{in}, {}};
    sol::state lua;
    lua.open_libraries(sol::lib::base); // minimal; avoid os/io if possible
    sol::environment env(lua, sol::create);
    env["folder_name"] = modinfo_path.parent_path().filename().string();
    env["locale"] = "";
    env["ChooseTranslationTable"] = [](sol::table t) { return t[1]; };
    // setfenv-style: script in env
    try {
        auto result = lua.safe_script(content, env);
        (void)result;
        out.ok = true;
        if (env["luajit_plugin_pack"].valid())
            out.luajit_plugin_pack = env["luajit_plugin_pack"].get_or(false);
        if (env["plugin_id"].valid() && env["plugin_id"].get_type() == sol::type::string)
            out.plugin_id = env["plugin_id"].get<std::string>();
    } catch (const std::exception &e) {
        out.ok = false;
        out.parse_error = e.what();
    }
    return out;
}
bool external_pack_trust_ok(const PluginPackModinfo &info) {
    return info.ok && info.luajit_plugin_pack && !info.plugin_id.empty();
}
```

Wire source into Injector static lib / existing core compilation unit list used by tests (`DS_PLUGIN_HOST_STATIC` pattern from `test_plugin_path`).

- [ ] **Step 4: Run tests — PASS**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(plugins): parse luajit plugin pack modinfo for trust gate"
```

---

### Task 2: Path jail + package module candidates (D0)

**Files:**
- Create/extend: `src/DontStarveInjector/core/ExternalPluginDiscovery.hpp/.cpp`
- Create: `tests/plugin/test_external_plugin_discovery.cpp`

**Interfaces:**
- Produces:

```cpp
bool path_under_root(const std::filesystem::path &root,
                     const std::filesystem::path &candidate);
// Returns absolute module paths under mod_root/plugins/plugin_*/plugin_*.{ext}
std::vector<std::filesystem::path>
list_pack_modules_under_mod(const std::filesystem::path &mod_root);
```

- [ ] **Step 1: Tests**

```cpp
// temp tree:
//   mod/plugins/plugin_x/plugin_x.dll (empty file ok for path tests)
//   mod/plugins/plugin_x/../../../evil.dll  (construct escaped path)
// assert list only contains jail-ok package modules
// assert path_under_root rejects escape
```

- [ ] **Step 2: RED → implement → GREEN**

```cpp
bool path_under_root(const std::filesystem::path &root,
                     const std::filesystem::path &candidate) {
    std::error_code ec;
    auto r = std::filesystem::weakly_canonical(root, ec);
    auto c = std::filesystem::weakly_canonical(candidate, ec);
    if (ec) return false;
    auto rs = r.generic_string();
    auto cs = c.generic_string();
    if (rs.back() != '/') rs.push_back('/');
    return cs == r.generic_string() || cs.rfind(rs, 0) == 0;
}
```

Package listing: directory_iterator on `mod_root/plugins`, directories starting with `plugin_`, file `stem+ext` exists, `path_under_root`.

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(plugins): path jail and package module listing for external packs"
```

---

### Task 3: Enumerate enabled DST mods — server modoverrides first (D1)

**Files:**
- Create: `src/DontStarveInjector/core/EnabledDstMods.hpp/.cpp`
- Create: `tests/plugin/test_enabled_dst_mods.cpp`
- Reuse path helpers: `GetServerModOverridesPaths` / `GameInfo` from `config/path/ConfigPaths.*` if already linked into Injector

**Interfaces:**
- Produces:

```cpp
struct EnabledDstMod {
    std::string name; // folder or workshop- id as game uses
    std::filesystem::path root;
};
// Role: is_client true → client sources; false → server sources.
std::vector<EnabledDstMod> enumerate_enabled_dst_mods(bool is_client);
```

**Server parse (pin format for tests):**

DST `modoverrides.lua` typically returns:

```lua
return {
  ["workshop-123"] = { enabled = true, configuration_options = { ... } },
  ["localmod"] = { enabled = false },
}
```

- [ ] **Step 1: Fixture test** writes temp `modoverrides.lua` with enabled/disabled entries; parser returns only enabled names.

- [ ] **Step 2: Implement** `parse_modoverrides_enabled_names(path) → vector<string>` using sol (plain file script like `load_plain_lua_table`).

- [ ] **Step 3: Resolve roots** using same bases as `PluginPath` workshop/local (`mods/`, UGC). Unresolved → omit + log.

- [ ] **Step 4: Client v1**  
  - Parse `mods/modsettings.lua` if present (best-effort; force-enable list).  
  - If client enabled-list file format is unclear, implement **server path fully** and client:  
    - `modsettings.lua` force enables +  
    - optional env `DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS` (path list) **only as test seam**, not as product bypass of enablement.  
  - Document any client gap in test comments; do not invent wrong formats.

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(plugins): enumerate enabled DST mods for external discovery"
```

---

### Task 4: Wire external discovery into DynamicPluginLoader (D2)

**Files:**
- Modify: `src/DontStarveInjector/core/DynamicPluginLoader.cpp` (`load_all`)
- Modify: `src/DontStarveInjector/core/ExternalPluginDiscovery.cpp` (orchestrator)
- Modify: `tests/plugin/test_external_plugin_discovery.cpp` or loader tests
- Pass `is_client` from Inject path (already known in `DontStarveInjector.cpp`)

**Interfaces:**
- Produces:

```cpp
// Loads external modules into host; returns counts for logging.
struct ExternalDiscoverReport {
    size_t mods_seen = 0;
    size_t mods_accepted = 0;
    size_t modules_loaded = 0;
    std::vector<std::string> skipped;
};
ExternalDiscoverReport
discover_and_load_external_plugins(PluginHost &host, bool is_client,
                                   const std::filesystem::path &this_mod_root,
                                   const std::unordered_set<std::string> &already_loaded_ids);
```

**Trust order (must match spec):**

```text
for mod in enumerate_enabled_dst_mods(is_client):
  if same as this_mod_root: continue
  info = parse_plugin_pack_modinfo(mod.root / "modinfo.lua")
  if !external_pack_trust_ok(info): skip log
  for module_path in list_pack_modules_under_mod(mod.root):
    if !path_under_root: skip
    LoadLibrary + ds_plugin_module_init  // existing loader helpers
    // if plugin registers id already present: Host behavior / skip log duplicate
```

- [ ] **Step 1: Unit test with mock**  
  Prefer testing orchestrator with **injectable** function pointers or a test-only `load_module_fn` that records paths **without** real LoadLibrary. Assert:
  - unmarked mod → zero loads
  - disabled (not in enumerate list) → zero loads  
  - marked+id → load_module called with package path only after parse

- [ ] **Step 2: Integrate `load_all`**

```cpp
// After existing directory scans:
auto this_mod_plugins = /* first mod-local plugins dir if any */;
auto this_mod_root = mod_root_from_plugins_dir(this_mod_plugins);
// is_client: add parameter to load_all(PluginHost&, bool is_client) and update call site in DontStarveInjector.cpp
discover_and_load_external_plugins(host, is_client, this_mod_root, /*registered ids optional*/);
```

- [ ] **Step 3: Logging** `[plugin-discover] ...` per spec §12

- [ ] **Step 4: Build Injector + run unit tests**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(loader): load external plugin packs after modinfo trust gate"
```

---

### Task 5: Lua discover_external + modmain wire (D3)

**Files:**
- Create: `Mod/plugins/discover_external.lua`
- Modify: `Mod/modmain.lua` (plugin host block)
- Create: `tests/plugin/discover_external_spec.lua`
- Create: `tests/plugin/run_discover_external.py`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Produces: `discover_external.run(api) → { plugin_table, ... }`

```lua
-- discover_external.lua
local M = {}
function M.run(api)
    -- api: MODROOT, kleiloadlua, package_load module, this_modname, is_client
    local out = {}
    local names = {}
    if api.is_client then
        -- KnownModIndex:GetClientModNames() / GetClientModNamesTable()
    else
        -- GetServerModNames() / GetEnabledServerModNames() as available
    end
    for _, modname in ipairs(names) do
        if modname == api.this_modname then goto continue end
        if not KnownModIndex:IsModEnabled(modname) then goto continue end
        local info = KnownModIndex:GetModInfo(modname)
        if not info or not info.luajit_plugin_pack then goto continue end
        if type(info.plugin_id) ~= "string" or info.plugin_id == "" then
            print("[luajit][plugin-discover] skip", modname, "missing_plugin_id")
            goto continue
        end
        local mod_root = api.mod_root_for(modname) -- MODS_ROOT..modname.."/" or softresolvefilepath
        -- for each package dir with modinfo.lua:
        local p = api.package_load.load_package_from_root(package_root, stem, api)
        out[#out+1] = p
        ::continue::
    end
    return out
end
return M
```

Use compatible Lua 5.1 control flow if `goto` undesirable: nested ifs.

- [ ] **Step 1: Unit tests** with fake `KnownModIndex` and temp directories on `package.path` / mock `load_package_from_root` recording calls.

- [ ] **Step 2: Wire modmain** after `registry = run_mod_chunk("plugins/init.lua")`:

```lua
local discover = run_mod_chunk("plugins/discover_external.lua")
local external = discover.run({ ... }) or {}
for i = 1, #external do registry[#registry+1] = external[i] end
host:register_all(registry)
```

- [ ] **Step 3: Run** `run_discover_external.py` + `run_lua_host.py` + `run_package_load.py`

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(plugins): Lua discovery of enabled external plugin packs"
```

---

### Task 6: Client enable-time warning (D4)

**Files:**
- Create: `Mod/scripts/luajit_plugin_pack_enable_warn.lua` (or `Mod/plugins/enable_warn.lua` loaded from modmain client-only)
- Modify: `Mod/modmain.lua` — only when client / `TheFrontEnd` path

**Behavior (pin):**

Hook `ModsTab.EnableCurrent` (redux widget) **before** enable when transitioning disabled → enabled:

```lua
-- Pseudocode
local old = ModsTab.EnableCurrent
function ModsTab:EnableCurrent(widget_idx)
    local modname = -- same resolution as original from widget_idx / current selection
    local info = KnownModIndex:GetModInfo(modname)
    local enabling = not KnownModIndex:IsModEnabled(modname)
    if enabling and info and info.luajit_plugin_pack and modname ~= THIS_MODNAME then
        local PopupDialogScreen = require "screens/redux/popupdialog"
        TheFrontEnd:PushScreen(PopupDialogScreen(
            title_zh_en,
            body_native_code_warning_zh_en,
            {
                { text = OK_ENABLE, cb = function()
                    TheFrontEnd:PopScreen()
                    old(self, widget_idx)
                end },
                { text = CANCEL, cb = function()
                    TheFrontEnd:PopScreen()
                    -- do not call old; remains disabled
                end },
            }
        ))
        return
    end
    return old(self, widget_idx)
end
```

Also cover **ModsScreen** non-redux path if still used (`screens/modsscreen.lua` / `screens/redux/modsscreen.lua`) — grep `EnableCurrent` / `OnConfirmEnable` and hook the single choke point that actually calls `KnownModIndex:Enable`.

Copy requirements:
- zh + en
- Must mention **native code / DLL** risk and trust

- [ ] **Step 1: Manual test checklist** in report (FrontEnd hard to automate):  
  1. Place dummy external mod with `luajit_plugin_pack=true`  
  2. Enable → dialog  
  3. Cancel → still disabled  
  4. Confirm → enabled  

- [ ] **Step 2: Optional unit** — extract pure function `should_warn_enable(modname, info, this_mod)` tested in Lua.

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(ui): confirm before enabling external luajit plugin packs"
```

---

### Task 7: Docs + example skeleton + security negatives (D5)

**Files:**
- Modify: `docs/plugin-system.md` — new section “External plugin packs”
- Create: `docs/examples/external_plugin_pack/` **or** `tests/fixtures/external_pack_mod/` with sample `modinfo.lua` (marker + plugin_id) + empty package layout README
- Extend tests for “evil.dll only” and “disabled mod with valid pack files”

- [ ] **Step 1: Docs** — author checklist:

```text
1. Normal DST mod with modinfo
2. luajit_plugin_pack = true
3. plugin_id = "..."
4. plugins/plugin_foo/plugin_foo.dll (+ optional modmain)
5. User must enable mod; client sees warning
```

- [ ] **Step 2: Negative tests** already partially in Tasks 1–4 — add any missing security cases from spec §13

- [ ] **Step 3: Commit**

```bash
git commit -m "docs: external plugin pack discovery and enable warning"
```

---

## Spec coverage

| Spec | Task |
|------|------|
| Enabled-only external | 3, 4, 5 |
| `luajit_plugin_pack` + this mod exempt | 1, 4, 5 |
| External `plugin_id` required | 1, 4, 5 |
| Trust before LoadLibrary | 1, 4 |
| Path jail + package shape | 2, 4 |
| Dual-phase C + Lua | 4, 5 |
| Client enable confirm | 6 |
| Logging | 4, 5, 6 |
| Tests §13 | 1–7 |
| Docs | 7 |

## Non-goals (do not implement)

- sha256 module allowlist  
- don’t-show-again for warning  
- Manager UI for external packs  
- Full client enable-file parity if format unknown (document gap; server path required)

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-08-external-plugin-discovery.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?
