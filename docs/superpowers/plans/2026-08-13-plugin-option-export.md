# Plugin Option Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package `configuration_options` + per-row `host_gate` is the widget SSOT; bake built-in rows into parent `Mod/modinfo.lua`; bind Host config reads to the owning DST mod.

**Architecture:** Delete package-private `options = { all_of/any_of }`. `package_load` derives the Host rule from `host_gate`. Built-in bake (`tools/bake_plugin_options.lua`) splices src package widgets into a generated region of parent `configuration_options` before `modinfo2cpp`. External marked packs keep the game’s own Mods UI; Host uses `config_modname` and must not call parent `GetModConfigData`.

**Tech Stack:** Lua 5.1 / LuaJIT (`tests/plugin/run_*.py`), Python unittest for identity, CMake custom command, existing `plugin_host_lua` / `plugin_package_load` / `plugin_package_identity` / `plugin_discover_external` CTest names.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-13-plugin-option-export-design.md` (O1–O11)
- Bake input is **only** `src/DontStarveInjector/plugins/plugin_*/modinfo.lua`
- Do **not** mutate `KnownModIndex` or merge external widgets into DontStarveLuaJit2
- Native `ConfigView` stays this-mod cascade (v1)
- C-only without package `modinfo` (`AngleBackend`, `EnableVBPool`) and L0/core.vm/flat Lua stay hand-written on parent
- `eval_option_rule` must AND `all_of` and `any_of` when both present
- Missing `api.config_modname` is fail-fast (no silent parent fallback)
- Leftover package `options` field is fail-fast
- TDD; focused tests under `tests/plugin/`; no project-wide game launch
- Skip formatters / full `ctest` unless a step names a specific `-R` filter

---

## File map

| Path | Responsibility |
|------|----------------|
| `Mod/plugins/package_load.lua` | `derive_option_rule`; reject `options`; require `config_modname`; bind `config_lookup` |
| `Mod/plugins/host.lua` | AND evaluator; per-plugin lookup in `resolve` |
| `Mod/plugins/init.lua` | Pass this-mod `config_modname` |
| `Mod/plugins/discover_external.lua` | Per-pack `config_modname =` enabled folder name |
| `Mod/modmain.lua` | `config_for_mod(modname, key)` via KnownModIndex for foreign mods |
| `src/DontStarveInjector/plugins/plugin_*/modinfo.lua` | Widget SSOT + `host_gate` |
| `Mod/plugins/plugin_*/modinfo.lua` | Byte-identical runtime copy |
| `Mod/modinfo.lua` | Hand-written core + generated region |
| `tools/bake_plugin_options.lua` | Collect / serialize / splice / `--check` |
| `tools/modinfo2cpp.lua` | Skip `section_start` |
| `tools/check_plugin_package_identity.py` | Parse `host_gate`; src vs Mod copy |
| `tests/plugin/plugin_host_lua_spec.lua` | Evaluator AND + per-plugin lookup |
| `tests/plugin/package_load_spec.lua` | Derive / reject / `config_modname` |
| `tests/plugin/discover_external_spec.lua` | Pack `config_modname` forwarded |
| `tests/plugin/bake_plugin_options_spec.lua` + `run_bake_plugin_options.py` | Bake unit tests |
| `tests/plugin/test_plugin_package_identity.py` | `host_gate` fixtures + copy drift |
| `tests/CMakeLists.txt` | `plugin_option_bake_check` |
| `CMakeLists.txt` | Bake before `modinfo2cpp` |
| `docs/plugin-system.md` | D5 revision |

---

### Task 1: Evaluator AND + `derive_option_rule`

**Files:**
- Modify: `Mod/plugins/host.lua` (`eval_option_rule`)
- Modify: `Mod/plugins/package_load.lua` (export `derive_option_rule`)
- Modify: `tests/plugin/plugin_host_lua_spec.lua` (`test_option_rules_unit`)
- Modify: `tests/plugin/package_load_spec.lua` (new derive tests)

**Interfaces:**
- Consumes: existing `PluginHost.evaluate_option_rule(rule, config)`
- Produces: `package_load.derive_option_rule(configuration_options) → { always=true } | { all_of=... } | { any_of=... } | { all_of=..., any_of=... }`
- Evaluator: if both groups present, `(all empty or all on) AND (any empty-table → false; any missing → true; else some on)`

- [ ] **Step 1: Write the failing evaluator tests**

In `tests/plugin/plugin_host_lua_spec.lua`, append inside `test_option_rules_unit` before the final `print`:

```lua
    -- AND semantics (spec O5): both groups
    assert_true(eval({ all_of = { "A" }, any_of = { "B", "C" } }, { A = true, B = true, C = false }), "and both")
    assert_false(eval({ all_of = { "A" }, any_of = { "B", "C" } }, { A = false, B = true }), "and all_of fail")
    assert_false(eval({ all_of = { "A" }, any_of = { "B", "C" } }, { A = true, B = false, C = false }), "and any_of fail")
    assert_true(eval({ all_of = {}, any_of = { "B" } }, { B = true }), "empty all_of + any")
    assert_false(eval({ all_of = { "A" }, any_of = {} }, { A = true }), "empty any_of is false")
```

- [ ] **Step 2: Run host tests — evaluator AND must fail**

Run: `python tests/plugin/run_lua_host.py`

Expected: FAIL on `and both` / early-return after `all_of` (current `eval_option_rule` never sees `any_of` when `all_of` is set).

- [ ] **Step 3: Implement AND in `eval_option_rule`**

Replace the exclusive `if all_of` / `if any_of` blocks in `Mod/plugins/host.lua` with:

```lua
    local has_all = all_of ~= nil
    local has_any = any_of ~= nil
    if has_all or has_any then
        local all_ok = true
        if has_all and #all_of > 0 then
            for i = 1, #all_of do
                if not is_bool_on(config, all_of[i]) then
                    all_ok = false
                    break
                end
            end
        end
        local any_ok = true
        if has_any then
            if #any_of == 0 then
                any_ok = false
            else
                any_ok = false
                for i = 1, #any_of do
                    if is_bool_on(config, any_of[i]) then
                        any_ok = true
                        break
                    end
                end
            end
        end
        return all_ok and any_ok
    end
```

Keep `{ option = "A" }` → `all_of = { rule.option }` **before** this block. Keep `eq`/`neq` after.

- [ ] **Step 4: Re-run host tests**

Run: `python tests/plugin/run_lua_host.py`

Expected: PASS (including new AND cases). Existing `all_of`/`any_of`-only tests unchanged.

- [ ] **Step 5: Write failing `derive_option_rule` tests**

Append to `tests/plugin/package_load_spec.lua` before `print("ALL PASS…")`:

```lua
local function test_derive_option_rule()
    local d = PL.derive_option_rule
    assert_true(type(d) == "function", "derive exported")

    local always = d(nil)
    assert_true(always.always == true, "nil → always")

    local all = d({
        { section_start = true, name = "SECTION_1", label = "S", options = { { description = "", data = "" } }, default = "" },
        { name = "EnableForkSave", host_gate = true, label = "x", options = { { description = "On", data = true } }, default = true },
    })
    assert_true(all.all_of and all.all_of[1] == "EnableForkSave", "host_gate true → all_of")
    assert_true(all.any_of == nil, "no any_of")

    local any = d({
        { name = "EnableProfiler", host_gate = "any_of" },
        { name = "EnableTracy", host_gate = "any_of" },
    })
    assert_true(any.any_of and #any.any_of == 2, "any_of group")
    assert_true(any.all_of == nil, "no all_of")

    local both = d({
        { name = "Need", host_gate = "all_of" },
        { name = "OptA", host_gate = "any_of" },
        { name = "SkipMe" }, -- display only
    })
    assert_true(both.all_of[1] == "Need" and both.any_of[1] == "OptA", "mixed groups")

    local ok, err = pcall(function()
        d({ { name = "X", host_gate = "nope" } })
    end)
    assert_true(not ok and tostring(err):find("host_gate", 1, true), "unknown host_gate")
    print("PASS: derive_option_rule")
end

test_derive_option_rule()
```

- [ ] **Step 6: Run package_load tests — derive missing**

Run: `python tests/plugin/run_package_load.py`

Expected: FAIL `derive exported` (`PL.derive_option_rule` nil).

- [ ] **Step 7: Implement `derive_option_rule` on `package_load`**

In `Mod/plugins/package_load.lua`, add (before `return M`):

```lua
function M.derive_option_rule(configuration_options)
    if type(configuration_options) ~= "table" then
        return { always = true }
    end
    local all_of, any_of = {}, {}
    for i = 1, #configuration_options do
        local row = configuration_options[i]
        if type(row) == "table" and row.section_start ~= true then
            local name = row.name
            if type(name) == "string" and name ~= "" then
                local g = row.host_gate
                if g == true or g == "all_of" then
                    all_of[#all_of + 1] = name
                elseif g == "any_of" then
                    any_of[#any_of + 1] = name
                elseif g ~= nil and g ~= false then
                    error("unknown host_gate: " .. tostring(g), 2)
                end
            end
        end
    end
    if #all_of == 0 and #any_of == 0 then
        return { always = true }
    end
    local rule = {}
    if #all_of > 0 then
        rule.all_of = all_of
    end
    if #any_of > 0 then
        rule.any_of = any_of
    end
    return rule
end
```

- [ ] **Step 8: Re-run package_load + host tests**

Run:

```
python tests/plugin/run_package_load.py
python tests/plugin/run_lua_host.py
```

Expected: both PASS.

- [ ] **Step 9: Commit**

```bash
git add Mod/plugins/host.lua Mod/plugins/package_load.lua tests/plugin/plugin_host_lua_spec.lua tests/plugin/package_load_spec.lua
git commit -m "feat(plugins): derive host_gate and AND all_of+any_of"
```

---

### Task 2: `package_load` cutover + migrate package `modinfo`

**Files:**
- Modify: `Mod/plugins/package_load.lua` (`build_plugin_table`, `load_package_from_root`)
- Modify: every dual-face `src/DontStarveInjector/plugins/plugin_*/modinfo.lua` that currently has `options =`
- Modify: matching `Mod/plugins/plugin_*/modinfo.lua` (byte-identical)
- Modify: `tests/plugin/package_load_spec.lua` (fixtures that set `options = { all_of = … }`)
- Modify: `tests/plugin/plugin_host_lua_spec.lua` (assertions on `plugin.options.all_of` from real packages — they still pass if derive fills `options`)
- Modify: `tools/check_plugin_package_identity.py` parse `host_gate` (so repo identity does not go red mid-cutover)
- Modify: `tests/plugin/test_plugin_package_identity.py` `MODINFO_TEMPLATE`

**Interfaces:**
- Consumes: `M.derive_option_rule` (Task 1)
- Produces: `plugin.options` derived; `plugin.config_modname`; `plugin.configuration_options`
- `load_package_from_root` errors if `env.options ~= nil` or `api.config_modname` missing/empty

Packages to migrate (src + Mod copy):

| stem | host_gate |
|------|-----------|
| `plugin_save_fork` | `EnableForkSave` = true |
| `plugin_sim_lagcomp` | `EnableLagCompensation` = true |
| `plugin_network_rpc` | `NetworkOpt` = true |
| `plugin_network_sim` | `EnableNetSim` = true |
| `plugin_debug_jitterprobe` | `EnableJitterProbe` = true |
| `plugin_client_anim` | `EnableClientAnimOwn` = true |
| `plugin_debug_profiler` | four keys `any_of` |
| `plugin_fps_render` | `TargetRenderFPS` = true |

`plugin_dummy`: no widgets (AlwaysOn). Do not add a fake `options` field.

- [ ] **Step 1: Failing tests for reject + required `config_modname`**

Add to `tests/plugin/package_load_spec.lua`:

```lua
local ENGINE = [[
name = "T"
description = "d"
author = "a"
version = "1.0.0"
api_version = 10
dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true
client_only_mod = false
server_only_mod = false
all_clients_require_mod = false
plugin_id = "t.x"
]]

local function test_reject_obsolete_options()
    local dir = tmp_dir("ds_pkg_obsolete_options")
    write_fixture(dir, "modinfo.lua", ENGINE .. "\noptions = { all_of = { \"EnableForkSave\" } }\n")
    write_fixture(dir, "modmain.lua", "--\n")
    local ok, err = pcall(function()
        return PL.load_package_from_root(dir, "plugin_x", { config_modname = "luajit2" })
    end)
    assert_true(not ok, "expected reject options")
    assert_true(tostring(err):find("options", 1, true), tostring(err))
    print("PASS: reject_obsolete_options")
end

local function test_require_config_modname()
    local dir = tmp_dir("ds_pkg_need_modname")
    write_fixture(dir, "modinfo.lua", ENGINE .. "\n")
    write_fixture(dir, "modmain.lua", "--\n")
    local ok, err = pcall(function()
        return PL.load_package_from_root(dir, "plugin_x")
    end)
    assert_true(not ok, "expected missing config_modname")
    assert_true(tostring(err):find("config_modname", 1, true), tostring(err))
    print("PASS: require_config_modname")
end

local function test_derive_from_configuration_options()
    local dir = tmp_dir("ds_pkg_cfg_opts")
    write_fixture(dir, "modinfo.lua", ENGINE .. [[
configuration_options = {
  { name = "EnableForkSave", label = "F", options = { { description = "On", data = true } }, default = true, host_gate = true },
}
]])
    write_fixture(dir, "modmain.lua", "--\n")
    local plugin = PL.load_package_from_root(dir, "plugin_x", { config_modname = "luajit2" })
    assert_true(plugin.config_modname == "luajit2", "config_modname")
    assert_true(plugin.options and plugin.options.all_of and plugin.options.all_of[1] == "EnableForkSave", "derived all_of")
    print("PASS: derive_from_configuration_options")
end
```

Call them at the bottom. Update **every existing** `load_package_from_root(...)` in this file to pass `{ config_modname = "luajit2" }` (or merge into existing api table). Change the rebind fixture: delete `options = { all_of = { "EnableForkSave" } }`, add a one-row `configuration_options` with `host_gate = true`.

- [ ] **Step 2: Run package_load tests — expect FAIL**

Run: `python tests/plugin/run_package_load.py`

Expected: FAIL (`options` still accepted; `config_modname` not required).

- [ ] **Step 3: Implement load-path checks**

In `load_package_from_root`, after `validate_modinfo`:

```lua
    if rawget(env, "options") ~= nil then
        error("package " .. stem .. " modinfo: obsolete field options; use configuration_options + host_gate", 2)
    end
    if type(api.config_modname) ~= "string" or api.config_modname == "" then
        error("package " .. stem .. " load: missing api.config_modname", 2)
    end
```

In `build_plugin_table`:

```lua
        options = M.derive_option_rule(rawget(env, "configuration_options")),
        configuration_options = rawget(env, "configuration_options"),
        config_modname = api.config_modname,
```

If `type(api.config_for_mod) == "function"`:

```lua
        config_lookup = function(key)
            return api.config_for_mod(api.config_modname, key)
        end,
```

`modmain` env `GetModConfigData`: if `plugin.config_lookup` exists, use it; else existing `api.GetModConfigData` **only when** `config_modname` is this-mod (tests may still pass `GetModConfigData`). Prefer:

```lua
            local get_config = plugin.config_lookup or api.GetModConfigData
```

(`plugin` is the table being built — assign `config_lookup` before `load` closure, or close over locals `cfg_name` / `cfg_for`.)

- [ ] **Step 4: `init.lua` supplies this-mod name**

In `get_api()` return table add:

```lua
        config_modname = (type(env) == "table" and (rawget(env, "modname") or env.modname))
            or rawget(_G, "modname")
            or "DontStarveLuaJit2",
```

Test path without `modname` uses the fallback so `require("plugins.init")` still loads. Production `modmain` sets `modname`.

- [ ] **Step 5: Update identity parser (so cutover does not break the gate)**

In `tools/check_plugin_package_identity.py` `parse_modinfo`:

- If text contains `options\s*=` (Host-private table, not widget `options =` inside a row): still treat as keys for one release? **No** — after this task packages have no private field. Parse:

```python
HOST_GATE_RE = re.compile(
    r"""name\s*=\s*["']([^"']+)["'][\s\S]{0,400}?host_gate\s*=\s*(true|["']all_of["']|["']any_of["'])""",
    re.IGNORECASE,
)
```

Simpler and less fragile: find each `host_gate` assignment and walk backward to the nearest `name = "…"` in the same row. Implement:

```python
def parse_host_gate_keys(text: str) -> tuple[set[str], set[str]]:
    all_of: set[str] = set()
    any_of: set[str] = set()
    for m in re.finditer(r"host_gate\s*=\s*(true|[\"']all_of[\"']|[\"']any_of[\"'])", text):
        kind = m.group(1).strip("'\"")
        before = text[: m.start()]
        names = re.findall(r"""name\s*=\s*["']([^"']+)["']""", before)
        if not names:
            continue
        name = names[-1]
        if kind == "any_of":
            any_of.add(name)
        else:
            all_of.add(name)
    return all_of, any_of
```

`parse_modinfo`: set `option_keys = all_of | any_of`; `option_rule = "any_of"` if any_of else (`"all_of"` if all_of else None).

`check_stem` AllOf/AnyOf compare unchanged (keys set).

Update `MODINFO_TEMPLATE` in `tests/plugin/test_plugin_package_identity.py`:

```python
configuration_options = {{
  {{ name = "{option_key}", label = "X", options = {{ {{ description = "On", data = true }} }}, default = true, host_gate = true }},
}}
```

Delete `options = {{ all_of = {{ "{option_key}" }} }}`.

- [ ] **Step 6: Run identity tests — template change first**

Run: `python tests/plugin/test_plugin_package_identity.py`

Expected: FAIL until parser reads `host_gate`; then PASS.

- [ ] **Step 7: Migrate each package `modinfo.lua` (src then copy to Mod)**

Delete `options = { … }`. Add prelude locals if the file does not already have `translate`/`toggle` (copy the parent helpers). Add `configuration_options`. Keep `when` / `plugin_id` / engine fields.

**`plugin_save_fork`** (also define `disable_by_lua51` like parent, using `LuaVmType` values `"lua51"` and `"game"`):

```lua
configuration_options = {
    {
        name = "EnableForkSave",
        label = translate({ en = "Fork Save (Preview)", zh = "分叉存档" }),
        hover = translate({
            en = "Fork or clone a child process to save the game, reducing save lag. Supported on Linux, macOS, and Windows x64 preview builds.",
            zh = "通过fork或克隆子进程保存游戏,存档不再卡顿.支持Linux、MacOS和Windows x64预览版",
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_lua51,
        host_gate = true,
    },
}
```

**`plugin_sim_lagcomp`:** `EnableLagCompensation`, `host_gate = true`, copy hover/label from parent; `disabled_by` can be an inline table `{ option = "LuaVmType", values = { "lua51", "game" }, reason = … }` plus document non-win in hover (parent used `disable_by_non_win or disable_by_lua51` — bake sentinel cannot OR two identifiers). Use `disable_by_lua51` only in the package; keep `disabled_by = disable_by_non_win` off unless you define both and pick one. Spec: sentinels are identifiers. Prefer **inline rule table** for lagcomp:

```lua
disabled_by = {
    option = "LuaVmType",
    values = { "lua51", "game" },
    reason = translate({ en = "Not compatible with Lua 5.1 VM", zh = "与Lua 5.1虚拟机不兼容" }),
},
```

**`plugin_network_rpc`:** `NetworkOpt`, `host_gate = true`, `disabled_by = disable_by_non_win` (define `local disable_by_non_win = { __bake_ref = "disable_by_non_win" }` **only if bake understands that**). Simpler: define

```lua
local disable_by_non_win = platform_info and not (platform_info.os == "Windows") or false
```

Bake sandbox should inject `platform_info = nil` so this evaluates to `false` at bake time — **wrong**. Inject sentinel userdata/`__bake_ident = "disable_by_non_win"` as the name `disable_by_non_win` in the bake sandbox (Task 4). In the package file, **reference the global/sentinel name** `disable_by_non_win` (do not compute `platform_info` yourself). Host/engine sandbox: parent bake emits the identifier; standalone pack prelude must assign the same local. For src package files used both ways, write:

```lua
local disable_by_non_win = disable_by_non_win
    or (platform_info and not (platform_info.os == "Windows"))
    or false
```

That is messy. **Do this:** package files use a local function-free assignment only when the bake/host sandbox injects the name. Engine KnownModIndex does **not** load src package `modinfo` for built-in. Standalone external pack root is authored by the pack. So src packages may assume bake/Host injects `disable_by_non_win`, `disable_by_lua51`, `disable_by_gen_gc`, `translate`, `toggle`, `AddSection`. Host `make_modinfo_env` **must inject those helpers** in this task (same semantics as parent). Engine-safe: if they are already in `_G`/env, use them; else define locals.

Inject in `make_modinfo_env` (and Task 4 bake sandbox):

```lua
-- disable_by_lua51 / disable_by_gen_gc as tables (real rules)
-- disable_by_non_win as boolean computed if extras.platform_info present, else false
-- translate / toggle / AddSection as in Mod/modinfo.lua
```

Packages then write `disabled_by = disable_by_non_win` and stay engine-safe when those names exist; when engine loads a **pack root** that copied this file, the pack root must include the same prelude. Spec §4.1.

**`plugin_network_sim`:** `EnableNetSim`, `host_gate = true`, `disabled_by = disable_by_non_win`.

**`plugin_debug_jitterprobe`:** `EnableJitterProbe` widget from parent (Disabled/Enabled false/true), `host_gate = true`.

**`plugin_client_anim`:** `EnableClientAnimOwn`, `host_gate = true`, `disabled_by = disable_by_non_win`.

**`plugin_fps_render`:** `TargetRenderFPS` full options list from parent, `host_gate = true`.

**`plugin_debug_profiler`:** four rows, each `host_gate = "any_of"`: `EnableProfiler`, `EnableTracy`, `DisableForceFullGC`, `EnableFrameGC`. Copy labels/hovers/`disabled_by` from parent. `DisableForceFullGC` / `EnableFrameGC` keep `disabled_by = disable_by_gen_gc`.

After editing src, copy the file to `Mod/plugins/<stem>/modinfo.lua` (`Copy-Item` / `cp`). They must match.

- [ ] **Step 8: Run Lua + identity tests**

```
python tests/plugin/run_package_load.py
python tests/plugin/run_lua_host.py
python tests/plugin/test_plugin_package_identity.py
python tools/check_plugin_package_identity.py --source-root .
```

Expected: PASS. Host tests that assert `plugin.options.all_of[1] == "EnableForkSave"` still pass via derive. Profiler test asserts `plugin.options.any_of`.

If a host test `require`s init without `modname`, fallback `DontStarveLuaJit2` keeps load working.

- [ ] **Step 9: Commit**

```bash
git add Mod/plugins/package_load.lua Mod/plugins/init.lua \
  src/DontStarveInjector/plugins/plugin_*/modinfo.lua \
  Mod/plugins/plugin_*/modinfo.lua \
  tests/plugin/package_load_spec.lua tests/plugin/plugin_host_lua_spec.lua \
  tools/check_plugin_package_identity.py tests/plugin/test_plugin_package_identity.py
git commit -m "feat(plugins): configuration_options + host_gate replace options"
```

---

### Task 3: Bind `config_modname` for resolve and external packs

**Files:**
- Modify: `Mod/plugins/host.lua` (`resolve` lookup)
- Modify: `Mod/modmain.lua` (`config_for_mod`, stop single parent `config_lookup`)
- Modify: `Mod/plugins/discover_external.lua` (per-pack api)
- Modify: `tests/plugin/plugin_host_lua_spec.lua`
- Modify: `tests/plugin/discover_external_spec.lua`

**Interfaces:**
- Consumes: `plugin.config_lookup` / `plugin.config_modname` + `gate_ctx.config_for_mod`
- Produces: external faces read pack saved/default; built-in still hits this mod

- [ ] **Step 1: Failing host test — foreign lookup**

```lua
local function test_resolve_uses_plugin_config_lookup()
    local a = fake({
        id = "ext.a",
        options = { all_of = { "PackKey" } },
        config_lookup = function(key)
            if key == "PackKey" then return true end
            return nil
        end,
    })
    local host = PluginHost.new()
    host:register(a)
    -- Parent table has PackKey off; plugin lookup has it on.
    host:resolve({ PackKey = false }, {})
    assert_eq(host:status("ext.a"), STATUS.Registered, "uses plugin lookup not parent")
    print("PASS: resolve_uses_plugin_config_lookup")
end
```

(`fake()` must copy `config_lookup` onto the plugin table — add `config_lookup = opts.config_lookup` in the fake constructor.)

Also test `gate_ctx.config_for_mod`:

```lua
local function test_resolve_config_for_mod()
    local a = fake({ id = "ext.b", options = { all_of = { "K" } }, config_modname = "pack_x" })
    local host = PluginHost.new()
    host:register(a)
    host:resolve({ K = false }, {
        config_for_mod = function(modname, key)
            assert_eq(modname, "pack_x", "modname")
            return key == "K"
        end,
    })
    assert_eq(host:status("ext.b"), STATUS.Registered, "config_for_mod")
    print("PASS: resolve_config_for_mod")
end
```

- [ ] **Step 2: Run host tests — FAIL**

Run: `python tests/plugin/run_lua_host.py`

Expected: FAIL (resolve ignores `config_lookup`).

- [ ] **Step 3: Implement lookup in `PluginHost:resolve`**

```lua
        local lookup = config
        if type(p.config_lookup) == "function" then
            lookup = p.config_lookup
        elseif type(p.config_modname) == "string"
            and type(self.last_ctx) == "table"
            and type(self.last_ctx.config_for_mod) == "function" then
            local modname = p.config_modname
            lookup = function(key)
                return self.last_ctx.config_for_mod(modname, key)
            end
        end
        e.option_enabled = eval_option_rule(options, lookup)
```

- [ ] **Step 4: `discover_external` forwards pack name**

In the loop, do not pass the shared `api` through. Clone and set `config_modname`:

```lua
local pack_api = {}
for k, v in pairs(api) do
    pack_api[k] = v
end
pack_api.config_modname = modname
local plugin, err = try_load_package(pack_api, package_root, stem)
```

Add a unit test in `discover_external_spec.lua`: stub `load_package_from_root` captures `api.config_modname` and asserts it equals the enabled pack folder, not `this_modname`.

- [ ] **Step 5: `modmain` `config_for_mod`**

Replace the single

```lua
local function config_lookup(key)
    return GetModConfigData(key)
end
```

with:

```lua
local function config_for_mod(owning_modname, key)
    if owning_modname == nil or owning_modname == modname then
        return GetModConfigData(key)
    end
    if type(KnownModIndex) ~= "table"
        or type(KnownModIndex.GetModConfigurationOptions_Internal) ~= "function" then
        return nil
    end
    local ok, cfg = pcall(function()
        return KnownModIndex:GetModConfigurationOptions_Internal(owning_modname)
    end)
    if not ok or type(cfg) ~= "table" then
        return nil
    end
    for _, option in pairs(cfg) do
        if type(option) == "table" and option.name == key then
            if option.saved ~= nil then
                return option.saved
            end
            return option.default
        end
    end
    return nil
end
```

Pass `config_for_mod` on `gate_ctx`. Pass `config_for_mod` on discover `api`. Do **not** pass parent `GetModConfigData` as the only resolver for external plugins (may still pass it on api for built-in helpers).

`host:resolve` can keep a parent function as fallback for flat plugins without `config_modname`:

```lua
host:resolve(function(key) return GetModConfigData(key) end, gate_ctx)
```

- [ ] **Step 6: Run tests**

```
python tests/plugin/run_lua_host.py
python tests/plugin/run_discover_external.py
python tests/plugin/run_package_load.py
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Mod/plugins/host.lua Mod/plugins/discover_external.lua Mod/modmain.lua \
  tests/plugin/plugin_host_lua_spec.lua tests/plugin/discover_external_spec.lua
git commit -m "feat(plugins): bind config reads to owning modname"
```

---

### Task 4: Bake collector / serializer / `--check`

**Files:**
- Create: `tools/bake_plugin_options.lua`
- Create: `tests/plugin/bake_plugin_options_spec.lua`
- Create: `tests/plugin/run_bake_plugin_options.py` (copy `run_package_load.py`, point at the new spec)
- Modify: `tests/CMakeLists.txt` (add `plugin_option_bake` test)

**Interfaces:**
- CLI: `luajit tools/bake_plugin_options.lua [--write|--check] [--source-root DIR] [--modinfo PATH] [--plugins-root PATH]`
- Markers (exact):

```lua
    -- BEGIN GENERATED PLUGIN OPTIONS
    -- END GENERATED PLUGIN OPTIONS
```

- Exit 0 `--check` if region matches what `--write` would emit; exit 1 if dirty or missing markers
- `--write` replaces only the interior (keep the two comment lines)

- [ ] **Step 1: Write failing bake spec**

`tests/plugin/bake_plugin_options_spec.lua` drives the tool via `os.execute` of `arg[-1]` / `LUAJIT` / `tools/bake_plugin_options.lua` **or** `dofile` the tool as a module. Prefer exporting a table when `BAKE_PLUGIN_OPTIONS_AS_MODULE=1`:

At bottom of `tools/bake_plugin_options.lua`:

```lua
if os.getenv("BAKE_PLUGIN_OPTIONS_AS_MODULE") == "1" then
    return {
        collect = collect,
        serialize_rows = serialize_rows,
        splice = splice,
        check = check,
        write = write,
    }
end
-- else parse arg and os.exit
```

Spec covers:

1. `serialize_rows` emits `translate({` and `zh =`, not a frozen English string
2. `toggle` sentinel → identifier `toggle`
3. `AddSection` sentinel → `AddSection(...)`
4. `disable_by_non_win` sentinel → identifier
5. `host_gate = true` preserved
6. collision two packages same `name` → `write` errors
7. collision with hand-written `AlwaysEnableMod` → error
8. `splice` is idempotent (second write identical)

Fixture parent:

```lua
configuration_options = {
    { name = "AlwaysEnableMod", label = "A", options = { { description = "On", data = true } }, default = true },
    -- BEGIN GENERATED PLUGIN OPTIONS
    -- END GENERATED PLUGIN OPTIONS
}
```

- [ ] **Step 2: Run bake spec — FAIL (tool missing)**

Run: `python tests/plugin/run_bake_plugin_options.py`

Expected: FAIL cannot load `tools/bake_plugin_options.lua`.

- [ ] **Step 3: Implement the tool**

Sandbox per package `modinfo.lua`:

```lua
local env = {
    folder_name = stem,
    locale = "",
    ChooseTranslationTable = function(t) return t end,
    translate = function(t)
        return { __bake_translate = t }
    end,
    toggle = { __bake_toggle = true },
    AddSection = function(label, hover)
        return { __bake_section = true, label = label, hover = hover }
    end,
    disable_by_non_win = { __bake_ident = "disable_by_non_win" },
    disable_by_lua51 = { __bake_ident = "disable_by_lua51" },
    disable_by_gen_gc = { __bake_ident = "disable_by_gen_gc" },
    platform_info = nil,
}
setmetatable(env, { __index = _G })
```

`collect(plugins_root)`: iterate `plugin_*` directories with `modinfo.lua`, `loadfile`+`setfenv`, skip empty `configuration_options`, sort by `priority` then `plugin_id`.

`serialize_value`:

- `{ __bake_translate = t }` → `translate({ en = %q, zh = %q })` (also emit `zhr`/`zht` only if present in `t`)
- `{ __bake_toggle = true }` → `toggle`
- `{ __bake_section = true }` → `AddSection(<label>, <hover>)`
- `{ __bake_ident = name }` → `name`
- boolean/number/string literals
- widget row: keys in order `name,label,hover,options,default,disabled_by,disabled_value,require_restart,host_gate`

Collision: accumulate `name` set from hand-written block (parse parent Lua by executing it in a similar sandbox **or** scan `name = "…"` outside markers). Fail on duplicate.

`splice(modinfo_text, generated_body)`: find markers; error if missing; replace interior.

`--check`: compute body; compare to current interior (normalize newlines to `\n`).

Default `--source-root` = cwd; `--plugins-root` = `<source-root>/src/DontStarveInjector/plugins`; `--modinfo` = `<source-root>/Mod/modinfo.lua`.

- [ ] **Step 4: Re-run bake spec**

Run: `python tests/plugin/run_bake_plugin_options.py`

Expected: PASS.

- [ ] **Step 5: Register CTest**

In `tests/CMakeLists.txt` next to `plugin_package_load`:

```cmake
add_test(
    NAME plugin_option_bake
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_bake_plugin_options.py
)
set_tests_properties(plugin_option_bake PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
```

- [ ] **Step 6: Commit**

```bash
git add tools/bake_plugin_options.lua tests/plugin/bake_plugin_options_spec.lua \
  tests/plugin/run_bake_plugin_options.py tests/CMakeLists.txt
git commit -m "feat(tools): bake plugin configuration_options into parent modinfo"
```

---

### Task 5: Parent splice + drop hand-written plugin rows + CMake

**Files:**
- Modify: `Mod/modinfo.lua` (markers; delete moved rows)
- Modify: `tools/modinfo2cpp.lua` (skip `section_start`)
- Modify: `CMakeLists.txt` (`create_modinfo_hpp` runs bake then modinfo2cpp)
- Modify: `tests/CMakeLists.txt` (`plugin_option_bake_check` on the real tree)

**Interfaces:**
- After `--write`, generated region contains `NetworkOpt`, `TargetRenderFPS`, `EnableLagCompensation`, `EnableForkSave`, `EnableProfiler`, `EnableTracy`, `DisableForceFullGC`, `EnableFrameGC`, `EnableNetSim`, `EnableJitterProbe`, `EnableClientAnimOwn`
- Hand-written block must **not** still define those names
- `src/modinfo.hpp` still has those constexpr names (modinfo2cpp after bake)

- [ ] **Step 1: Insert markers at end of `configuration_options`**

Before the closing `}` of `configuration_options` in `Mod/modinfo.lua`:

```lua
    -- BEGIN GENERATED PLUGIN OPTIONS
    -- END GENERATED PLUGIN OPTIONS
```

Do not delete rows yet.

- [ ] **Step 2: `--check` on real tree should fail (empty vs packages)**

Run: `luajit tools/bake_plugin_options.lua --check`

Expected: FAIL dirty (or empty interior vs collected rows).

- [ ] **Step 3: `--write` then delete the moved hand-written rows**

Run: `luajit tools/bake_plugin_options.lua --write`

Then remove the original hand-written entries listed in spec §6.6 from **above** the markers. Leave L0/core/flat/C-only. If a section becomes empty (e.g. Network Simulation only had `EnableNetSim`/`EnableJitterProbe`/`EnableClientAnimOwn`), delete that `AddSection` too **or** leave it — prefer delete empty sections.

- [ ] **Step 4: Collision check**

Run: `luajit tools/bake_plugin_options.lua --write` then `--check`

Expected: `--write` succeeds (no name clash). `--check` exit 0.

If clash, a moved row was left in the hand-written block — delete it.

- [ ] **Step 5: Skip sections in `modinfo2cpp.lua`**

After the `missing required fields` check, add:

```lua
    if configuration_option.section_start == true then
        goto continue
    end
```

- [ ] **Step 6: Wire CMake**

Replace the `create_modinfo_hpp` custom command:

```cmake
file(GLOB DS_PLUGIN_MODINFO_LUA
    "${CMAKE_CURRENT_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_*/modinfo.lua")

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/modinfo.hpp
        COMMAND $<TARGET_FILE:${LUAJIT_EXECUTABLE_TARGET}>
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/bake_plugin_options.lua" --write
        COMMAND $<TARGET_FILE:${LUAJIT_EXECUTABLE_TARGET}>
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/modinfo2cpp.lua"
        DEPENDS ${LUAJIT_EXECUTABLE_TARGET}
            ${CMAKE_CURRENT_SOURCE_DIR}/Mod/modinfo.lua
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/modinfo2cpp.lua
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/bake_plugin_options.lua
            ${DS_PLUGIN_MODINFO_LUA}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
```

Add CTest for the real tree:

```cmake
add_test(
    NAME plugin_option_bake_check
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} -c
        "import os,subprocess,sys; from pathlib import Path; r=Path(os.environ['REPO_ROOT']);
sys.exit(subprocess.call(['python', str(r/'tests/plugin/run_bake_plugin_options.py')]))"
)
```

Do **not** use that `-c` blob. Add `tests/plugin/run_bake_check.py`:

```python
# same lua candidate search as run_lua_host.py
# argv: luajit tools/bake_plugin_options.lua --check
# cwd = REPO_ROOT
```

```cmake
add_test(
    NAME plugin_option_bake_check
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_bake_check.py
)
set_tests_properties(plugin_option_bake_check PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
```

- [ ] **Step 7: Regenerate `src/modinfo.hpp` and verify keys**

Run bake `--write` then `luajit tools/modinfo2cpp.lua`.

Grep `src/modinfo.hpp` for `EnableForkSave`, `NetworkOpt`, `EnableJitterProbe`, `TargetRenderFPS`. They must still exist. `SECTION_` constants must not appear.

- [ ] **Step 8: Run focused tests**

```
python tests/plugin/run_bake_plugin_options.py
python tests/plugin/run_bake_check.py
python tests/plugin/run_lua_host.py
python tests/plugin/run_package_load.py
python tools/check_plugin_package_identity.py --source-root .
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add Mod/modinfo.lua src/modinfo.hpp tools/modinfo2cpp.lua CMakeLists.txt \
  tests/CMakeLists.txt tests/plugin/run_bake_check.py
git commit -m "feat(modinfo): bake built-in plugin widgets into parent configuration_options"
```

---

### Task 6: Identity copy-gate + docs

**Files:**
- Modify: `tools/check_plugin_package_identity.py` (src vs `Mod/plugins/<stem>/modinfo.lua` byte compare)
- Modify: `tests/plugin/test_plugin_package_identity.py`
- Modify: `docs/plugin-system.md` (D5 paragraph)
- Modify: `docs/superpowers/specs/2026-08-08-plugin-package-aggregation-design.md` §6.2 pointer

**Interfaces:**
- If both files exist and differ → exit 1
- Native AllOf/AnyOf keys == `host_gate` group (already Task 2)

- [ ] **Step 1: Failing copy-drift test**

```python
    def test_detects_mod_copy_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            _write_package(td)
            dest = td / "Mod" / "plugins" / "plugin_save_fork"
            dest.mkdir(parents=True)
            (dest / "modinfo.lua").write_text("plugin_id = 'nope'\n", encoding="utf-8")
            result = _run(td, "--stem", "plugin_save_fork")
            self.assertNotEqual(result.returncode, 0, msg=result.stdout + result.stderr)
```

- [ ] **Step 2: Run identity tests — FAIL**

Run: `python tests/plugin/test_plugin_package_identity.py`

Expected: FAIL (no copy compare yet).

- [ ] **Step 3: Implement byte compare in `check_stem`**

```python
    installed = source_root / "Mod" / "plugins" / stem / "modinfo.lua"
    if installed.is_file():
        src_bytes = modinfo_path.read_bytes()
        dst_bytes = installed.read_bytes()
        if src_bytes != dst_bytes:
            errors.append(f"{stem}: Mod/plugins/{stem}/modinfo.lua differs from src")
```

- [ ] **Step 4: Run identity on fixtures + repo**

```
python tests/plugin/test_plugin_package_identity.py
python tools/check_plugin_package_identity.py --source-root .
```

Expected: PASS. If repo copies drifted in Task 2/5, copy src → Mod again.

- [ ] **Step 5: Docs**

`docs/plugin-system.md` replace “User-facing config remains `Mod/modinfo.lua` only (D5)” with:

- Author widgets on package `configuration_options` + `host_gate`
- Built-in: `tools/bake_plugin_options.lua` projects into parent
- External: marked pack’s own `modinfo`; Host binds `config_modname`

Package-aggregation spec §6.2: add a note that D5 authoring SSOT moved to `2026-08-13-plugin-option-export-design.md`; parent is the embedded projection.

- [ ] **Step 6: Final verification**

```
python tests/plugin/run_lua_host.py
python tests/plugin/run_package_load.py
python tests/plugin/run_discover_external.py
python tests/plugin/run_bake_plugin_options.py
python tests/plugin/run_bake_check.py
python tests/plugin/test_plugin_package_identity.py
python tools/check_plugin_package_identity.py --source-root .
```

Expected: all PASS.

Grep gate:

```
rg -n "options\\s*=\\s*\\{\\s*all_of" src/DontStarveInjector/plugins Mod/plugins/plugin_*
```

Expected: no package `modinfo.lua` matches (widget row `options = { { description` is fine).

- [ ] **Step 7: Commit**

```bash
git add tools/check_plugin_package_identity.py tests/plugin/test_plugin_package_identity.py \
  docs/plugin-system.md docs/superpowers/specs/2026-08-08-plugin-package-aggregation-design.md
git commit -m "docs+gate: D5 option export and src/Mod modinfo copy check"
```

---

## Self-review

1. **Spec coverage:** O1–O11, bake source=src only, no KnownModIndex inject, config_modname bind, host_gate AND, identity, CMake order, moved key list — each has a task.
2. **Placeholders:** none. Sentinel injection for `disable_by_*` is specified in Task 2 Step 7 + Task 4 sandbox.
3. **Types:** `derive_option_rule` / `config_modname` / `config_for_mod` / `config_lookup` names are consistent across tasks.

---

Plan complete and saved to `docs/superpowers/plans/2026-08-13-plugin-option-export.md`. Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks

**2. Inline Execution** — this session, executing-plans, batch with checkpoints

Which approach?
