-- tests/plugin/package_load_spec.lua
-- Pure-Lua package_load tests: DST-like modinfo sandbox + modimport rebind.
-- Runner: tests/plugin/run_package_load.py

local function repo_root()
    local from_env = os.getenv("REPO_ROOT")
    if from_env and from_env ~= "" then
        return from_env:gsub("\\", "/")
    end
    local src = debug.getinfo(1, "S").source
    if src:sub(1, 1) == "@" then
        src = src:sub(2)
    end
    src = src:gsub("\\", "/")
    local dir = src:match("^(.*)/[^/]+$") or "."
    local root = dir:match("^(.*)/tests/plugin$") or (dir .. "/../..")
    return root
end

local ROOT = repo_root()
package.path = ROOT .. "/Mod/?.lua;" .. ROOT .. "/Mod/?/init.lua;" .. package.path

local PL = require("plugins.package_load")

local load_string = loadstring or load

local function assert_true(cond, msg)
    if not cond then error(msg or "assert_true failed", 2) end
end

local function ensure_dir(dir)
    dir = dir:gsub("\\", "/")
    if package.config:sub(1, 1) == "\\" then
        os.execute('mkdir "' .. dir:gsub("/", "\\") .. '" 2>nul')
    else
        os.execute('mkdir -p "' .. dir .. '" 2>/dev/null')
    end
end

local function write_fixture(dir, name, body)
    dir = dir:gsub("\\", "/")
    ensure_dir(dir)
    local f = assert(io.open(dir .. "/" .. name, "w"))
    f:write(body)
    f:close()
end

local function tmp_dir(name)
    local tmp = os.getenv("TMP") or os.getenv("TEMP") or "/tmp"
    local dir = (tmp .. "/" .. name):gsub("\\", "/")
    ensure_dir(dir)
    return dir
end

local function test_missing_api_version_fails()
    local dir = tmp_dir("ds_pkg_miss_api")
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
    local dir = tmp_dir("ds_pkg_marker")
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
    local plugin = PL.load_package_from_root(dir, "plugin_test_marker")
    assert_true(plugin.id == "test.marker", "id")
    assert_true(PL.last_modinfo_env and PL.last_modinfo_env.ds_luajit_package_host == true, "marker")
    print("PASS: host_marker_true")
end

local function test_engine_safe_without_marker()
    -- load file with only engine injects; must not error if top-level is data-only
    local chunk = assert(load_string([[
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
    local dir = tmp_dir("ds_pkg_rebind")
    ensure_dir(dir .. "/scripts")
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
    _G.BIZ_LOADED = nil
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
local function test_when_sees_thenet_from_g()
    local dir = tmp_dir("ds_pkg_when_thenet")
    write_fixture(dir, "modinfo.lua", [[
name = "WhenNet"
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
plugin_id = "test.when_thenet"
when = function(ctx)
    if not ctx or not ctx.has_luajit then
        return false
    end
    if ctx.is_client ~= nil then
        return not ctx.is_client
    end
    return TheNet:IsDedicated()
end
]])
    write_fixture(dir, "modmain.lua", "-- empty\n")

    local prev = rawget(_G, "TheNet")
    _G.TheNet = {
        IsDedicated = function()
            return false
        end,
    }
    local ok, err = pcall(function()
        local plugin = PL.load_package_from_root(dir, "plugin_test_when_thenet")
        assert_true(type(plugin.when) == "function", "when present")
        -- Incomplete gate_ctx (no is_client) must fall through to TheNet, not error.
        local result = plugin.when({ has_luajit = true })
        assert_true(result == false, "when returns TheNet:IsDedicated() result")
        -- Host marker still raw on sandbox env.
        assert_true(PL.last_modinfo_env.ds_luajit_package_host == true, "host marker")
        assert_true(rawget(PL.last_modinfo_env, "ds_luajit_package_host") == true, "marker raw")
    end)
    _G.TheNet = prev
    if not ok then
        error(err, 2)
    end
    print("PASS: when_sees_thenet_from_g")
end

test_missing_api_version_fails()
test_host_marker_true()
test_engine_safe_without_marker()
test_modimport_rebind_on_load()
test_when_sees_thenet_from_g()

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
print("ALL PASS package_load_spec")
