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

test_missing_api_version_fails()
test_host_marker_true()
test_engine_safe_without_marker()
test_modimport_rebind_on_load()
print("ALL PASS package_load_spec")
