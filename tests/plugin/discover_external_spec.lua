local function repo_root()
    local r = os.getenv("REPO_ROOT")
    if r and #r > 0 then
        return r:gsub("\\", "/")
    end
    return "."
end

local ROOT = repo_root()
package.path = ROOT .. "/Mod/?.lua;" .. ROOT .. "/Mod/?/init.lua;" .. package.path

local discover = require("plugins.discover_external")

local function assert_true(cond, msg)
    if not cond then
        error(msg or "assert_true failed", 2)
    end
end

-- Fake KnownModIndex
local mods = {}
_G.KnownModIndex = {
    GetClientModNames = function()
        local t = {}
        for name, _ in pairs(mods) do
            t[#t + 1] = name
        end
        return t
    end,
    GetServerModNames = function()
        return _G.KnownModIndex:GetClientModNames()
    end,
    IsModEnabled = function(_, name)
        return mods[name] and mods[name].enabled or false
    end,
    GetModInfo = function(_, name)
        return mods[name] and mods[name].info or nil
    end,
}

local function test_skips_unmarked()
    mods = {
        plain = { enabled = true, info = { name = "plain" } },
    }
    local loaded = {}
    local out = discover.run({
        this_modname = "DontStarveLuaJit2",
        is_client = true,
        package_load = {
            load_package_from_root = function(root, stem)
                loaded[#loaded + 1] = stem
                return { id = "x" }
            end,
        },
        package_dirs_for_mod = function()
            return { "/tmp/plain/plugins/plugin_x/" }
        end,
    })
    assert_true(#out == 0, "unmarked should not load")
    assert_true(#loaded == 0)
    print("PASS: skips_unmarked")
end

local function test_skips_disabled()
    mods = {
        pack = {
            enabled = false,
            info = { luajit_plugin_pack = true, plugin_id = "vendor.x" },
        },
    }
    local loaded = {}
    local out = discover.run({
        this_modname = "DontStarveLuaJit2",
        is_client = true,
        package_load = {
            load_package_from_root = function()
                loaded[#loaded + 1] = true
                return { id = "vendor.x" }
            end,
        },
        package_dirs_for_mod = function()
            return { "/tmp/pack/plugins/plugin_x/" }
        end,
    })
    assert_true(#out == 0)
    assert_true(#loaded == 0)
    print("PASS: skips_disabled")
end

local function test_loads_marked_enabled()
    mods = {
        pack = {
            enabled = true,
            info = { luajit_plugin_pack = true, plugin_id = "vendor.x" },
        },
    }
    local loaded = {}
    local out = discover.run({
        this_modname = "DontStarveLuaJit2",
        is_client = true,
        mod_root_for = function()
            return "/tmp/pack/"
        end,
        package_dirs_for_mod = function()
            return { "/tmp/pack/plugins/plugin_x/" }
        end,
        package_load = {
            load_package_from_root = function(root, stem)
                loaded[#loaded + 1] = { root = root, stem = stem }
                return { id = "vendor.x", version = "1.0.0" }
            end,
        },
    })
    assert_true(#out == 1, "expected one plugin")
    assert_true(out[1].id == "vendor.x")
    assert_true(#loaded == 1)
    assert_true(loaded[1].stem == "plugin_x")
    print("PASS: loads_marked_enabled")
end

local function test_skips_missing_plugin_id()
    mods = {
        pack = {
            enabled = true,
            info = { luajit_plugin_pack = true, plugin_id = "" },
        },
    }
    local loaded = {}
    discover.run({
        this_modname = "DontStarveLuaJit2",
        is_client = true,
        package_dirs_for_mod = function()
            return { "/tmp/pack/plugins/plugin_x/" }
        end,
        package_load = {
            load_package_from_root = function()
                loaded[#loaded + 1] = true
                return { id = "x" }
            end,
        },
    })
    assert_true(#loaded == 0)
    print("PASS: skips_missing_plugin_id")
end

local function test_skips_this_mod()
    mods = {
        DontStarveLuaJit2 = {
            enabled = true,
            info = { luajit_plugin_pack = true, plugin_id = "should.not" },
        },
    }
    local loaded = {}
    discover.run({
        this_modname = "DontStarveLuaJit2",
        is_client = true,
        package_dirs_for_mod = function()
            return { "/tmp/self/plugins/plugin_x/" }
        end,
        package_load = {
            load_package_from_root = function()
                loaded[#loaded + 1] = true
                return { id = "x" }
            end,
        },
    })
    assert_true(#loaded == 0)
    print("PASS: skips_this_mod")
end

test_skips_unmarked()
test_skips_disabled()
test_loads_marked_enabled()
test_skips_missing_plugin_id()
test_skips_this_mod()
print("ALL PASS discover_external_spec")
