-- tests/plugin/bake_plugin_options_spec.lua
-- Fixture-only bake collector / serializer / --check tests.
-- Runner: tests/plugin/run_bake_plugin_options.py

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

local function assert_true(cond, msg)
    if not cond then
        error(msg or "assert_true failed", 2)
    end
end

local function ensure_dir(dir)
    dir = dir:gsub("\\", "/")
    if package.config:sub(1, 1) == "\\" then
        os.execute('mkdir "' .. dir:gsub("/", "\\") .. '" 2>nul')
    else
        os.execute('mkdir -p "' .. dir .. '" 2>/dev/null')
    end
end

local function write_file(path, body)
    path = path:gsub("\\", "/")
    local dir = path:match("^(.*)/[^/]+$")
    if dir then
        ensure_dir(dir)
    end
    local f = assert(io.open(path, "wb"))
    f:write(body)
    f:close()
end

local function read_file(path)
    local f = assert(io.open(path, "rb"))
    local body = f:read("*a")
    f:close()
    return body
end

local function tmp_dir(name)
    local tmp = os.getenv("TMP") or os.getenv("TEMP") or "/tmp"
    local dir = (tmp .. "/" .. name):gsub("\\", "/")
    ensure_dir(dir)
    return dir
end

local PARENT_FIXTURE = [[
configuration_options = {
    { name = "AlwaysEnableMod", label = "A", options = { { description = "On", data = true } }, default = true },
    -- BEGIN GENERATED PLUGIN OPTIONS
    -- END GENERATED PLUGIN OPTIONS
}
]]

local function package_modinfo(opts)
    opts = opts or {}
    local name = opts.name or "Fixture"
    local plugin_id = opts.plugin_id or "fixture.test"
    local priority = opts.priority or 50
    local extra = opts.extra or ""
    local rows = opts.rows or [[
    {
        name = "EnableForkSave",
        label = translate({ en = "Fork Save", zh = "分叉存档" }),
        hover = translate({ en = "hover", zh = "提示" }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_non_win,
        host_gate = true,
    },
]]
    return string.format([[
name = %q
description = "fixture"
author = "test"
version = "1.0.0"
api_version = 10
dst_compatible = true
dont_starve_compatible = false
reign_of_giants_compatible = false
client_only_mod = false
server_only_mod = false
all_clients_require_mod = false
priority = %s
plugin_id = %q
%s
configuration_options = {
%s
}
]], name, tostring(priority), plugin_id, extra, rows)
end

local tool_path = ROOT .. "/tools/bake_plugin_options.lua"
local chunk, load_err = loadfile(tool_path)
if not chunk then
    error("cannot load tools/bake_plugin_options.lua: " .. tostring(load_err))
end
local bake = chunk()
assert_true(type(bake) == "table", "expected bake module table when BAKE_PLUGIN_OPTIONS_AS_MODULE=1")
assert_true(type(bake.collect) == "function", "missing collect")
assert_true(type(bake.serialize_rows) == "function", "missing serialize_rows")
assert_true(type(bake.splice) == "function", "missing splice")
assert_true(type(bake.check) == "function", "missing check")
assert_true(type(bake.write) == "function", "missing write")

local function test_serialize_keeps_translate_locales()
    local text = bake.serialize_rows({
        {
            name = "EnableForkSave",
            label = { __bake_translate = { en = "Fork Save", zh = "分叉存档" } },
            options = { { description = "On", data = true } },
            default = true,
        },
    })
    assert_true(text:find("translate({", 1, true), "expected translate({, got:\n" .. text)
    assert_true(text:find("zh =", 1, true), "expected zh =, got:\n" .. text)
    assert_true(text:find("en =", 1, true), "expected en =, got:\n" .. text)
    assert_true(not text:find('label = "Fork Save"', 1, true), "label frozen to English:\n" .. text)
    print("PASS: serialize_keeps_translate_locales")
end

local function test_serialize_toggle_identifier()
    local text = bake.serialize_rows({
        {
            name = "EnableForkSave",
            label = "L",
            options = { __bake_toggle = true },
            default = true,
        },
    })
    assert_true(text:find("options%s*=%s*toggle"), "expected identifier toggle, got:\n" .. text)
    assert_true(not text:find("__bake_toggle", 1, true), text)
    print("PASS: serialize_toggle_identifier")
end

local function test_serialize_addsection()
    local text = bake.serialize_rows({
        {
            __bake_section = true,
            label = { __bake_translate = { en = "Net", zh = "网络" } },
            hover = { __bake_translate = { en = "h", zh = "h" } },
        },
    })
    assert_true(text:find("AddSection(", 1, true), "expected AddSection(...), got:\n" .. text)
    assert_true(text:find("translate({", 1, true), text)
    print("PASS: serialize_addsection")
end

local function test_serialize_disable_by_non_win()
    local text = bake.serialize_rows({
        {
            name = "NetworkOpt",
            label = "N",
            options = { { description = "On", data = true } },
            default = true,
            disabled_by = { __bake_ident = "disable_by_non_win" },
        },
    })
    assert_true(text:find("disable_by_non_win", 1, true), text)
    assert_true(text:find("disabled_by%s*=%s*disable_by_non_win"), "expected identifier, got:\n" .. text)
    print("PASS: serialize_disable_by_non_win")
end

local function test_serialize_host_gate_true()
    local text = bake.serialize_rows({
        {
            name = "EnableForkSave",
            label = "L",
            options = { { description = "On", data = true } },
            default = true,
            host_gate = true,
        },
    })
    assert_true(text:find("host_gate = true", 1, true), "expected host_gate = true, got:\n" .. text)
    print("PASS: serialize_host_gate_true")
end

local function test_collision_two_packages()
    local root = tmp_dir("ds_bake_collide_pkgs")
    local plugins = root .. "/src/DontStarveInjector/plugins"
    write_file(root .. "/Mod/modinfo.lua", PARENT_FIXTURE)
    write_file(plugins .. "/plugin_aaa/modinfo.lua", package_modinfo({
        plugin_id = "aaa",
        priority = 10,
        rows = [[
    { name = "SharedKey", label = "A", options = toggle, default = true, host_gate = true },
]],
    }))
    write_file(plugins .. "/plugin_bbb/modinfo.lua", package_modinfo({
        plugin_id = "bbb",
        priority = 20,
        rows = [[
    { name = "SharedKey", label = "B", options = toggle, default = false, host_gate = true },
]],
    }))
    local ok, err = pcall(function()
        bake.write({
            source_root = root,
            plugins_root = plugins,
            modinfo = root .. "/Mod/modinfo.lua",
        })
    end)
    assert_true(not ok, "expected write to fail on two-package name collision")
    assert_true(tostring(err):find("SharedKey", 1, true), tostring(err))
    print("PASS: collision_two_packages")
end

local function test_collision_handwritten()
    local root = tmp_dir("ds_bake_collide_parent")
    local plugins = root .. "/src/DontStarveInjector/plugins"
    write_file(root .. "/Mod/modinfo.lua", PARENT_FIXTURE)
    write_file(plugins .. "/plugin_aaa/modinfo.lua", package_modinfo({
        plugin_id = "aaa",
        rows = [[
    { name = "AlwaysEnableMod", label = "X", options = toggle, default = true, host_gate = true },
]],
    }))
    local ok, err = pcall(function()
        bake.write({
            source_root = root,
            plugins_root = plugins,
            modinfo = root .. "/Mod/modinfo.lua",
        })
    end)
    assert_true(not ok, "expected write to fail on hand-written collision")
    local msg = tostring(err)
    assert_true(msg:find("AlwaysEnableMod", 1, true), msg)
    print("PASS: collision_handwritten")
end

local function test_splice_idempotent()
    local body = [[    {
        name = "EnableForkSave",
        label = translate({ en = "Fork Save", zh = "分叉存档" }),
        options = toggle,
        default = true,
        host_gate = true,
    },]]
    local once = bake.splice(PARENT_FIXTURE, body)
    local twice = bake.splice(once, body)
    assert_true(once == twice, "splice is not idempotent")
    assert_true(once:find("-- BEGIN GENERATED PLUGIN OPTIONS", 1, true), once)
    assert_true(once:find("-- END GENERATED PLUGIN OPTIONS", 1, true), once)
    assert_true(once:find("EnableForkSave", 1, true), once)
    assert_true(once:find("AlwaysEnableMod", 1, true), once)
    print("PASS: splice_idempotent")
end

local function test_write_check_roundtrip()
    local root = tmp_dir("ds_bake_roundtrip")
    local plugins = root .. "/src/DontStarveInjector/plugins"
    local modinfo = root .. "/Mod/modinfo.lua"
    write_file(modinfo, PARENT_FIXTURE)
    write_file(plugins .. "/plugin_save_fork/modinfo.lua", package_modinfo({
        name = "Save Fork",
        plugin_id = "save.fork",
        priority = 60,
    }))
    write_file(plugins .. "/plugin_net/modinfo.lua", package_modinfo({
        name = "Net",
        plugin_id = "network.rpc",
        priority = 10,
        rows = [[
    AddSection(translate({ en = "Net", zh = "网络" }), translate({ en = "h", zh = "h" })),
    {
        name = "NetworkOpt",
        label = translate({ en = "Net Opt", zh = "网络优化" }),
        options = toggle,
        default = true,
        host_gate = true,
    },
]],
    }))
    write_file(plugins .. "/plugin_dummy/modinfo.lua", package_modinfo({
        name = "Dummy",
        plugin_id = "debug.dummy",
        priority = 1000,
        rows = "",
    }))
    write_file(plugins .. "/plugin_client_anim/modinfo.lua", package_modinfo({
        name = "Deleted",
        plugin_id = "client.anim",
        priority = 1,
        rows = [[
    { name = "EnableClientAnimOwn", label = "X", options = toggle, default = true },
]],
    }))
    write_file(plugins .. "/plugin_c_only/README.txt", "no modinfo\n")

    bake.write({
        source_root = root,
        plugins_root = plugins,
        modinfo = modinfo,
    })
    local after_first = read_file(modinfo)
    bake.write({
        source_root = root,
        plugins_root = plugins,
        modinfo = modinfo,
    })
    local after_second = read_file(modinfo)
    assert_true(after_first == after_second, "write is not idempotent")

    local clean = bake.check({
        source_root = root,
        plugins_root = plugins,
        modinfo = modinfo,
    })
    assert_true(clean == true, "expected --check clean after write")

    assert_true(after_first:find("translate({", 1, true), after_first)
    assert_true(after_first:find("zh =", 1, true), after_first)
    assert_true(after_first:find("options = toggle", 1, true), after_first)
    assert_true(after_first:find("AddSection(", 1, true), after_first)
    assert_true(after_first:find("disable_by_non_win", 1, true), after_first)
    assert_true(after_first:find("host_gate = true", 1, true), after_first)
    assert_true(after_first:find("NetworkOpt", 1, true), after_first)
    assert_true(after_first:find("EnableForkSave", 1, true), after_first)
    -- priority 10 (network) before 60 (save.fork)
    local i_net = after_first:find("NetworkOpt", 1, true)
    local i_fork = after_first:find("EnableForkSave", 1, true)
    assert_true(i_net < i_fork, "expected priority-ascending emit order")
    assert_true(not after_first:find("EnableClientAnimOwn", 1, true), "plugin_client_anim must be skipped")

    local dirty = after_first:gsub("EnableForkSave", "EnableForkSaveDIRTY", 1)
    write_file(modinfo, dirty)
    local dirty_ok = bake.check({
        source_root = root,
        plugins_root = plugins,
        modinfo = modinfo,
    })
    assert_true(dirty_ok == false, "expected --check dirty after mutation")
    print("PASS: write_check_roundtrip")
end

local function test_check_missing_markers()
    local root = tmp_dir("ds_bake_nomarkers")
    local plugins = root .. "/src/DontStarveInjector/plugins"
    local modinfo = root .. "/Mod/modinfo.lua"
    write_file(modinfo, "configuration_options = {\n}\n")
    write_file(plugins .. "/plugin_aaa/modinfo.lua", package_modinfo({
        plugin_id = "aaa",
        rows = [[
    { name = "OnlyKey", label = "A", options = toggle, default = true },
]],
    }))
    local ok, err = pcall(function()
        return bake.check({
            source_root = root,
            plugins_root = plugins,
            modinfo = modinfo,
        })
    end)
    assert_true(not ok, "expected missing markers to error")
    assert_true(tostring(err):lower():find("marker", 1, true), tostring(err))
    print("PASS: check_missing_markers")
end

local function test_reject_obsolete_options()
    local root = tmp_dir("ds_bake_obsolete")
    local plugins = root .. "/src/DontStarveInjector/plugins"
    write_file(root .. "/Mod/modinfo.lua", PARENT_FIXTURE)
    write_file(plugins .. "/plugin_aaa/modinfo.lua", package_modinfo({
        plugin_id = "aaa",
        extra = 'options = { all_of = { "EnableForkSave" } }',
        rows = [[
    { name = "EnableForkSave", label = "A", options = toggle, default = true, host_gate = true },
]],
    }))
    local ok, err = pcall(function()
        bake.write({
            source_root = root,
            plugins_root = plugins,
            modinfo = root .. "/Mod/modinfo.lua",
        })
    end)
    assert_true(not ok, "expected obsolete options field to fail")
    assert_true(tostring(err):find("options", 1, true), tostring(err))
    print("PASS: reject_obsolete_options")
end

test_serialize_keeps_translate_locales()
test_serialize_toggle_identifier()
test_serialize_addsection()
test_serialize_disable_by_non_win()
test_serialize_host_gate_true()
test_collision_two_packages()
test_collision_handwritten()
test_splice_idempotent()
test_write_check_roundtrip()
test_check_missing_markers()
test_reject_obsolete_options()
print("ALL PASS bake_plugin_options_spec")
