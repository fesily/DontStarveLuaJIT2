-- L-C: pure-Lua PluginHost tests mirroring C++ plugin_host_graph + option rules.
-- Runner: tests/plugin/run_lua_host.py

local function repo_root()
    local from_env = os.getenv("REPO_ROOT")
    if from_env and from_env ~= "" then
        return from_env:gsub("\\", "/")
    end
    -- script is tests/plugin/plugin_host_lua_spec.lua → two levels up
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

local PluginHost = require("plugins.host")

local function assert_eq(actual, expected, message)
    if actual ~= expected then
        error(string.format("%s: expected %s, got %s", message, tostring(expected), tostring(actual)), 2)
    end
end

local function assert_true(v, message)
    if not v then
        error(message, 2)
    end
end

local function assert_false(v, message)
    if v then
        error(message, 2)
    end
end

local STATUS = PluginHost.Status
local FAIL = PluginHost.FailReason
local PHASE = PluginHost.Phase

local function fake(opts)
    opts = opts or {}
    local p = {
        id = opts.id,
        version = opts.version or "1.0.0",
        depends = opts.depends or {},
        soft_depends = opts.soft_depends or {},
        conflicts = opts.conflicts or {},
        phases = opts.phases or PHASE.AfterModMain,
        options = opts.options, -- nil => always on
        support_reload = opts.support_reload or false,
        priority = opts.priority or 100,
        allow = opts.allow ~= false,
        load_count = 0,
        unload_count = 0,
        throw_on_load = opts.throw_on_load or false,
        throw_msg = opts.throw_msg or "boom",
    }
    function p.can_load(ctx)
        return p.allow
    end
    function p.load(ctx)
        if p.throw_on_load then
            error(p.throw_msg)
        end
        p.load_count = p.load_count + 1
    end
    function p.unload(ctx)
        p.unload_count = p.unload_count + 1
    end
    return p
end

local function always()
    return { always = true }
end

local function opt_all(keys)
    return { all_of = keys }
end

local function pos(order, id)
    for i = 1, #order do
        if order[i] == id then
            return i
        end
    end
    return nil
end

local function test_empty_registry()
    local host = PluginHost.new()
    host:resolve({}, {})
    local lr = host:load_phase(PHASE.AfterModMain)
    assert_eq(#lr.loaded_order, 0, "empty loaded_order")
    assert_true(lr.ok, "empty ok")
    print("PASS: empty_registry")
end

local function test_topo_linear()
    local b = fake({ id = "B", priority = 10, options = always() })
    local a = fake({ id = "A", priority = 10, depends = { "B" }, options = always() })
    local host = PluginHost.new()
    host:register(b)
    host:register(a)
    host:resolve({}, {})
    local lr = host:load_phase(PHASE.AfterModMain)
    assert_eq(#lr.loaded_order, 2, "topo size")
    assert_eq(lr.loaded_order[1], "B", "B first")
    assert_eq(lr.loaded_order[2], "A", "A second")
    assert_eq(b.load_count, 1, "B load")
    assert_eq(a.load_count, 1, "A load")
    assert_eq(host:status("A"), STATUS.Loaded, "A status")
    assert_eq(host:status("B"), STATUS.Loaded, "B status")
    print("PASS: topo_linear")
end

local function test_topo_diamond()
    local d = fake({ id = "D", priority = 1, options = always() })
    local b = fake({ id = "B", priority = 2, depends = { "D" }, options = always() })
    local c = fake({ id = "C", priority = 3, depends = { "D" }, options = always() })
    local a = fake({ id = "A", priority = 4, depends = { "B", "C" }, options = always() })
    local host = PluginHost.new()
    host:register(a)
    host:register(b)
    host:register(c)
    host:register(d)
    host:resolve({}, {})
    local lr = host:load_phase(PHASE.AfterModMain)
    assert_eq(#lr.loaded_order, 4, "diamond size")
    local pd, pb, pc, pa = pos(lr.loaded_order, "D"), pos(lr.loaded_order, "B"),
        pos(lr.loaded_order, "C"), pos(lr.loaded_order, "A")
    assert_true(pd < pb, "D before B")
    assert_true(pd < pc, "D before C")
    assert_true(pb < pa, "B before A")
    assert_true(pc < pa, "C before A")
    print("PASS: topo_diamond")
end

local function test_soft_dep_missing()
    local a = fake({ id = "A", soft_depends = { "Z" }, options = always() })
    local host = PluginHost.new()
    host:register(a)
    host:resolve({}, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(a.load_count, 1, "soft missing still loads")
    assert_eq(host:status("A"), STATUS.Loaded, "A loaded")
    assert_eq(host:fail_reason("A"), FAIL.None, "no fail")
    print("PASS: soft_dep_missing")
end

local function test_soft_dep_present()
    local z = fake({ id = "Z", priority = 5, options = always() })
    local a = fake({ id = "A", priority = 10, soft_depends = { "Z" }, options = always() })
    local host = PluginHost.new()
    host:register(a)
    host:register(z)
    host:resolve({}, {})
    local lr = host:load_phase(PHASE.AfterModMain)
    assert_eq(#lr.loaded_order, 2, "soft present size")
    assert_eq(lr.loaded_order[1], "Z", "Z first")
    assert_eq(lr.loaded_order[2], "A", "A second")
    print("PASS: soft_dep_present")
end

local function test_hard_dep_missing()
    local a = fake({ id = "A", depends = { "Z" }, options = always() })
    local host = PluginHost.new()
    host:register(a)
    host:resolve({}, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(a.load_count, 0, "no load on missing hard dep")
    assert_eq(host:status("A"), STATUS.Failed, "A failed")
    assert_eq(host:fail_reason("A"), FAIL.MissingHardDep, "MissingHardDep")
    print("PASS: hard_dep_missing")
end

local function test_conflict_both_enabled()
    local a = fake({ id = "A", conflicts = { "B" }, options = always() })
    local b = fake({ id = "B", conflicts = { "A" }, options = always() })
    local host = PluginHost.new()
    host:register(a)
    host:register(b)
    host:resolve({}, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(a.load_count, 0, "A no load")
    assert_eq(b.load_count, 0, "B no load")
    assert_eq(host:status("A"), STATUS.Failed, "A failed")
    assert_eq(host:status("B"), STATUS.Failed, "B failed")
    assert_eq(host:fail_reason("A"), FAIL.Conflict, "A conflict")
    assert_eq(host:fail_reason("B"), FAIL.Conflict, "B conflict")
    print("PASS: conflict_both_enabled")
end

local function test_conflict_one_enabled()
    local a = fake({ id = "A", conflicts = { "B" }, options = opt_all({ "enA" }) })
    local b = fake({ id = "B", conflicts = { "A" }, options = opt_all({ "enB" }) })
    local host = PluginHost.new()
    host:register(a)
    host:register(b)
    host:resolve({ enA = true, enB = false }, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(a.load_count, 1, "A loads")
    assert_eq(b.load_count, 0, "B skips")
    assert_eq(host:status("A"), STATUS.Loaded, "A loaded")
    assert_eq(host:status("B"), STATUS.Disabled, "B disabled")
    print("PASS: conflict_one_enabled")
end

local function test_cycle_three()
    local a = fake({ id = "A", depends = { "B" }, options = always() })
    local b = fake({ id = "B", depends = { "C" }, options = always() })
    local c = fake({ id = "C", depends = { "A" }, options = always() })
    local host = PluginHost.new()
    host:register(a)
    host:register(b)
    host:register(c)
    host:resolve({}, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(a.load_count + b.load_count + c.load_count, 0, "no loads in cycle")
    assert_eq(host:status("A"), STATUS.Failed, "A failed")
    assert_eq(host:status("B"), STATUS.Failed, "B failed")
    assert_eq(host:status("C"), STATUS.Failed, "C failed")
    assert_eq(host:fail_reason("A"), FAIL.Cycle, "cycle reason")
    print("PASS: cycle_three")
end

local function test_phase_barrier()
    local x = fake({ id = "X", phases = PHASE.EarlyNative, options = always() })
    local y = fake({ id = "Y", phases = PHASE.AfterModMain, depends = { "X" }, options = always() })
    local host = PluginHost.new()
    host:register(x)
    host:register(y)
    host:resolve({}, {})
    local early = host:load_phase(PHASE.EarlyNative)
    assert_eq(#early.loaded_order, 1, "early size")
    assert_eq(early.loaded_order[1], "X", "X early")
    assert_eq(y.load_count, 0, "Y not early")
    local late = host:load_phase(PHASE.AfterModMain)
    assert_eq(#late.loaded_order, 1, "late size")
    assert_eq(late.loaded_order[1], "Y", "Y late")
    assert_eq(y.load_count, 1, "Y loaded once")
    print("PASS: phase_barrier")
end

local function test_option_off()
    local a = fake({ id = "A", options = opt_all({ "on" }) })
    local host = PluginHost.new()
    host:register(a)
    host:resolve({ on = false }, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(a.load_count, 0, "option off no load")
    assert_eq(host:status("A"), STATUS.Disabled, "disabled")
    print("PASS: option_off")
end

local function test_option_on_shorthand()
    local a = fake({ id = "A", options = { option = "EnableForkSave" } })
    local host = PluginHost.new()
    host:register(a)
    host:resolve({ EnableForkSave = true }, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(a.load_count, 1, "shorthand on")
    assert_eq(host:status("A"), STATUS.Loaded, "loaded")
    print("PASS: option_on_shorthand")
end

local function test_string_predicate()
    local profiler = fake({
        id = "debug.profiler",
        options = { neq = { key = "EnableProfiler", value = "off" } },
        priority = 20,
    })
    local tracy = fake({
        id = "debug.tracy",
        options = { eq = { key = "EnableTracy", value = "on" } },
        priority = 21,
    })
    local host = PluginHost.new()
    host:register(profiler)
    host:register(tracy)
    host:resolve({ EnableProfiler = "fzvp", EnableTracy = "off" }, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(profiler.load_count, 1, "profiler neq off")
    assert_eq(tracy.load_count, 0, "tracy eq on fails")
    assert_eq(host:status("debug.tracy"), STATUS.Disabled, "tracy disabled")
    print("PASS: string_predicate")
end

local function test_load_throw_fails_dependents()
    local b = fake({ id = "B", priority = 1, options = always() })
    local a = fake({ id = "A", priority = 2, depends = { "B" }, options = always(), throw_on_load = true })
    local c = fake({ id = "C", priority = 3, depends = { "A" }, options = always() })
    local host = PluginHost.new()
    host:register(b)
    host:register(a)
    host:register(c)
    host:resolve({}, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(b.load_count, 1, "B loads")
    assert_eq(a.load_count, 0, "A no load")
    assert_eq(c.load_count, 0, "C no load")
    assert_eq(host:status("B"), STATUS.Loaded, "B loaded")
    assert_eq(host:status("A"), STATUS.Failed, "A failed")
    assert_eq(host:fail_reason("A"), FAIL.LoadThrew, "A threw")
    assert_eq(host:status("C"), STATUS.Failed, "C failed")
    assert_eq(host:fail_reason("C"), FAIL.MissingHardDep, "C missing dep")
    print("PASS: load_throw_fails_dependents")
end

local function test_priority_tiebreak()
    local a = fake({ id = "A", priority = 10, options = always() })
    local b = fake({ id = "B", priority = 20, options = always() })
    local host = PluginHost.new()
    host:register(b)
    host:register(a)
    host:resolve({}, {})
    local lr = host:load_phase(PHASE.AfterModMain)
    assert_eq(#lr.loaded_order, 2, "prio size")
    assert_eq(lr.loaded_order[1], "A", "lower prio first")
    assert_eq(lr.loaded_order[2], "B", "higher prio second")
    print("PASS: priority_tiebreak")
end

local function test_profiler_before_hide()
    local profiler = fake({ id = "debug.profiler", priority = 20, options = always() })
    local jit = fake({ id = "jit.runtime", priority = 70, options = always() })
    local host = PluginHost.new()
    host:register(jit)
    host:register(profiler)
    host:resolve({}, {})
    local lr = host:load_phase(PHASE.AfterModMain)
    assert_eq(lr.loaded_order[1], "debug.profiler", "profiler first")
    assert_eq(lr.loaded_order[2], "jit.runtime", "jit second")
    print("PASS: profiler_before_hide")
end

local function test_when_false()
    local a = fake({ id = "A", options = always(), allow = false })
    local host = PluginHost.new()
    host:register(a)
    host:resolve({}, {})
    host:load_phase(PHASE.AfterModMain)
    assert_eq(a.load_count, 0, "when false no load")
    assert_eq(host:status("A"), STATUS.Disabled, "disabled not failed")
    print("PASS: when_false")
end

local function test_sticky_and_reload()
    local sticky = fake({ id = "sticky", options = always(), support_reload = false })
    local reloadable = fake({ id = "reloadable", options = always(), support_reload = true })
    local host = PluginHost.new()
    host:register(sticky)
    host:register(reloadable)
    host:resolve({}, {})
    host:load_phase(PHASE.AfterModMain)
    assert_false(host:unload("sticky", {}), "sticky refuses unload")
    assert_eq(sticky.unload_count, 0, "sticky unload_count")
    assert_true(host:unload("reloadable", {}), "reloadable unloads")
    assert_eq(reloadable.unload_count, 1, "reload unload_count")
    print("PASS: sticky_and_reload")
end

local function test_config_function_getmodconfigdata()
    -- Production path: config is a wrapper around GetModConfigData
    local calls = {}
    local function get_mod_config_data(key)
        calls[#calls + 1] = key
        if key == "EnableForkSave" then
            return true
        end
        return false
    end
    local a = fake({ id = "save.fork", options = { option = "EnableForkSave" } })
    local host = PluginHost.new()
    host:register(a)
    host:resolve(get_mod_config_data, { has_luajit = true })
    host:load_phase(PHASE.AfterModMain)
    assert_eq(a.load_count, 1, "function config loads")
    assert_true(#calls >= 1, "queried config")
    print("PASS: config_function_getmodconfigdata")
end

local function plugin_by_id(list, id)
    for i = 1, #list do
        if list[i].id == id then
            return list[i]
        end
    end
    return nil
end

local function test_save_fork_enable_matrix()
    -- L-E: save.fork EnableForkSave true/false (+ when gate).
    package.loaded["plugins.init"] = nil
    package.loaded["plugins.package_load"] = nil
    package.loaded["plugins.save_fork"] = nil
    package.loaded["plugins.sim_lagcomp"] = nil
    package.loaded["plugins.network_sim"] = nil
    package.loaded["plugins.network_rpc"] = nil
    package.loaded["plugins.network_entity"] = nil
    local list = require("plugins.init")
    assert_eq(type(list), "table", "init returns table")
    assert_true(#list >= 1, "init has plugins")
    local save_fork = plugin_by_id(list, "save.fork")
    assert_true(save_fork ~= nil, "save.fork registered")
    assert_eq(save_fork.priority, 60, "save.fork priority")

    -- Stub production load side effects (AddGamePostInit + modimport).
    local postinits = {}
    local modimports = {}
    local prev_AddGamePostInit = rawget(_G, "AddGamePostInit")
    local prev_modimport = rawget(_G, "modimport")
    rawset(_G, "AddGamePostInit", function(fn)
        postinits[#postinits + 1] = fn
    end)
    rawset(_G, "modimport", function(path)
        modimports[#modimports + 1] = path
    end)

    local ok, err = pcall(function()
        -- Row: EnableForkSave=true + dedicated + has_luajit → Loaded
        local host_on = PluginHost.new()
        host_on:register_all(list)
        host_on:resolve(
            { EnableForkSave = true },
            { has_luajit = true, is_client = false }
        )
        local lr_on = host_on:load_phase(PHASE.AfterModMain)
        assert_true(lr_on.ok, "save.fork on load ok")
        assert_eq(host_on:status("save.fork"), STATUS.Loaded, "save.fork on Loaded")
        assert_eq(pos(lr_on.loaded_order, "save.fork") ~= nil and 1 or 0, 1, "save.fork in order")
        local e_on = host_on:find("save.fork")
        assert_eq(e_on.load_count, 1, "save.fork load_count on")
        assert_eq(#postinits, 1, "save.fork scheduled PostInit")
        postinits[1]()
        assert_eq(#modimports, 1, "save.fork modimport once")
        assert_eq(modimports[1], "scripts/fork_save", "save.fork modimport path")

        -- Row: EnableForkSave=false → Disabled, no load
        postinits = {}
        modimports = {}
        local host_off = PluginHost.new()
        host_off:register_all(list)
        host_off:resolve(
            { EnableForkSave = false },
            { has_luajit = true, is_client = false }
        )
        local lr_off = host_off:load_phase(PHASE.AfterModMain)
        assert_true(lr_off.ok, "save.fork off resolve ok")
        assert_eq(host_off:status("save.fork"), STATUS.Disabled, "save.fork off Disabled")
        assert_eq(pos(lr_off.loaded_order, "save.fork"), nil, "save.fork not loaded when off")
        local e_off = host_off:find("save.fork")
        assert_eq(e_off.load_count or 0, 0, "save.fork load_count off")
        assert_eq(#postinits, 0, "no PostInit when off")
        assert_eq(#modimports, 0, "no modimport when off")

        -- when gate: client (not dedicated) disables even if option on
        local host_client = PluginHost.new()
        host_client:register_all(list)
        host_client:resolve(
            { EnableForkSave = true },
            { has_luajit = true, is_client = true }
        )
        host_client:load_phase(PHASE.AfterModMain)
        assert_eq(host_client:status("save.fork"), STATUS.Disabled, "save.fork disabled on client")

        -- when gate: no luajit disables
        local host_nojit = PluginHost.new()
        host_nojit:register_all(list)
        host_nojit:resolve(
            { EnableForkSave = true },
            { has_luajit = false, is_client = false }
        )
        host_nojit:load_phase(PHASE.AfterModMain)
        assert_eq(host_nojit:status("save.fork"), STATUS.Disabled, "save.fork disabled without luajit")
    end)

    rawset(_G, "AddGamePostInit", prev_AddGamePostInit)
    rawset(_G, "modimport", prev_modimport)
    if not ok then
        error(err, 0)
    end
    print("PASS: save_fork_enable_matrix")
end

local function test_sim_lagcomp_enable_matrix()
    -- L-E: sim.lagcomp EnableLagCompensation true/false (+ when gates).
    package.loaded["plugins.init"] = nil
    package.loaded["plugins.package_load"] = nil
    package.loaded["plugins.save_fork"] = nil
    package.loaded["plugins.sim_lagcomp"] = nil
    package.loaded["plugins.network_sim"] = nil
    package.loaded["plugins.network_rpc"] = nil
    package.loaded["plugins.network_entity"] = nil
    local list = require("plugins.init")
    local plugin = plugin_by_id(list, "sim.lagcomp")
    assert_true(plugin ~= nil, "sim.lagcomp registered")
    assert_eq(plugin.priority, 60, "sim.lagcomp priority")
    assert_eq(plugin.options.all_of[1], "EnableLagCompensation", "sim.lagcomp option")

    local modimports = {}
    local prev_modimport = rawget(_G, "modimport")
    rawset(_G, "modimport", function(path)
        modimports[#modimports + 1] = path
    end)

    local ok, err = pcall(function()
        -- Row: option on + has_luajit + windows + mastersim → Loaded
        modimports = {}
        local host_on = PluginHost.new()
        host_on:register_all(list)
        host_on:resolve(
            { EnableLagCompensation = true },
            { has_luajit = true, is_windows = true, is_mastersim = true }
        )
        local lr_on = host_on:load_phase(PHASE.AfterModMain)
        assert_true(lr_on.ok, "sim.lagcomp on load ok")
        assert_eq(host_on:status("sim.lagcomp"), STATUS.Loaded, "sim.lagcomp on Loaded")
        assert_eq(pos(lr_on.loaded_order, "sim.lagcomp") ~= nil and 1 or 0, 1, "sim.lagcomp in order")
        local e_on = host_on:find("sim.lagcomp")
        assert_eq(e_on.load_count, 1, "sim.lagcomp load_count on")
        assert_eq(#modimports, 1, "sim.lagcomp modimport once")
        assert_eq(modimports[1], "scripts/lag_compensation", "sim.lagcomp modimport path")

        -- Row: option off → Disabled
        modimports = {}
        local host_off = PluginHost.new()
        host_off:register_all(list)
        host_off:resolve(
            { EnableLagCompensation = false },
            { has_luajit = true, is_windows = true, is_mastersim = true }
        )
        local lr_off = host_off:load_phase(PHASE.AfterModMain)
        assert_true(lr_off.ok, "sim.lagcomp off resolve ok")
        assert_eq(host_off:status("sim.lagcomp"), STATUS.Disabled, "sim.lagcomp off Disabled")
        assert_eq(pos(lr_off.loaded_order, "sim.lagcomp"), nil, "sim.lagcomp not loaded when off")
        local e_off = host_off:find("sim.lagcomp")
        assert_eq(e_off.load_count or 0, 0, "sim.lagcomp load_count off")
        assert_eq(#modimports, 0, "no modimport when off")

        -- when gate: not mastersim
        local host_client = PluginHost.new()
        host_client:register_all(list)
        host_client:resolve(
            { EnableLagCompensation = true },
            { has_luajit = true, is_windows = true, is_mastersim = false }
        )
        host_client:load_phase(PHASE.AfterModMain)
        assert_eq(host_client:status("sim.lagcomp"), STATUS.Disabled, "sim.lagcomp disabled when not mastersim")

        -- when gate: non-windows
        local host_nowin = PluginHost.new()
        host_nowin:register_all(list)
        host_nowin:resolve(
            { EnableLagCompensation = true },
            { has_luajit = true, is_windows = false, is_mastersim = true }
        )
        host_nowin:load_phase(PHASE.AfterModMain)
        assert_eq(host_nowin:status("sim.lagcomp"), STATUS.Disabled, "sim.lagcomp disabled without windows")

        -- when gate: no luajit
        local host_nojit = PluginHost.new()
        host_nojit:register_all(list)
        host_nojit:resolve(
            { EnableLagCompensation = true },
            { has_luajit = false, is_windows = true, is_mastersim = true }
        )
        host_nojit:load_phase(PHASE.AfterModMain)
        assert_eq(host_nojit:status("sim.lagcomp"), STATUS.Disabled, "sim.lagcomp disabled without luajit")
    end)

    rawset(_G, "modimport", prev_modimport)
    if not ok then
        error(err, 0)
    end
    print("PASS: sim_lagcomp_enable_matrix")
end

local function test_network_sim_enable_matrix()
    -- L-E: network.sim EnableNetSim true/false (+ when gates).
    package.loaded["plugins.init"] = nil
    package.loaded["plugins.package_load"] = nil
    package.loaded["plugins.save_fork"] = nil
    package.loaded["plugins.sim_lagcomp"] = nil
    package.loaded["plugins.network_sim"] = nil
    package.loaded["plugins.network_rpc"] = nil
    package.loaded["plugins.network_entity"] = nil
    local list = require("plugins.init")
    local plugin = plugin_by_id(list, "network.sim")
    assert_true(plugin ~= nil, "network.sim registered")
    assert_eq(plugin.priority, 60, "network.sim priority")
    assert_eq(plugin.options.all_of[1], "EnableNetSim", "network.sim option")

    local modimports = {}
    local prev_modimport = rawget(_G, "modimport")
    rawset(_G, "modimport", function(path)
        modimports[#modimports + 1] = path
    end)

    local ok, err = pcall(function()
        -- Row: option on + has_luajit + windows + not mastersim → Loaded
        modimports = {}
        local host_on = PluginHost.new()
        host_on:register_all(list)
        host_on:resolve(
            { EnableNetSim = true },
            { has_luajit = true, is_windows = true, is_mastersim = false }
        )
        local lr_on = host_on:load_phase(PHASE.AfterModMain)
        assert_true(lr_on.ok, "network.sim on load ok")
        assert_eq(host_on:status("network.sim"), STATUS.Loaded, "network.sim on Loaded")
        assert_eq(pos(lr_on.loaded_order, "network.sim") ~= nil and 1 or 0, 1, "network.sim in order")
        local e_on = host_on:find("network.sim")
        assert_eq(e_on.load_count, 1, "network.sim load_count on")
        assert_eq(#modimports, 1, "network.sim modimport once")
        assert_eq(modimports[1], "scripts/netsim", "network.sim modimport path")

        -- Row: option off → Disabled
        modimports = {}
        local host_off = PluginHost.new()
        host_off:register_all(list)
        host_off:resolve(
            { EnableNetSim = false },
            { has_luajit = true, is_windows = true, is_mastersim = false }
        )
        local lr_off = host_off:load_phase(PHASE.AfterModMain)
        assert_true(lr_off.ok, "network.sim off resolve ok")
        assert_eq(host_off:status("network.sim"), STATUS.Disabled, "network.sim off Disabled")
        assert_eq(pos(lr_off.loaded_order, "network.sim"), nil, "network.sim not loaded when off")
        local e_off = host_off:find("network.sim")
        assert_eq(e_off.load_count or 0, 0, "network.sim load_count off")
        assert_eq(#modimports, 0, "no modimport when off")

        -- when gate: mastersim (server) disables even if option on
        local host_master = PluginHost.new()
        host_master:register_all(list)
        host_master:resolve(
            { EnableNetSim = true },
            { has_luajit = true, is_windows = true, is_mastersim = true }
        )
        host_master:load_phase(PHASE.AfterModMain)
        assert_eq(host_master:status("network.sim"), STATUS.Disabled, "network.sim disabled on mastersim")

        -- when gate: non-windows
        local host_nowin = PluginHost.new()
        host_nowin:register_all(list)
        host_nowin:resolve(
            { EnableNetSim = true },
            { has_luajit = true, is_windows = false, is_mastersim = false }
        )
        host_nowin:load_phase(PHASE.AfterModMain)
        assert_eq(host_nowin:status("network.sim"), STATUS.Disabled, "network.sim disabled without windows")

        -- when gate: no luajit
        local host_nojit = PluginHost.new()
        host_nojit:register_all(list)
        host_nojit:resolve(
            { EnableNetSim = true },
            { has_luajit = false, is_windows = true, is_mastersim = false }
        )
        host_nojit:load_phase(PHASE.AfterModMain)
        assert_eq(host_nojit:status("network.sim"), STATUS.Disabled, "network.sim disabled without luajit")
    end)

    rawset(_G, "modimport", prev_modimport)
    if not ok then
        error(err, 0)
    end
    print("PASS: network_sim_enable_matrix")
end

local function clear_plugin_modules()
    package.loaded["plugins.init"] = nil
    package.loaded["plugins.package_load"] = nil
    package.loaded["plugins.save_fork"] = nil
    package.loaded["plugins.sim_lagcomp"] = nil
    package.loaded["plugins.network_sim"] = nil
    package.loaded["plugins.network_rpc"] = nil
    package.loaded["plugins.network_entity"] = nil
    package.loaded["plugins.jit_tailcall"] = nil
    package.loaded["plugins.debug_profiler"] = nil
    package.loaded["plugins.gc_policy"] = nil
    package.loaded["plugins.fps_render"] = nil
    package.loaded["plugins.jit_runtime"] = nil
end

local function make_bit_stub()
    return {
        bxor = function(a, b)
            local r, p = 0, 1
            a, b = a % 4294967296, b % 4294967296
            for _ = 1, 32 do
                local abit, bbit = a % 2, b % 2
                if abit ~= bbit then
                    r = r + p
                end
                a, b, p = (a - abit) / 2, (b - bbit) / 2, p * 2
            end
            return r
        end,
        lshift = function(a, n)
            return (a * (2 ^ n)) % 4294967296
        end,
        rshift = function(a, n)
            return math.floor((a % 4294967296) / (2 ^ n))
        end,
    }
end

local function test_network_rpc_enable_matrix()
    -- L-E: network.rpc NetworkOpt true/false (Lua face AfterModMain).
    clear_plugin_modules()
    local list = require("plugins.init")
    local plugin = plugin_by_id(list, "network.rpc")
    assert_true(plugin ~= nil, "network.rpc registered")
    assert_eq(plugin.priority, 40, "network.rpc priority")
    assert_eq(plugin.options.all_of[1], "NetworkOpt", "network.rpc option")
    assert_eq(#(plugin.depends or {}), 0, "network.rpc no hard deps")

    local set_next_calls = {}
    -- Stub TheNet metatable + bit helpers used by production load.
    local injector = {
        DS_LUAJIT_SetNextRpcInfo = function(p, r, c)
            set_next_calls[#set_next_calls + 1] = { p, r, c }
        end,
        DS_LUAJIT_disable_fullgc = function() end,
        DS_LUAJIT_enable_framegc = function() end,
        DS_LUAJIT_replace_profiler_api = function() end,
        DS_LUAJIT_set_target_fps = function()
            return 0
        end,
        DS_LUAJIT_Fengxun_Decrypt = function()
            return nil
        end,
    }
    local net_index = {
        SendRPCToServer = function() end,
        SendRPCToClient = function() end,
        SendRPCToShard = function() end,
        SendModRPCToServer = function() end,
        SendModRPCToClient = function() end,
        SendModRPCToShard = function() end,
    }
    local TheNet = setmetatable({}, { __index = net_index })
    local prev_TheNet = rawget(_G, "TheNet")
    local prev_bit = rawget(_G, "bit")
    rawset(_G, "TheNet", TheNet)
    rawset(_G, "bit", make_bit_stub())
    local ok, err = pcall(function()
        -- Row: NetworkOpt=true → Loaded, wraps SendRPC*
        local host_on = PluginHost.new()
        host_on:register_all(list)
        host_on:resolve({ NetworkOpt = true }, { injector = injector })
        local lr_on = host_on:load_phase(PHASE.AfterModMain)
        assert_true(lr_on.ok, "network.rpc on load ok")
        assert_eq(host_on:status("network.rpc"), STATUS.Loaded, "network.rpc on Loaded")
        assert_eq(pos(lr_on.loaded_order, "network.rpc") ~= nil and 1 or 0, 1, "network.rpc in order")
        local e_on = host_on:find("network.rpc")
        assert_eq(e_on.load_count, 1, "network.rpc load_count on")
        assert_true(type(net_index.SendRPCToServer) == "function", "SendRPCToServer wrapped")
        assert_true(type(net_index.SendRPCToServer2) == "function", "SendRPCToServer2 installed")
        assert_true(type(net_index.alloc_rpc_channel) == "function", "alloc_rpc_channel installed")

        -- Row: NetworkOpt=false → Disabled, no load
        local host_off = PluginHost.new()
        host_off:register_all(list)
        host_off:resolve({ NetworkOpt = false }, { injector = injector })
        local lr_off = host_off:load_phase(PHASE.AfterModMain)
        assert_true(lr_off.ok, "network.rpc off resolve ok")
        assert_eq(host_off:status("network.rpc"), STATUS.Disabled, "network.rpc off Disabled")
        assert_eq(pos(lr_off.loaded_order, "network.rpc"), nil, "network.rpc not loaded when off")
        local e_off = host_off:find("network.rpc")
        assert_eq(e_off.load_count or 0, 0, "network.rpc load_count off")
    end)

    rawset(_G, "TheNet", prev_TheNet)
    rawset(_G, "bit", prev_bit)
    if not ok then
        error(err, 0)
    end
    print("PASS: network_rpc_enable_matrix")
end

local function test_network_entity_enable_matrix()
    -- L-E / S9: network.entity × network.rpc hard dep matrix.
    clear_plugin_modules()
    local list = require("plugins.init")
    local plugin = plugin_by_id(list, "network.entity")
    assert_true(plugin ~= nil, "network.entity registered")
    assert_eq(plugin.priority, 40, "network.entity priority")
    assert_eq(plugin.options.all_of[1], "NetworkOptEntity", "network.entity option")
    assert_eq(plugin.depends[1], "network.rpc", "network.entity depends network.rpc")

    local register_calls = {}
    local injector = {
        DS_LUAJIT_EntityNetWorkExtension_Register = function(net, id)
            register_calls[#register_calls + 1] = { net, id }
            return { registered = true, id = id }
        end,
        DS_LUAJIT_SetNextRpcInfo = function() end,
        DS_LUAJIT_disable_fullgc = function() end,
        DS_LUAJIT_enable_framegc = function() end,
        DS_LUAJIT_replace_profiler_api = function() end,
        DS_LUAJIT_set_target_fps = function()
            return 0
        end,
        DS_LUAJIT_Fengxun_Decrypt = function()
            return nil
        end,
    }
    -- Minimal TheNet for rpc face when both on.
    local net_index = {
        SendRPCToServer = function() end,
        SendRPCToClient = function() end,
        SendRPCToShard = function() end,
        SendModRPCToServer = function() end,
        SendModRPCToClient = function() end,
        SendModRPCToShard = function() end,
    }
    local TheNet = setmetatable({}, { __index = net_index })
    local prev_TheNet = rawget(_G, "TheNet")
    local prev_bit = rawget(_G, "bit")
    local prev_SpawnPrefab = rawget(_G, "SpawnPrefab")
    rawset(_G, "TheNet", TheNet)
    rawset(_G, "bit", make_bit_stub())
    rawset(_G, "SpawnPrefab", function(name)
        return {
            prefab = name,
            Network = {
                GetNetworkID = function() return 42 end,
            },
        }
    end)

    local ok, err = pcall(function()
        -- Row: entity on + rpc on → both Loaded; SpawnPrefab registers extension
        register_calls = {}
        local host_both = PluginHost.new()
        host_both:register_all(list)
        host_both:resolve(
            { NetworkOpt = true, NetworkOptEntity = true },
            { injector = injector }
        )
        local lr_both = host_both:load_phase(PHASE.AfterModMain)
        assert_true(lr_both.ok, "entity+rpc load ok")
        assert_eq(host_both:status("network.rpc"), STATUS.Loaded, "rpc Loaded with entity")
        assert_eq(host_both:status("network.entity"), STATUS.Loaded, "entity Loaded with rpc")
        -- hard dep: rpc before entity in load order
        local pr = pos(lr_both.loaded_order, "network.rpc")
        local pe = pos(lr_both.loaded_order, "network.entity")
        assert_true(pr ~= nil and pe ~= nil and pr < pe, "rpc before entity")
        local inst = SpawnPrefab("walrus")
        assert_true(inst.NetworkExtension ~= nil, "NetworkExtension registered")
        assert_eq(#register_calls, 1, "EntityNetWorkExtension_Register once")

        -- Row: entity on + rpc off → entity Failed MissingHardDep, no load
        register_calls = {}
        local host_ent_only = PluginHost.new()
        host_ent_only:register_all(list)
        host_ent_only:resolve(
            { NetworkOpt = false, NetworkOptEntity = true },
            { injector = injector }
        )
        local lr_ent = host_ent_only:load_phase(PHASE.AfterModMain)
        assert_eq(host_ent_only:status("network.rpc"), STATUS.Disabled, "rpc Disabled")
        assert_eq(host_ent_only:status("network.entity"), STATUS.Failed, "entity Failed alone")
        assert_eq(host_ent_only:fail_reason("network.entity"), FAIL.MissingHardDep, "MissingHardDep")
        local e_ent = host_ent_only:find("network.entity")
        assert_eq(e_ent.load_count or 0, 0, "entity not loaded without rpc")
        assert_eq(pos(lr_ent.loaded_order, "network.entity"), nil, "entity not in order alone")

        -- Row: entity off + rpc on → entity Disabled, rpc Loaded
        local host_rpc_only = PluginHost.new()
        host_rpc_only:register_all(list)
        host_rpc_only:resolve(
            { NetworkOpt = true, NetworkOptEntity = false },
            { injector = injector }
        )
        host_rpc_only:load_phase(PHASE.AfterModMain)
        assert_eq(host_rpc_only:status("network.rpc"), STATUS.Loaded, "rpc alone Loaded")
        assert_eq(host_rpc_only:status("network.entity"), STATUS.Disabled, "entity off Disabled")

        -- Row: both off → both Disabled
        local host_off = PluginHost.new()
        host_off:register_all(list)
        host_off:resolve(
            { NetworkOpt = false, NetworkOptEntity = false },
            { injector = injector }
        )
        host_off:load_phase(PHASE.AfterModMain)
        assert_eq(host_off:status("network.rpc"), STATUS.Disabled, "rpc both-off Disabled")
        assert_eq(host_off:status("network.entity"), STATUS.Disabled, "entity both-off Disabled")
    end)

    rawset(_G, "TheNet", prev_TheNet)
    rawset(_G, "bit", prev_bit)
    rawset(_G, "SpawnPrefab", prev_SpawnPrefab)
    if not ok then
        error(err, 0)
    end
    print("PASS: network_entity_enable_matrix")
end

local function test_option_rules_unit()
    local eval = PluginHost.evaluate_option_rule
    assert_true(eval({ all_of = { "A", "B" } }, { A = true, B = true }), "all_of true")
    assert_false(eval({ all_of = { "A", "B" } }, { A = true, B = false }), "all_of partial")
    assert_true(eval({ any_of = { "A", "B" } }, { A = false, B = true }), "any_of one")
    assert_false(eval({ any_of = { "A", "B" } }, { A = false, B = false }), "any_of none")
    assert_true(eval({ option = "A" }, { A = true }), "shorthand")
    assert_true(eval({ neq = { "EnableProfiler", "off" } }, { EnableProfiler = "fzvp" }), "string ne")
    assert_false(eval({ neq = { "EnableProfiler", "off" } }, { EnableProfiler = "off" }), "string off")
    assert_true(eval({ eq = { "EnableTracy", "on" } }, { EnableTracy = "on" }), "string eq on")
    assert_false(eval({ eq = { "EnableTracy", "on" } }, { EnableTracy = "off" }), "string eq off")
    assert_true(eval(nil, {}), "always nil")
    -- AND semantics (spec O5): both groups
    assert_true(eval({ all_of = { "A" }, any_of = { "B", "C" } }, { A = true, B = true, C = false }), "and both")
    assert_false(eval({ all_of = { "A" }, any_of = { "B", "C" } }, { A = false, B = true }), "and all_of fail")
    assert_false(eval({ all_of = { "A" }, any_of = { "B", "C" } }, { A = true, B = false, C = false }), "and any_of fail")
    assert_true(eval({ all_of = {}, any_of = { "B" } }, { B = true }), "empty all_of + any")
    assert_false(eval({ all_of = { "A" }, any_of = {} }, { A = true }), "empty any_of is false")
    print("PASS: option_rules_unit")
end

local function fresh_m4_injector()
    local inj = {
        fullgc = nil,
        framegc = nil,
        profiler_api = 0,
        tracy = 0,
        profiler = 0,
        target_fps = nil,
    }
    function inj.DS_LUAJIT_disable_fullgc(v)
        inj.fullgc = v
    end
    function inj.DS_LUAJIT_enable_framegc(v)
        inj.framegc = v
    end
    function inj.DS_LUAJIT_replace_profiler_api()
        inj.profiler_api = inj.profiler_api + 1
    end
    function inj.DS_LUAJIT_enable_tracy(v)
        inj.tracy = v
    end
    function inj.DS_LUAJIT_enable_profiler(v)
        inj.profiler = v
    end
    function inj.DS_LUAJIT_set_target_fps(fps, mode)
        inj.target_fps = fps
        return 1
    end
    function inj.DS_LUAJIT_Fengxun_Decrypt()
        return nil
    end
    return inj
end

local function install_m4_game_stubs()
    local prev = {
        TheSim = rawget(_G, "TheSim"),
        TheNet = rawget(_G, "TheNet"),
        AddSimPostInit = rawget(_G, "AddSimPostInit"),
        AddGamePostInit = rawget(_G, "AddGamePostInit"),
        KnownModIndex = rawget(_G, "KnownModIndex"),
        APP_VERSION = rawget(_G, "APP_VERSION"),
        bit = rawget(_G, "bit"),
        json = rawget(_G, "json"),
        debug = rawget(_G, "debug"),
        jit = rawget(_G, "jit"),
        package_preload_jit_opt = package.preload["jit.opt"],
        package_preload_jit_zone = package.preload["jit.zone"],
        package_preload_jit_p = package.preload["jit.p"],
        package_loaded_jit_opt = package.loaded["jit.opt"],
        package_loaded_jit_zone = package.loaded["jit.zone"],
        package_loaded_jit_p = package.loaded["jit.p"],
    }

    local sim_index = {
        ProfilerPush = function() end,
        ProfilerPop = function() end,
        GetModDirectoryNames = function()
            return {}
        end,
        SetNetbookMode = function() end,
    }
    rawset(_G, "TheSim", setmetatable({}, { __index = sim_index }))
    -- debug.profiler uses getmetatable(TheSim).__index for method wraps
    getmetatable(rawget(_G, "TheSim")).__index = sim_index
    rawset(_G, "TheNet", {
        IsDedicated = function()
            return false
        end,
    })
    rawset(_G, "AddSimPostInit", function(fn)
        -- do not run immediately; just accept
    end)
    rawset(_G, "AddGamePostInit", function(fn) end)
    rawset(_G, "KnownModIndex", {
        GetModInfo = function()
            return nil
        end,
    })
    rawset(_G, "APP_VERSION", "test-1.0")
    rawset(_G, "bit", make_bit_stub())
    rawset(_G, "json", {
        encode = function()
            return "{}"
        end,
        decode = function()
            return nil
        end,
    })
    local reg = {}
    rawset(_G, "debug", {
        getregistry = function()
            return reg
        end,
    })
    local jit_stub = {
        off = function() end,
        on = function() end,
        disabletailcall = function() end,
    }
    rawset(_G, "jit", jit_stub)
    package.preload["jit.opt"] = function()
        return {
            start = function() end,
        }
    end
    package.preload["jit.zone"] = function()
        return function() end
    end
    package.preload["jit.p"] = function()
        return {
            start = function() end,
            stop = function() end,
        }
    end
    package.loaded["jit.opt"] = nil
    package.loaded["jit.zone"] = nil
    package.loaded["jit.p"] = nil
    return prev, reg, jit_stub
end

local function restore_m4_game_stubs(prev)
    rawset(_G, "TheSim", prev.TheSim)
    rawset(_G, "TheNet", prev.TheNet)
    rawset(_G, "AddSimPostInit", prev.AddSimPostInit)
    rawset(_G, "AddGamePostInit", prev.AddGamePostInit)
    rawset(_G, "KnownModIndex", prev.KnownModIndex)
    rawset(_G, "APP_VERSION", prev.APP_VERSION)
    rawset(_G, "bit", prev.bit)
    rawset(_G, "json", prev.json)
    rawset(_G, "debug", prev.debug)
    rawset(_G, "jit", prev.jit)
    package.preload["jit.opt"] = prev.package_preload_jit_opt
    package.preload["jit.zone"] = prev.package_preload_jit_zone
    package.preload["jit.p"] = prev.package_preload_jit_p
    package.loaded["jit.opt"] = prev.package_loaded_jit_opt
    package.loaded["jit.zone"] = prev.package_loaded_jit_zone
    package.loaded["jit.p"] = prev.package_loaded_jit_p
end

local function test_m4_plugin_priorities_and_order()
    -- L-A / S8: real registry priorities + profiler before jit.runtime.
    clear_plugin_modules()
    local list = require("plugins.init")
    local expected = {
        ["jit.tailcall"] = 10,
        ["debug.profiler"] = 20,
        ["fps.render"] = 50,
        ["jit.runtime"] = 70,
    }
    for id, prio in pairs(expected) do
        local p = plugin_by_id(list, id)
        assert_true(p ~= nil, id .. " registered")
        assert_eq(p.priority, prio, id .. " priority")
    end

    local prev, reg, jit_stub = install_m4_game_stubs()
    local injector = fresh_m4_injector()
    local ok, err = pcall(function()
        local host = PluginHost.new()
        host:register_all(list)
        host:resolve({
            SlowTailCall = true,
            AutoDetectEncryptedMod = false,
            ForceDisableTailCall = false,
            EnableProfiler = "fzvp",
            EnableTracy = "off",
            DisableForceFullGC = true,
            EnableFrameGC = false,
            EnabledGenGC = false,
            TargetRenderFPS = 120,
            EnabledJIT = true,
            HideGlobalJIT = false,
            ModBlackList = false,
            NetworkOpt = false,
            NetworkOptEntity = false,
            EnableForkSave = false,
            EnableLagCompensation = false,
            EnableNetSim = false,
        }, {
            injector = injector,
            has_luajit = true,
            is_client = true,
            is_windows = true,
            jit = jit_stub,
            mod_env = { modinfo = { luajit_compatible = true }, jit = jit_stub },
        })
        local lr = host:load_phase(PHASE.AfterModMain)
        assert_true(lr.ok, "m4 load ok")
        local p_prof = pos(lr.loaded_order, "debug.profiler")
        local p_jit = pos(lr.loaded_order, "jit.runtime")
        local p_tail = pos(lr.loaded_order, "jit.tailcall")
        local p_fps = pos(lr.loaded_order, "fps.render")
        local p_gc = pos(lr.loaded_order, "gc.policy")
        assert_true(p_tail ~= nil and p_prof ~= nil and p_jit ~= nil, "m4 plugins loaded")
        assert_true(p_tail < p_prof, "tailcall before profiler")
        assert_true(p_prof < p_jit, "profiler before jit.runtime")
        assert_true(p_gc == nil, "gc.policy no longer a separate plugin")
        assert_true(p_fps ~= nil and p_fps < p_jit, "fps before jit.runtime")
        assert_eq(host:status("debug.profiler"), STATUS.Loaded, "profiler Loaded")
        assert_eq(host:status("jit.runtime"), STATUS.Loaded, "jit.runtime Loaded")
        assert_eq(injector.target_fps, 120, "fps set")
        assert_eq(injector.fullgc, true, "fullgc enabled via debug.profiler")
    end)
    restore_m4_game_stubs(prev)
    if not ok then
        error(err, 0)
    end
    print("PASS: m4_plugin_priorities_and_order")
end

local function test_debug_profiler_enable_matrix()
    -- L-E: EnableProfiler off/fzvp; EnableTracy on/off
    clear_plugin_modules()
    local list = require("plugins.init")
    local plugin = plugin_by_id(list, "debug.profiler")
    assert_true(plugin ~= nil, "debug.profiler registered")
    assert_eq(plugin.priority, 20, "debug.profiler priority")

    local prev = install_m4_game_stubs()
    local ok, err = pcall(function()
        local inj = fresh_m4_injector()
        local host_off = PluginHost.new()
        host_off:register_all(list)
        host_off:resolve({
            EnableProfiler = "off",
            EnableTracy = "off",
            NetworkOpt = false,
            NetworkOptEntity = false,
            EnableForkSave = false,
            EnableLagCompensation = false,
            EnableNetSim = false,
            SlowTailCall = false,
            ForceDisableTailCall = false,
            AutoDetectEncryptedMod = false,
            TargetRenderFPS = false,
        }, { injector = inj, has_luajit = true, is_windows = true, jit = rawget(_G, "jit") })
        host_off:load_phase(PHASE.AfterModMain)
        assert_eq(host_off:status("debug.profiler"), STATUS.Disabled, "profiler both-off Disabled")

        local inj2 = fresh_m4_injector()
        local host_prof = PluginHost.new()
        host_prof:register_all(list)
        host_prof:resolve({
            EnableProfiler = "fzvp",
            EnableTracy = "off",
            NetworkOpt = false,
            NetworkOptEntity = false,
            EnableForkSave = false,
            EnableLagCompensation = false,
            EnableNetSim = false,
            SlowTailCall = false,
            ForceDisableTailCall = false,
            AutoDetectEncryptedMod = false,
            TargetRenderFPS = false,
            EnabledJIT = false,
            HideGlobalJIT = false,
        }, { injector = inj2, has_luajit = true, is_windows = true, jit = rawget(_G, "jit") })
        host_prof:load_phase(PHASE.AfterModMain)
        assert_eq(host_prof:status("debug.profiler"), STATUS.Loaded, "profiler fzvp Loaded")
        assert_true(rawget(_G, "ProfilerJit") ~= nil, "ProfilerJit installed")

        local inj3 = fresh_m4_injector()
        local host_tracy = PluginHost.new()
        host_tracy:register_all(list)
        host_tracy:resolve({
            EnableProfiler = "off",
            EnableTracy = "on",
            NetworkOpt = false,
            NetworkOptEntity = false,
            EnableForkSave = false,
            EnableLagCompensation = false,
            EnableNetSim = false,
            SlowTailCall = false,
            ForceDisableTailCall = false,
            AutoDetectEncryptedMod = false,
            TargetRenderFPS = false,
            EnabledJIT = false,
            HideGlobalJIT = false,
        }, { injector = inj3, has_luajit = true, is_windows = true, jit = rawget(_G, "jit") })
        host_tracy:load_phase(PHASE.AfterModMain)
        assert_eq(host_tracy:status("debug.profiler"), STATUS.Loaded, "tracy on Loaded")
        assert_eq(inj3.tracy, 1, "tracy enabled")
        assert_true(inj3.profiler_api >= 1, "profiler api replaced for tracy")
    end)
    restore_m4_game_stubs(prev)
    if not ok then
        error(err, 0)
    end
    print("PASS: debug_profiler_enable_matrix")
end

local function test_gc_policy_enable_matrix()
    -- L-E: DisableForceFullGC / EnableFrameGC now owned by debug.profiler (+ EnabledGenGC short-circuit)
    clear_plugin_modules()
    local list = require("plugins.init")
    assert_true(plugin_by_id(list, "gc.policy") == nil, "gc.policy removed from registry")
    local plugin = plugin_by_id(list, "debug.profiler")
    assert_true(plugin ~= nil, "debug.profiler registered")
    assert_eq(plugin.priority, 20, "debug.profiler priority")
    assert_true(plugin.options and plugin.options.any_of, "debug.profiler any_of options")

    local prev = install_m4_game_stubs()
    local ok, err = pcall(function()
        local base = {
            NetworkOpt = false,
            NetworkOptEntity = false,
            EnableForkSave = false,
            EnableLagCompensation = false,
            EnableNetSim = false,
            SlowTailCall = false,
            ForceDisableTailCall = false,
            AutoDetectEncryptedMod = false,
            EnableProfiler = "off",
            EnableTracy = "off",
            TargetRenderFPS = false,
            EnabledJIT = false,
            HideGlobalJIT = false,
        }

        local inj = fresh_m4_injector()
        local host = PluginHost.new()
        host:register_all(list)
        local cfg = {}
        for k, v in pairs(base) do
            cfg[k] = v
        end
        cfg.DisableForceFullGC = true
        cfg.EnableFrameGC = true
        cfg.EnabledGenGC = false
        host:resolve(cfg, { injector = inj, has_luajit = true, is_windows = true, jit = rawget(_G, "jit") })
        host:load_phase(PHASE.AfterModMain)
        assert_eq(host:status("debug.profiler"), STATUS.Loaded, "profiler Loaded for GC flags")
        assert_eq(inj.fullgc, true, "fullgc on")
        assert_eq(inj.framegc, true, "framegc on")

        local inj2 = fresh_m4_injector()
        local host2 = PluginHost.new()
        host2:register_all(list)
        local cfg2 = {}
        for k, v in pairs(base) do
            cfg2[k] = v
        end
        cfg2.DisableForceFullGC = true
        cfg2.EnableFrameGC = true
        cfg2.EnabledGenGC = true
        host2:resolve(cfg2, { injector = inj2, has_luajit = true, is_windows = true, jit = rawget(_G, "jit") })
        host2:load_phase(PHASE.AfterModMain)
        assert_eq(host2:status("debug.profiler"), STATUS.Loaded, "profiler still Loaded under GenGC")
        assert_eq(inj2.fullgc, false, "fullgc reset under GenGC")
        assert_eq(inj2.framegc, false, "framegc reset under GenGC")
    end)
    restore_m4_game_stubs(prev)
    if not ok then
        error(err, 0)
    end
    print("PASS: gc_policy_enable_matrix")
end

local function test_fps_render_enable_matrix()
    -- L-E: TargetRenderFPS present vs off-ish; Win gate
    clear_plugin_modules()
    local list = require("plugins.init")
    local plugin = plugin_by_id(list, "fps.render")
    assert_true(plugin ~= nil, "fps.render registered")
    assert_eq(plugin.priority, 50, "fps.render priority")

    local prev = install_m4_game_stubs()
    local ok, err = pcall(function()
        local base = {
            NetworkOpt = false,
            NetworkOptEntity = false,
            EnableForkSave = false,
            EnableLagCompensation = false,
            EnableNetSim = false,
            SlowTailCall = false,
            ForceDisableTailCall = false,
            AutoDetectEncryptedMod = false,
            EnableProfiler = "off",
            EnableTracy = "off",
            EnabledJIT = false,
            HideGlobalJIT = false,
            DisableForceFullGC = false,
            EnableFrameGC = false,
            EnabledGenGC = false,
        }

        local inj = fresh_m4_injector()
        local host = PluginHost.new()
        host:register_all(list)
        local cfg = {}
        for k, v in pairs(base) do
            cfg[k] = v
        end
        cfg.TargetRenderFPS = 144
        host:resolve(cfg, { injector = inj, has_luajit = true, is_windows = true, jit = rawget(_G, "jit") })
        host:load_phase(PHASE.AfterModMain)
        assert_eq(host:status("fps.render"), STATUS.Loaded, "fps Loaded")
        assert_eq(inj.target_fps, 144, "target fps 144")

        local inj2 = fresh_m4_injector()
        local host2 = PluginHost.new()
        host2:register_all(list)
        local cfg2 = {}
        for k, v in pairs(base) do
            cfg2[k] = v
        end
        cfg2.TargetRenderFPS = 0
        host2:resolve(cfg2, { injector = inj2, has_luajit = true, is_windows = true, jit = rawget(_G, "jit") })
        host2:load_phase(PHASE.AfterModMain)
        assert_eq(host2:status("fps.render"), STATUS.Disabled, "fps 0 Disabled")

        local inj3 = fresh_m4_injector()
        local host3 = PluginHost.new()
        host3:register_all(list)
        local cfg3 = {}
        for k, v in pairs(base) do
            cfg3[k] = v
        end
        cfg3.TargetRenderFPS = 120
        host3:resolve(cfg3, { injector = inj3, has_luajit = true, is_windows = false, jit = rawget(_G, "jit") })
        host3:load_phase(PHASE.AfterModMain)
        assert_eq(host3:status("fps.render"), STATUS.Disabled, "fps non-win Disabled")
    end)
    restore_m4_game_stubs(prev)
    if not ok then
        error(err, 0)
    end
    print("PASS: fps_render_enable_matrix")
end

local function test_jit_tailcall_enable_matrix()
    -- L-E: SlowTailCall / ForceDisable / AutoDetect combinations
    clear_plugin_modules()
    local list = require("plugins.init")
    local plugin = plugin_by_id(list, "jit.tailcall")
    assert_true(plugin ~= nil, "jit.tailcall registered")
    assert_eq(plugin.priority, 10, "jit.tailcall priority")

    local prev, reg = install_m4_game_stubs()
    local ok, err = pcall(function()
        local base = {
            NetworkOpt = false,
            NetworkOptEntity = false,
            EnableForkSave = false,
            EnableLagCompensation = false,
            EnableNetSim = false,
            EnableProfiler = "off",
            EnableTracy = "off",
            TargetRenderFPS = false,
            EnabledJIT = false,
            HideGlobalJIT = false,
            DisableForceFullGC = false,
            EnableFrameGC = false,
            EnabledGenGC = false,
        }

        local inj = fresh_m4_injector()
        local host = PluginHost.new()
        host:register_all(list)
        local cfg = {}
        for k, v in pairs(base) do
            cfg[k] = v
        end
        cfg.SlowTailCall = true
        cfg.AnyModDisableTailCall = true
        cfg.ForceDisableTailCall = false
        cfg.AutoDetectEncryptedMod = false
        host:resolve(cfg, { injector = inj, has_luajit = true, is_windows = true, jit = rawget(_G, "jit") })
        host:load_phase(PHASE.AfterModMain)
        assert_eq(host:status("jit.tailcall"), STATUS.Loaded, "tailcall Loaded")
        assert_true(reg["LJ_DS_slowtailcall_mods"] ~= nil, "slowtail registry set")
        assert_eq(reg["LJ_DS_slowtailcall_mods"]["__any__"], true, "any mod disable")

        local host_off = PluginHost.new()
        host_off:register_all(list)
        local cfg2 = {}
        for k, v in pairs(base) do
            cfg2[k] = v
        end
        cfg2.SlowTailCall = false
        cfg2.ForceDisableTailCall = false
        cfg2.AutoDetectEncryptedMod = false
        host_off:resolve(cfg2, { injector = inj, has_luajit = true, is_windows = true, jit = rawget(_G, "jit") })
        host_off:load_phase(PHASE.AfterModMain)
        assert_eq(host_off:status("jit.tailcall"), STATUS.Disabled, "tailcall all-off Disabled")

        local host_nojit = PluginHost.new()
        host_nojit:register_all(list)
        local cfg3 = {}
        for k, v in pairs(base) do
            cfg3[k] = v
        end
        cfg3.SlowTailCall = true
        host_nojit:resolve(cfg3, { injector = inj, has_luajit = false, is_windows = true })
        host_nojit:load_phase(PHASE.AfterModMain)
        assert_eq(host_nojit:status("jit.tailcall"), STATUS.Disabled, "tailcall no-luajit Disabled")
    end)
    restore_m4_game_stubs(prev)
    if not ok then
        error(err, 0)
    end
    print("PASS: jit_tailcall_enable_matrix")
end

local function test_jit_runtime_enable_matrix()
    -- L-E: EnabledJIT true/false; HideGlobalJIT true/false; order vs profiler
    clear_plugin_modules()
    local list = require("plugins.init")
    local plugin = plugin_by_id(list, "jit.runtime")
    assert_true(plugin ~= nil, "jit.runtime registered")
    assert_eq(plugin.priority, 70, "jit.runtime priority")

    local prev, reg, jit_stub = install_m4_game_stubs()
    local ok, err = pcall(function()
        local base = {
            NetworkOpt = false,
            NetworkOptEntity = false,
            EnableForkSave = false,
            EnableLagCompensation = false,
            EnableNetSim = false,
            EnableProfiler = "off",
            EnableTracy = "off",
            TargetRenderFPS = false,
            SlowTailCall = false,
            ForceDisableTailCall = false,
            AutoDetectEncryptedMod = false,
            DisableForceFullGC = false,
            EnableFrameGC = false,
            EnabledGenGC = false,
            ModBlackList = false,
        }

        local inj = fresh_m4_injector()
        local host = PluginHost.new()
        host:register_all(list)
        local cfg = {}
        for k, v in pairs(base) do
            cfg[k] = v
        end
        cfg.EnabledJIT = true
        cfg.HideGlobalJIT = false
        host:resolve(cfg, {
            injector = inj,
            has_luajit = true,
            is_windows = true,
            jit = jit_stub,
            mod_env = { modinfo = { luajit_compatible = true }, jit = jit_stub },
        })
        local lr = host:load_phase(PHASE.AfterModMain)
        assert_eq(host:status("jit.runtime"), STATUS.Loaded, "jit.runtime Loaded")
        assert_true(pos(lr.loaded_order, "jit.runtime") ~= nil, "jit.runtime in order")

        local host_nojit = PluginHost.new()
        host_nojit:register_all(list)
        host_nojit:resolve(cfg, { injector = inj, has_luajit = false, is_windows = true })
        host_nojit:load_phase(PHASE.AfterModMain)
        assert_eq(host_nojit:status("jit.runtime"), STATUS.Disabled, "jit.runtime no-luajit Disabled")

        -- HideGlobalJIT true clears global jit
        rawset(_G, "jit", jit_stub)
        local host_hide = PluginHost.new()
        host_hide:register_all(list)
        local cfg2 = {}
        for k, v in pairs(base) do
            cfg2[k] = v
        end
        cfg2.EnabledJIT = false
        cfg2.HideGlobalJIT = true
        host_hide:resolve(cfg2, {
            injector = inj,
            has_luajit = true,
            is_windows = true,
            jit = jit_stub,
            mod_env = { modinfo = { luajit_compatible = true }, jit = jit_stub },
        })
        host_hide:load_phase(PHASE.AfterModMain)
        assert_eq(host_hide:status("jit.runtime"), STATUS.Loaded, "hide path Loaded")
        assert_eq(rawget(_G, "jit"), nil, "global jit hidden")
    end)
    restore_m4_game_stubs(prev)
    if not ok then
        error(err, 0)
    end
    print("PASS: jit_runtime_enable_matrix")
end

-- Required L-C cases from task brief: topo, hard dep missing, option off, priority
test_empty_registry()
test_topo_linear()
test_topo_diamond()
test_soft_dep_missing()
test_soft_dep_present()
test_hard_dep_missing()
test_conflict_both_enabled()
test_conflict_one_enabled()
test_cycle_three()
test_phase_barrier()
test_option_off()
test_option_on_shorthand()
test_string_predicate()
test_load_throw_fails_dependents()
test_priority_tiebreak()
test_profiler_before_hide()
test_when_false()
test_sticky_and_reload()
test_config_function_getmodconfigdata()
test_option_rules_unit()
test_save_fork_enable_matrix()
test_sim_lagcomp_enable_matrix()
test_network_sim_enable_matrix()
test_network_rpc_enable_matrix()
test_network_entity_enable_matrix()
test_m4_plugin_priorities_and_order()
test_debug_profiler_enable_matrix()
test_gc_policy_enable_matrix()
test_fps_render_enable_matrix()
test_jit_tailcall_enable_matrix()
test_jit_runtime_enable_matrix()

print("plugin_host_lua_spec: all tests passed")
