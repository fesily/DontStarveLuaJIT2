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
    package.loaded["plugins.save_fork"] = nil
    package.loaded["plugins.sim_lagcomp"] = nil
    package.loaded["plugins.network_sim"] = nil
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
    package.loaded["plugins.save_fork"] = nil
    package.loaded["plugins.sim_lagcomp"] = nil
    package.loaded["plugins.network_sim"] = nil
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
    package.loaded["plugins.save_fork"] = nil
    package.loaded["plugins.sim_lagcomp"] = nil
    package.loaded["plugins.network_sim"] = nil
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
    print("PASS: option_rules_unit")
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
test_save_fork_enable_matrix()
test_sim_lagcomp_enable_matrix()
test_network_sim_enable_matrix()
test_option_rules_unit()

print("plugin_host_lua_spec: all tests passed")
