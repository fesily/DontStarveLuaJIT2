local G = GLOBAL
if not G or G.rawget(G, "WORLDGEN_MAIN") == nil then
    return
end

local getenv = G.os.getenv
local seed = G.tonumber(getenv("DS_PERF_SEED"))
G.assert(seed, "DS_PERF_SEED is required")
G.rawset(G, "SEED", seed)

local jit = G.rawget(G, "jit")
local jit_mode = getenv("DS_PERF_JIT") or "default"
local sample_lua = getenv("DS_PERF_SAMPLE_LUA") == "1"
local profile = sample_lua and jit and G.require("jit.profile") or nil
local diagnose_jit = getenv("DS_PERF_JIT_DIAGNOSTICS") == "1" and jit
local jutil = diagnose_jit and G.require("jit.util") or nil
local vmdef = diagnose_jit and G.require("jit.vmdef") or nil
local json = diagnose_jit and G.require("json") or nil
local jit_options = getenv("DS_PERF_JIT_OPTIONS")
if jit and jit_options then
    local opt = G.require("jit.opt")
    for option in G.string.gmatch(jit_options, "[^,]+") do
        opt.start(option)
    end
end
local vm = G.GameInjector and G.GameInjector.DS_LUAJIT_get_vm_type_name(0) or "unknown"
G.print("[ds_perf] VM type=" .. G.tostring(vm) ..
    " jit=" .. G.tostring(jit and jit.status() or false) ..
    " version=" .. G.tostring(jit and jit.version or "none"))

-- forest_map is loaded before worldgen mods; retain the engine's retry logic.
local forest = G.require("map/forest_map")
local generate = forest.Generate
local attempt = 0
forest.Generate = function(...)
    attempt = attempt + 1
    local previous_jit = jit and jit.status() or false
    if jit and jit_mode == "on" then
        jit.on()
    elseif jit and jit_mode == "off" then
        jit.off()
    end
    local counts = {}
    local trace_counts, trace_aborts, trace_rows, abort_locations = {}, {}, {}, {}
    local trace_epoch, trace_started, compile_seconds = 0, nil, 0
    local map_started
    local trace_hook
    local memory_before = diagnose_jit and G.collectgarbage("count") or nil
    if diagnose_jit then
        trace_hook = function(what, tr, func, pc, err, detail)
            local now = G.walltime()
            trace_counts[what] = (trace_counts[what] or 0) + 1
            if what == "start" then
                trace_started = now
            elseif what == "flush" then
                for _, row in G.ipairs(trace_rows) do
                    if row.epoch == trace_epoch then
                        row.valid_until_seconds = now - map_started
                    end
                end
                trace_epoch = trace_epoch + 1
            elseif what == "abort" then
                compile_seconds = compile_seconds + (trace_started and now - trace_started or 0)
                trace_started = nil
                local reason = G.type(err) == "number" and vmdef.traceerr[err] or G.tostring(err)
                if G.type(err) == "number" then
                    if G.type(detail) == "function" then
                        detail = jutil.funcinfo(detail).loc or "C function"
                    elseif reason == "NYI: bytecode %s" then
                        detail = G.string.sub(vmdef.bcnames, 6 * detail + 1, 6 * detail + 6)
                    end
                    reason = G.string.format(reason, detail)
                end
                trace_aborts[reason] = (trace_aborts[reason] or 0) + 1
                local fi = func and jutil.funcinfo(func, pc) or {}
                local location = reason .. " at " .. (fi.loc or "unknown")
                abort_locations[location] = (abort_locations[location] or 0) + 1
            elseif what == "stop" then
                compile_seconds = compile_seconds + (trace_started and now - trace_started or 0)
                trace_started = nil
                local info = jutil.traceinfo(tr)
                local code, address = jutil.tracemc(tr)
                local fi = func and jutil.funcinfo(func, pc) or {}
                trace_rows[#trace_rows + 1] = {
                    trace = tr, linktype = info.linktype, link = info.link,
                    nins = info.nins, nexit = info.nexit,
                    address = address, size = code and #code or 0,
                    location = fi.loc, source = fi.source, line = fi.currentline,
                    elapsed_seconds = now - map_started, epoch = trace_epoch,
                }
            end
        end
    end
    local original_require = G.require
    if sample_lua then
        local require_depth = 0
        G.require = function(name)
            require_depth = require_depth + 1
            local loading = require_depth == 1 and not G.package.loaded[name]
            if loading then
                G.print("[ds_perf] REQUIRE_BEGIN name=" .. G.tostring(name))
            end
            local result = original_require(name)
            if loading then
                G.print("[ds_perf] REQUIRE_END name=" .. G.tostring(name))
            end
            require_depth = require_depth - 1
            return result
        end
    end
    if profile then
        profile.start("li5", function(thread, samples, state)
            local stack = profile.dumpstack(thread, "pf|lZ;", 12)
            local key = state .. " " .. stack
            counts[key] = (counts[key] or 0) + samples
        end)
    end
    local jit_enabled = jit and jit.status() or false
    map_started = G.walltime()
    if trace_hook then
        jit.attach(trace_hook, "trace")
    end
    G.print("[ds_perf] MAP_BEGIN attempt=" .. attempt ..
        " seed=" .. G.tostring(G.rawget(G, "SEED")) ..
        " jit=" .. G.tostring(jit_enabled))
    local savedata = generate(...)
    if trace_hook then
        jit.attach(trace_hook)
    end
    if profile then
        profile.stop()
    end
    if jit and jit_mode ~= "default" then
        if previous_jit then
            jit.on()
        else
            jit.off()
        end
    end
    G.print(G.string.format("[ds_perf] MAP_END attempt=%d ok=%s",
        attempt, G.tostring(savedata ~= nil)))
    if diagnose_jit then
        G.print("[ds_perf] TRACE_SUMMARY attempt=" .. attempt .. " " .. json.encode({
            events = trace_counts, aborts = trace_aborts,
            trace_record_compile_wall_seconds = compile_seconds,
            memory_before_kb = memory_before,
            memory_after_kb = G.collectgarbage("count"),
        }))
        for location, count in G.pairs(abort_locations) do
            G.print("[ds_perf] TRACE_ABORT attempt=" .. attempt .. " " .. json.encode({
                location = location, count = count,
            }))
        end
        for _, row in G.ipairs(trace_rows) do
            G.print("[ds_perf] TRACE_ROW attempt=" .. attempt .. " " .. json.encode(row))
        end
    end
    if sample_lua then
        G.require = original_require
        if profile then
            local rows = {}
            for key, count in G.pairs(counts) do
                rows[#rows + 1] = {key = key, count = count}
            end
            G.table.sort(rows, function(a, b) return a.count > b.count end)
            for _, row in G.ipairs(rows) do
                G.print(G.string.format("[ds_perf] SAMPLE attempt=%d count=%d state=%s stack=%s",
                    attempt, row.count, row.key:sub(1, 1), row.key:sub(3)))
            end
        end
    end
    return savedata
end
