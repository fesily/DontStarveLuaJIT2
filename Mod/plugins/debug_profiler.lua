-- debug.profiler — EnableProfiler / EnableTracy + GC policy (FullGC / FrameGC).
-- Priority 20: must load before jit.runtime (70) HideGlobalJIT so jit.zone / jit.p remain requireable.
-- Absorbs former gc.policy (priority 30): always reset fullgc/framegc when load runs, then apply flags.
--
-- Option predicates: any of EnableProfiler / EnableTracy / DisableForceFullGC / EnableFrameGC.
-- is_bool_on treats string "off" as off and non-empty modes ("fzvp","Gz","on") as on.

local function get_config(ctx, key)
    local config = ctx and ctx.config
    if type(config) == "function" then
        return config(key)
    end
    if type(config) == "table" then
        return config[key]
    end
    if type(GetModConfigData) == "function" then
        return GetModConfigData(key)
    end
    return nil
end

local function EnableProfiler(injector, mode)
    local zone = require("jit.zone")
    local sim = getmetatable(TheSim).__index
    local old_profiler_push = sim.ProfilerPush
    local old_profiler_pop = sim.ProfilerPop
    rawset(_G, "ProfilerJitEx", {
        start = function(m)
            injector.DS_LUAJIT_enable_profiler(1)
        end,
        stop = function()
            injector.DS_LUAJIT_enable_profiler(0)
        end,
    })
    local profiler = require("jit.p")
    local enabled_profiler = false
    sim.ProfilerPush = function(self, name, ...)
        if enabled_profiler then
            zone(name)
        end
        old_profiler_push(self, name, ...)
    end
    sim.ProfilerPop = function(...)
        if enabled_profiler then
            zone()
        end
        old_profiler_pop(...)
    end
    rawset(_G, "ProfilerJit", {
        start = function(m)
            enabled_profiler = true
            profiler.start(m or mode, "unsafedata/profiler.txt")
        end,
        stop = function()
            enabled_profiler = false
            profiler.stop()
        end,
    })
end

local function EnableTracy(injector)
    injector.DS_LUAJIT_replace_profiler_api()
    injector.DS_LUAJIT_enable_tracy(1)
end

local function ApplyGcPolicy(injector, ctx)
    -- Match former gc.policy / modmain: always clear, then re-enable when not GenGC.
    injector.DS_LUAJIT_disable_fullgc(false)
    injector.DS_LUAJIT_enable_framegc(false)

    if get_config(ctx, "EnabledGenGC") then
        return
    end

    if get_config(ctx, "DisableForceFullGC") then
        injector.DS_LUAJIT_replace_profiler_api()
        injector.DS_LUAJIT_disable_fullgc(true)
    end

    if get_config(ctx, "EnableFrameGC") then
        injector.DS_LUAJIT_replace_profiler_api()
        injector.DS_LUAJIT_enable_framegc(true)

        local old_OnSimPaused = _G.OnSimPaused
        local old_OnSimUnpaused = _G.OnSimUnpaused
        if old_OnSimPaused and old_OnSimUnpaused then
            _G.OnSimPaused = function(...)
                injector.DS_LUAJIT_enable_framegc(false)
                old_OnSimPaused(...)
            end

            _G.OnSimUnpaused = function(...)
                injector.DS_LUAJIT_enable_framegc(true)
                old_OnSimUnpaused(...)
            end
        end
    end
end

return {
    id = "debug.profiler",
    version = "1.0.0",
    depends = {},
    soft_depends = {},
    conflicts = {},
    phases = "AfterModMain",
    -- String feature switches + GC flags; is_bool_on treats "off" as off and "fzvp"/"Gz"/"on" as on.
    options = {
        any_of = {
            "EnableProfiler",
            "EnableTracy",
            "DisableForceFullGC",
            "EnableFrameGC",
        },
    },
    support_reload = false,
    priority = 20,
    when = function(ctx)
        if not ctx or not ctx.has_luajit then
            return false
        end
        return true
    end,
    load = function(ctx)
        local injector = ctx and ctx.injector
        if not injector then
            return
        end

        -- 1) GC reset + DisableForceFullGC / EnableFrameGC (former gc.policy)
        ApplyGcPolicy(injector, ctx)

        -- 2) EnableProfiler mode / EnableTracy
        local mode = get_config(ctx, "EnableProfiler")
        if mode ~= nil and tostring(mode) ~= "off" and tostring(mode) ~= "" then
            EnableProfiler(injector, mode)
        end

        if tostring(get_config(ctx, "EnableTracy") or "") == "on" then
            EnableTracy(injector)
        end
    end,
    unload = function(ctx)
        -- Sticky by default; ProfilerPush wraps / tracy / GC hooks are not torn down.
    end,
}
