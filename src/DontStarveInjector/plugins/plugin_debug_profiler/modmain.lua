-- plugins/plugin_debug_profiler/modmain.lua
-- EnableProfiler / EnableTracy + GC policy (FullGC / FrameGC).
-- Priority 20: must load before jit.runtime (70) HideGlobalJIT so jit.zone / jit.p remain requireable.
-- Absorbs former gc.policy: always reset fullgc/framegc when load runs, then apply flags.

local function get_config(key)
    if type(GetModConfigData) == "function" then
        return GetModConfigData(key)
    end
    return nil
end

local injector = GameInjector
if not injector then
    return
end

local function EnableProfiler(mode)
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

local function EnableTracy()
    injector.DS_LUAJIT_replace_profiler_api()
    injector.DS_LUAJIT_enable_tracy(1)
end

local function ApplyGcPolicy()
    -- Match former gc.policy / modmain: always clear, then re-enable when not GenGC.
    injector.DS_LUAJIT_disable_fullgc(false)
    injector.DS_LUAJIT_enable_framegc(false)

    if get_config("EnabledGenGC") then
        return
    end

    if get_config("DisableForceFullGC") then
        injector.DS_LUAJIT_replace_profiler_api()
        injector.DS_LUAJIT_disable_fullgc(true)
    end

    if get_config("EnableFrameGC") then
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

-- 1) GC reset + DisableForceFullGC / EnableFrameGC (former gc.policy)
ApplyGcPolicy()

-- 2) EnableProfiler mode / EnableTracy
local mode = get_config("EnableProfiler")
if mode ~= nil and tostring(mode) ~= "off" and tostring(mode) ~= "" then
    EnableProfiler(mode)
end

if tostring(get_config("EnableTracy") or "") == "on" then
    EnableTracy()
end
