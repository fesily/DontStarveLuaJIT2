-- gc.policy — DisableForceFullGC + EnableFrameGC.
-- Priority 30 per §7.3. GenGC disables both via modinfo disabled_by (already resolved by GetModConfigData).
-- AlwaysOn: always reset fullgc/framegc false, then apply options when EnabledGenGC is off.

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

return {
    id = "gc.policy",
    version = "1.0.0",
    depends = {},
    soft_depends = {},
    conflicts = {},
    phases = "AfterModMain",
    options = { always = true },
    support_reload = false,
    priority = 30,
    load = function(ctx)
        local injector = ctx and ctx.injector
        if not injector then
            return
        end

        -- Match former modmain: always clear, then re-enable from options when not GenGC.
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
    end,
    unload = function(ctx)
        -- Sticky by default.
    end,
}
