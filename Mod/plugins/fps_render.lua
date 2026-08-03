-- fps.render — TargetRenderFPS → DS_LUAJIT_set_target_fps + SetNetbookMode.
-- Priority 50 per §7.3. Non-Windows GetModConfigData returns nil (HookGetModConfigData).

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
    id = "fps.render",
    version = "1.0.0",
    depends = {},
    soft_depends = {},
    conflicts = {},
    phases = "AfterModMain",
    -- Number options: host is_bool_on treats non-zero as on (default 60fps is enabled).
    options = { option = "TargetRenderFPS" },
    support_reload = false,
    priority = 50,
    when = function(ctx)
        if ctx and ctx.is_windows == false then
            return false
        end
        return true
    end,
    load = function(ctx)
        local injector = ctx and ctx.injector
        if not injector then
            return
        end
        local targetfps = get_config(ctx, "TargetRenderFPS")
        if not targetfps then
            return
        end
        if injector.DS_LUAJIT_set_target_fps(targetfps, 1) > 0 then
            print("Reset fps by SetNetbookMode", targetfps)
            TheSim:SetNetbookMode(false)
        end
    end,
    unload = function(ctx)
        -- Sticky by default.
    end,
}
