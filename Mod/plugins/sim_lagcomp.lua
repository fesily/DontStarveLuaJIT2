-- Lua face of dual-face plugin sim.lagcomp (native APIs already exported by GameSimHook).
-- Mirrors former modmain hard-wire: has_luajit + windows + mastersim + EnableLagCompensation
-- → scripts/lag_compensation.

return {
    id = "sim.lagcomp",
    version = "1.0.0",
    depends = {},
    soft_depends = {},
    conflicts = {},
    phases = "AfterModMain",
    options = { all_of = { "EnableLagCompensation" } },
    support_reload = false,
    priority = 60,
    when = function(ctx)
        -- Prefer gate_ctx from modmain; fall back to globals when absent.
        if not ctx or not ctx.has_luajit then
            return false
        end
        local is_windows = ctx.is_windows
        if is_windows == nil then
            is_windows = (_G.IsWin32 and _G.IsWin32()) or false
        end
        if not is_windows then
            return false
        end
        if ctx.is_mastersim ~= nil then
            return ctx.is_mastersim
        end
        return TheWorld ~= nil and TheWorld.ismastersim
    end,
    load = function(ctx)
        modimport("scripts/lag_compensation")
    end,
    unload = function(ctx)
        -- Sticky by default; FindEntities wrap is not torn down.
    end,
}
