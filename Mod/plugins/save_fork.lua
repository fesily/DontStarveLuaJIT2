-- Lua face of dual-face plugin save.fork (native APIs already exported by GameForkSave).
-- Mirrors former modmain hard-wire: dedicated + has_luajit + EnableForkSave → scripts/fork_save.

return {
    id = "save.fork",
    version = "1.0.0",
    depends = {},
    soft_depends = {},
    conflicts = {},
    -- AfterModMain is the Lua host default; keep explicit for dual-face docs.
    phases = "AfterModMain",
    options = { all_of = { "EnableForkSave" } },
    support_reload = false,
    priority = 60,
    when = function(ctx)
        -- Prefer gate_ctx from modmain (has_luajit / is_client); fall back to TheNet.
        if not ctx or not ctx.has_luajit then
            return false
        end
        if ctx.is_client ~= nil then
            return not ctx.is_client
        end
        return TheNet:IsDedicated()
    end,
    load = function(ctx)
        print("Dedicated server, load fork_save")
        -- SaveGame is not always ready at modmain time; preserve historical PostInit deferral.
        AddGamePostInit(function()
            modimport("scripts/fork_save")
        end)
    end,
    unload = function(ctx)
        -- Sticky by default; SaveGame wrap is not torn down.
    end,
}
