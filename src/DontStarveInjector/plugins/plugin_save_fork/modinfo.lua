-- plugins/plugin_save_fork/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).

-- Engine-required / compatibility (DST InitializeModInfo)
name = "Save Fork"
description = "Dedicated-server fork save path for DontStarveLuaJit2 (feature package)."
author = "fesil"
version = "1.0.0"
api_version = 10

dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true

client_only_mod = false
server_only_mod = true
all_clients_require_mod = false

-- Optional engine
priority = 60

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "save.fork"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative in C++ projection
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false

configuration_options = {
    {
        name = "EnableForkSave",
        label = translate({ en = "Fork Save (Preview)", zh = "分叉存档" }),
        hover = translate({
            en = "Fork or clone a child process to save the game, reducing save lag. Supported on Linux, macOS, and Windows x64 preview builds.",
            zh = "通过fork或克隆子进程保存游戏,存档不再卡顿.支持Linux、MacOS和Windows x64预览版",
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_lua51,
        host_gate = true,
    },
}

when = function(ctx)
    -- Called only by package Host, never by KnownModIndex.
    if not ctx or not ctx.has_luajit then
        return false
    end
    if ctx.is_client ~= nil then
        return not ctx.is_client
    end
    return TheNet:IsDedicated()
end
