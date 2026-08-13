-- plugins/plugin_debug_jitterprobe/modinfo.lua
-- Temporary investigation probe for client movement prediction OFF jitter.

name = "Debug Jitter Probe"
description = "Client-only movement jitter probes (prediction-OFF path) for DontStarveLuaJit2."
author = "fesil"
version = "1.0.0"
api_version = 10

dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true

client_only_mod = true
server_only_mod = false
all_clients_require_mod = false

priority = 15

plugin_id = "debug.jitterprobe"
phases = "AfterModMain"
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false

configuration_options = {
    {
        name = "EnableJitterProbe",
        label = translate({ en = "Jitter Probe", zh = "抖动探测" }),
        hover = translate({
            en = "Client prediction-OFF movement jitter logs (Win x64)",
            zh = "客户端预测关闭时的移动抖动日志（仅Win x64）",
        }),
        options = {
            { description = translate({ en = "Disabled", zh = "关闭" }), data = false },
            { description = translate({ en = "Enabled", zh = "开启" }), data = true },
        },
        default = false,
        host_gate = true,
    },
}

when = function(ctx)
    -- Native probe needs Injector exports; require("jit") is not required (game VM OK).
    if not ctx then
        return false
    end
    if ctx.injector == nil and not ctx.has_luajit then
        return false
    end
    local is_windows = ctx.is_windows
    if is_windows == nil then
        is_windows = (_G.IsWin32 and _G.IsWin32()) or false
    end
    if not is_windows then
        return false
    end
    if ctx.is_client ~= nil then
        return ctx.is_client
    end
    if TheNet and TheNet.IsDedicated then
        return not TheNet:IsDedicated()
    end
    return true
end
