-- plugins/plugin_network_sim/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).

-- Engine-required / compatibility (DST InitializeModInfo)
name = "Network Sim"
description = "Client-side network simulator for DontStarveLuaJit2 (feature package)."
author = "fesil"
version = "1.0.0"
api_version = 10

dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true

client_only_mod = true
server_only_mod = false
all_clients_require_mod = false

-- Optional engine
priority = 60

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "network.sim"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative in C++ projection
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false

configuration_options = {
    {
        name = "EnableNetSim",
        label = translate({ en = "Enable Network Simulator", zh = "启用网络模拟器" }),
        hover = translate({
            en = "Simulate packet delay/jitter/loss (client-side, Win x64 only)",
            zh = "模拟网络延迟/抖动/丢包（仅客户端，仅Win x64）",
        }),
        options = toggle,
        default = false,
        disabled_value = false,
        disabled_by = disable_by_non_win,
        host_gate = true,
    },
}

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
        return not ctx.is_mastersim
    end
    return TheWorld ~= nil and not TheWorld.ismastersim
end
