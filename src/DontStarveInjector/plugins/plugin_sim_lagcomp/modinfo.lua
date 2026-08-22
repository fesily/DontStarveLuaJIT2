-- plugins/plugin_sim_lagcomp/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).

-- Engine-required / compatibility (DST InitializeModInfo)
name = "Sim Lag Compensation"
description = "Master-sim lag compensation for DontStarveLuaJit2 (feature package)."
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
plugin_id = "sim.lagcomp"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative in C++ projection
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false

configuration_options = {
    {
        name = "EnableLagCompensation",
        label = translate({ en = "Lag Compensation (Preview)", zh = "延迟补偿" }),
        hover = translate({
            en = "Extrapolate remote player positions before spatial queries. Server-side only, Win x64 only.",
            zh = "在空间查询前外推远程玩家位置。仅服务端生效，仅支持 Win x64。",
        }),
        options = toggle,
        default = false,
        disabled_value = false,
        disabled_by = {
            option = "LuaVmType",
            values = { "lua51", "game" },
            reason = translate({ en = "Not compatible with Lua 5.1 VM", zh = "与Lua 5.1虚拟机不兼容" }),
        },
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
        return ctx.is_mastersim
    end
    return TheWorld ~= nil and TheWorld.ismastersim
end
