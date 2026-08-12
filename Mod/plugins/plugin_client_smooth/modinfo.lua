-- plugins/plugin_client_smooth/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).

-- Engine-required / compatibility (DST InitializeModInfo)
name = "Client Smooth"
description = "Local-player display smooth when movement prediction is OFF."
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
priority = 55
-- configuration_options = nil  -- embedded: UI on parent Mod; standalone may fill later

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "client.smooth"
phases = "AfterModMain"
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
options = { all_of = { "EnableClientSmooth" } }

when = function(ctx)
    -- Pure Lua display path: do not require require("jit") (LuaVmType=game has no jit).
    -- Need client + Injector/mod host context.
    if not ctx then
        return false
    end
    if ctx.injector == nil and not ctx.has_luajit then
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
