-- plugins/plugin_client_anim/modinfo.lua
name = "Client Anim Own"
description = "Pred-OFF local run/idle drive; position stays server-authoritative."
author = "fesil"
version = "1.0.0"
api_version = 10

dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true

client_only_mod = true
server_only_mod = false
all_clients_require_mod = false

priority = 55

plugin_id = "client.anim"
phases = "AfterModMain"
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
options = { all_of = { "EnableClientAnimOwn" } }

when = function(ctx)
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
    -- Client only.
    if ctx.is_client ~= nil then
        return ctx.is_client
    end
    if TheNet and TheNet.IsDedicated and TheNet:IsDedicated() then
        return false
    end
    return true
end
