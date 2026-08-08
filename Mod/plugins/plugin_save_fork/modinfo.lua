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
-- configuration_options = nil  -- embedded: UI on parent Mod; standalone may fill later

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "save.fork"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative in C++ projection
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
options = { all_of = { "EnableForkSave" } }

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
