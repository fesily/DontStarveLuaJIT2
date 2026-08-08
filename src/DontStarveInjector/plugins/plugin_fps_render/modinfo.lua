-- plugins/plugin_fps_render/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).
-- Native face is AlwaysOn so exports stay mapped; Lua options gate AfterModMain work.

-- Engine-required / compatibility (DST InitializeModInfo)
name = "FPS Render"
description = "Target render FPS for DontStarveLuaJit2 (feature package)."
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
priority = 50
-- configuration_options = nil  -- embedded: UI on parent Mod; standalone may fill later

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "fps.render"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative + AlwaysOn
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
-- Number options: host is_bool_on treats non-zero as on (default 60fps is enabled).
-- Native OptionRuleKind is AlwaysOn (identity gate skips AllOf/AnyOf key match).
options = { option = "TargetRenderFPS" }

when = function(ctx)
    if ctx and ctx.is_windows == false then
        return false
    end
    return true
end
