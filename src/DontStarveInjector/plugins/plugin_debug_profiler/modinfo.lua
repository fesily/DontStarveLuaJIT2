-- plugins/plugin_debug_profiler/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).
-- Native face is AlwaysOn so exports stay mapped; Lua options gate AfterModMain work.

-- Engine-required / compatibility (DST InitializeModInfo)
name = "Debug Profiler"
description = "Profiler / Tracy / FullGC / FrameGC for DontStarveLuaJit2 (feature package)."
author = "fesil"
version = "1.0.0"
api_version = 10

dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true

client_only_mod = false
server_only_mod = false
all_clients_require_mod = false

-- Optional engine
priority = 20
-- configuration_options = nil  -- embedded: UI on parent Mod; standalone may fill later

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "debug.profiler"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative + AlwaysOn
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
-- User-facing keys (Lua gate); native OptionRuleKind is AlwaysOn (identity gate skips AllOf/AnyOf key match).
options = {
    any_of = {
        "EnableProfiler",
        "EnableTracy",
        "DisableForceFullGC",
        "EnableFrameGC",
    },
}

when = function(ctx)
    if not ctx or not ctx.has_luajit then
        return false
    end
    return true
end
