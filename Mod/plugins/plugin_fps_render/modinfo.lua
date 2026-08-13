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

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "fps.render"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative + AlwaysOn
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false

-- Number options: host is_bool_on treats non-zero as on (default 60fps is enabled).
-- Native OptionRuleKind is AlwaysOn (identity gate skips AllOf/AnyOf key match).
configuration_options = {
    {
        name = "TargetRenderFPS",
        label = translate({ en = "Render FPS", zh = "渲染帧率" }),
        hover = translate({
            en = "Render FPS",
            zh = "渲染帧率",
        }),
        options = {
            { description = translate({ en = "off", zh = "禁用" }), data = 60 },
            { description = "30fps", data = 30 },
            { description = "60fps", data = 60 },
            { description = "90fps", data = 90 },
            { description = "120fps", data = 120 },
            { description = "144fps", data = 144 },
            { description = "165fps", data = 165 },
            { description = "200fps", data = 200 },
            { description = "240fps", data = 240 },
        },
        default = 60,
        host_gate = true,
    },
}

when = function(ctx)
    if ctx and ctx.is_windows == false then
        return false
    end
    return true
end
