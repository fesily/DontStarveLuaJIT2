-- plugins/plugin_render_shadow/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).
-- Native face is AlwaysOn so exports stay mapped; Lua AfterModMain applies config.

-- Engine-required / compatibility (DST InitializeModInfo)
name = "Render Shadow (Sun Drive)"
description = "Sun-driven engine DynamicShadow (ellipse). Native AfterModMain apply."
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
plugin_id = "render.shadow"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative + AlwaysOn
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
-- Native OptionRuleKind is AlwaysOn (identity gate skips AllOf/AnyOf key match).
options = { always = true }

configuration_options = {
    {
        name = "ShadowSunDrive",
        label = "Sun-driven shadows",
        options = {
            {description = "Off", data = false},
            {description = "On", data = true},
        },
        default = false,
    },
    {
        name = "ShadowLengthBoost",
        label = "Shadow length boost",
        options = {
            {description = "0.5", data = 0.5},
            {description = "1.0", data = 1.0},
            {description = "1.5", data = 1.5},
            {description = "2.0", data = 2.0},
        },
        default = 1.0,
    },
}

when = function(ctx)
    if ctx and ctx.is_windows == false then
        return false
    end
    return true
end
