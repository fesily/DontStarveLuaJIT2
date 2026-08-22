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
-- Native OptionRuleKind is AlwaysOn; no host_gate (widgets display-only).

configuration_options = {
    {
        name = "ShadowSunDrive",
        label = translate({ en = "Sun-driven shadows", zh = "太阳驱动的阴影" }),
        options = {
            {description = translate({ en = "Off", zh = "关闭" }), data = false},
            {description = translate({ en = "On", zh = "开启" }), data = true},
        },
        default = false,
    },
    {
        name = "ShadowSilhouetteBatch",
        label = translate({ en = "Silhouette batch shadows", zh = "剪影批阴影" }),
        hover = translate({
            en = "Exclusive with sun-driven ellipses; both on → silhouette wins.",
            zh = "与太阳驱动椭圆互斥；同时开启时以剪影为准。",
        }),
        options = {
            {description = translate({ en = "Off", zh = "关闭" }), data = false},
            {description = translate({ en = "On", zh = "开启" }), data = true},
        },
        default = false,
    },
    {
        name = "ShadowLengthBoost",
        label = translate({ en = "Shadow length boost", zh = "阴影长度增强" }),
        options = {
            {description = "0.5", data = 0.5},
            {description = "1.0", data = 1.0},
            {description = "1.5", data = 1.5},
            {description = "2.0", data = 2.0},
        },
        default = 1.0,
    },
    {
        name = "ShadowHemisphere",
        label = translate({ en = "Shadow hemisphere", zh = "阴影半球" }),
        hover = translate({
            en = "Northern: dawn shadow SE, dusk NW (TL). Southern: mirrored.",
            zh = "北半球：黎明影子朝东南、黄昏朝西北（晨昏线）。南半球取反。",
        }),

        options = {
            {description = translate({ en = "Northern", zh = "北半球" }), data = "north"},
            {description = translate({ en = "Southern", zh = "南半球" }), data = "south"},
        },
        default = "north",
    },
}

when = function(ctx)
    if ctx and ctx.is_windows == false then
        return false
    end
    return true
end
