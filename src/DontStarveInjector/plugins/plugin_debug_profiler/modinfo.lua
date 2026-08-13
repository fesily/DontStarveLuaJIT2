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

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "debug.profiler"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative + AlwaysOn
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false

-- User-facing keys (Lua gate); native OptionRuleKind is AlwaysOn (identity gate skips AllOf/AnyOf key match).
configuration_options = {
    {
        name = "DisableForceFullGC",
        label = translate({ en = "GC Incremental Only", zh = "禁用强制完全gc,仅gc小部分" }),
        hover = translate({
            en = "Enabling this feature will result in a larger memory footprint, and will alleviate occasional lagging issues",
            zh = "启用该选项会导致更大的内存占用,将缓解偶发卡顿问题",
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_gen_gc,
        host_gate = "any_of",
    },
    {
        name = "EnableFrameGC",
        label = translate({ en = "Frame GC", zh = "帧间gc" }),
        hover = translate({
            en = "GC during idle time between frames",
            zh = "见缝插针地gc",
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_gen_gc,
        host_gate = "any_of",
    },
    {
        name = "EnableProfiler",
        label = translate({ en = "Enable Profiler Command", zh = "启用性能分析控制台命令" }),
        hover = translate({ en = "ProfilerJit.start | ProfilerJit.stop", zh = "ProfilerJit.start | ProfilerJit.stop" }),
        options = {
            { description = translate({ en = "off", zh = "关闭" }), data = "off" },
            { description = translate({ en = "Detailed Sampling Mode", zh = "详细采样模式" }), data = "fzvp" }, -- 会展示完整的代码路径和行数，以及虚拟机状态，还有模块zone采样点
            { description = translate({ en = "Origin Sampling Mode", zh = "原始采样模式" }), data = "Gz" }, -- 等于EnableTracy，不过是luajit自带的分析器
        },
        default = "off",
        host_gate = "any_of",
    },
    {
        name = "EnableTracy",
        label = translate({ en = "Enable Tracy", zh = "启用性能追踪" }),
        options = {
            { description = translate({ en = "off", zh = "关闭" }), data = "off" },
            { description = translate({ en = "on", zh = "开启" }), data = "on" },
        },
        default = "off",
        host_gate = "any_of",
    },
}

when = function(ctx)
    if not ctx or not ctx.has_luajit then
        return false
    end
    return true
end
