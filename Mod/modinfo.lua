---@diagnostic disable: lowercase-global
local lc = locale

local function translate(t)
    t.zhr = t.zh
    t.zht = t.zht or t.zh
    return t[lc] or t.en
end
name = "DontStarveLuaJit2"

description = translate(
    {
        zh = [[
        替换游戏底层虚拟机为LUAJIT,加速整个游戏
        务必备份你的存档,不保证没错误
    ]],
        en = [[
        Replaces the underlying VM with luajit to speed up the entire game.
        Make sure to back up your saves! There is no guarantee that there are no bugs!
    ]]
    }
)

author = "fesil"

version = "2.7.3"

--forumthread = "https://github.com/fesily/DontStarveLuaJit2"

api_version = 10

dont_starve_compatible = true
reign_of_giants_compatible = true
dst_compatible = true
luajit_compatible = true
--TODO: need test compatible without the mod
--all_clients_require_mod = true
client_only_mod = true
server_only_mod = true

priority = 2e53

-- Preview image
icon_atlas = "modicon.xml"
icon = "modicon.tex"

mod_dependencies  = {
    -- "buttonpicker",
    -- "workshop-3317960157",
}

local toggle = {
    { description = translate({ en = "On", zh = "启用" }), data = true },
    { description = translate({ en = "Off", zh = "禁用" }), data = false },
}

local luavmtype = {
    jit = 'jit',
    game = 'game',
    _51 = 'lua51',
    jit_gen = 'jit_gen',
}

local section_counter = 0
local function AddSection(label, hover)
    section_counter = section_counter + 1

    return {
        section_start = true,
        name = "SECTION_" .. section_counter,
        label = label,
        hover = hover,
        options = { { description = "", data = "" } },
        default =
        ""
    }
end

local disable_by_gen_gc = {
    option = "EnabledGenGC",
    value = true,
    reason = translate({ en = "Not compatible with generational GC", zh = "与分代GC不兼容" }),
}
local disable_by_lua51 = {
    option = "LuaVmType",
    values = { luavmtype._51, luavmtype.game },
    reason = translate({ en = "Not compatible with Lua 5.1 VM", zh = "与Lua 5.1虚拟机不兼容" }),
}
local disable_by_non_win = platform_info and not (platform_info.os == "Windows") or false
configuration_options = {
    AddSection(translate({ en = "General Options", zh = "通用选项" })),
    {
        name = "DisableForceFullGC",
        label = translate({ en = "GC Incremental Only", zh = "禁用强制完全gc,仅gc小部分" }),
        hover = translate({
            en =
            "Enabling this feature will result in a larger memory footprint, and will alleviate occasional lagging issues",
            zh = "启用该选项会导致更大的内存占用,将缓解偶发卡顿问题"
        }),
        options = {
            { description = translate({ en = "off", zh = "禁用" }), data = 0 },
            { description = "gc 1MB", data = 1 },
            { description = "gc 2MB", data = 2 },
            { description = "gc 4MB", data = 4 },
            { description = "gc 8MB", data = 8 },
            { description = "gc 16MB", data = 16 },
            { description = "gc 32MB", data = 32 },
            { description = "gc 64MB", data = 64 },
            { description = "gc 128MB", data = 128 },
            { description = "gc 256MB", data = 256 },
            { description = "gc 512MB", data = 512 },
        },
        default = 1,
        disabled_value = 0,
        disabled_by = disable_by_gen_gc
    },
    {
        name = "EnableFrameGC",
        label = translate({ en = "Frame GC", zh = "帧间gc" }),
        hover = translate({
            en = "GC during idle time between frames",
            zh = "见缝插针地gc"
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_gen_gc
    },
    {
        name = "TargetRenderFPS",
        label = translate({ en = "Render FPS", zh = "渲染帧率" }),
        hover = translate({
            en = "Render FPS",
            zh = "渲染帧率"
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
        default = 60
    },
    {
        name = "AlwaysEnableMod",
        label = translate({ en = "Always Enable Mod", zh = "总是启用mod" }),
        hover = translate({
            zh = "强制启用当前mod,即使它在mod设置中没有启用",
            en = "Force enable the current mod, even if it is not enabled in the mod settings"
        }),
        options = toggle,
        default = true,
    },
    {
        name = "NetworkOpt",
        label = translate({ en = "Network RPC Optimizations", zh = "网络RPC优化" }),
        hover = translate({
            en = "Optimize network rpc transmission, out-of-order sending of RPCs, may have unexpected situations",
            zh = "优化网络RPC传输, 并行发送RPC, 可能导致意外的情况"
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_non_win,
    },
    {
        name = "NetworkOptEntity",
        label = translate({ en = "Network Entity Optimizations", zh = "网络实体优化" }),
        hover = translate({
            en = "Optimize network entity transmission, out-of-order sending of entities, may have unexpected situations",
            zh = "优化网络实体传输, 并行发送实体, 可能导致意外的情况"
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_non_win,
    },
    AddSection(translate({ en = "JitOptions", zh = "JIT选项" })),
    {
        name = "EnabledJIT",
        label = translate({ en = "Enable JIT", zh = "开启JIT模式" }),
        hover = translate({
            en = "Recommend to turn this off if there is severe lag in the game",
            zh = "在游戏中卡顿现象很严重的建议关闭"
        }),
        options = toggle,
        default = true
    },
    {
        name = "LuaVmType",
        label = translate({ en = "Lua VM Type", zh = "Lua虚拟机类型" }),
        hover = translate({
            en = "Choose the Lua VM type",
            zh = "选择Lua虚拟机类型"
        }),
        options = {
            { description = translate({ en = "LuaJIT", zh = "LuaJIT" }), data = luavmtype.jit },
            { description = translate({ en = "Game Default VM", zh = "游戏默认虚拟机" }), data = luavmtype.game },
            -- { description = translate({ en = "Lua 5.1", zh = "lua 5.1" }), data = luavmtype._51 },
        },
        default = luavmtype.jit,
        disabled_value = luavmtype.jit_gen,
        disabled_by = disable_by_gen_gc
    },
    -- {
    --     name = "ClientNetWorkTick",
    --     label = translate({ en = "Client network sync tick", zh = "客户端网络发包频率" }),
    --     hover = translate({
    --         en =
    --         "Client network sync frequency, the download frequency is 1.5 times the current setting. Default (10fps for upload, 15fps for download).",
    --         zh = "客户端网络同步频率,下行频率=当前设置*1.5.默认(上行10fps,下行15fps)."
    --     }),
    --     options = {
    --         { description = translate({ en = "off", zh = "禁用" }), data = 10 },
    --         { description = "15fps", data = 15 },
    --         { description = "20fps", data = 20 },
    --         { description = "25fps", data = 25 },
    --         { description = "30fps", data = 30 },
    --         { description = "32fps", data = 32 },
    --         { description = "35fps", data = 35 },
    --         { description = "40fps", data = 40 },
    --         { description = "45fps", data = 45 },
    --         { description = "50fps", data = 50 },
    --         { description = "55fps", data = 55 },
    --         { description = "60fps", data = 60 },
    --         { description = "64fps", data = 64 },
    --         { description = "75fps", data = 75 },
    --         { description = "90fps", data = 90 },
    --         { description = "115fps", data = 115 },
    --         { description = "120fps", data = 120 },
    --     },
    --     default = 10
    -- },
    -- {
    --     name = "ServerNetWorkTick",
    --     label = translate({ en = "Server network sync tick", zh = "服务器网络同步频率" }),
    --     hover = translate({
    --         en =
    --         "Server network sync tick, the same frequency for both upload and download. Default (15fps for upload, 0fps for download).",
    --         zh = "服务器网络同步频率,默认(上行15fps,下行0fps)."
    --     }),
    --     options = {
    --         { description = translate({ en = "off", zh = "禁用" }), data = 15 },
    --         { description = "20fps", data = 20 },
    --         { description = "25fps", data = 25 },
    --         { description = "30fps", data = 30 },
    --         { description = "32fps", data = 32 },
    --         { description = "35fps", data = 35 },
    --         { description = "40fps", data = 40 },
    --         { description = "45fps", data = 45 },
    --         { description = "50fps", data = 50 },
    --         { description = "55fps", data = 55 },
    --         { description = "60fps", data = 60 },
    --         { description = "64fps", data = 64 },
    --         { description = "75fps", data = 75 },
    --         { description = "90fps", data = 90 },
    --         { description = "115fps", data = 115 },
    --         { description = "120fps", data = 120 },
    --     },
    --     default = 15
    -- },
    {
        name = "SlowTailCall",
        label = translate({ en = "Slow Tail Call", zh = "慢速尾调用" }),
        hover = translate({
            zh = "模拟原生lua的尾调用堆栈, 加强加密mod兼容, 但会导致性能下降.搭配<启发式检测加密mod>选项食用",
            en =
            "Simulate the tail call stack of native lua, enhance compatibility with encrypted mods, but will cause a performance drop.\nUse with <Heuristic Detection of Encrypted Mods> option"
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_lua51
    },
    {
        name = "AnyModDisableTailCall",
        label = translate({ en = "Any Mod Disable Tail Call", zh = "任何模组都禁用尾调用" }),
        hover = translate({
            zh = "强制模拟原生lua的尾调用堆栈, 加强加密mod兼容",
            en =
            "Force simulate the tail call stack of native lua, enhance compatibility with encrypted mods"
        }),
        options = toggle,
        default = false,
        disabled_value = false,
        disabled_by = disable_by_lua51
    },
    {
        name = "AutoDetectEncryptedMod",
        label = translate({ en = "Heuristic Detection of Encrypted Mods", zh = "启发式检测加密mod" }),
        hover = translate({
            en = "Automatically detect and enable compatibility for encrypted mods",
            zh = "自动检测并启用加密mod的兼容性"
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_lua51
    },
    {
        name = "ModBlackList",
        label = translate({ en = "Mod JIT Blacklist", zh = "MODJit黑名单" }),
        hover = translate({ en = "Some mods may not be appropriate for JIT", zh = "有些mod可能写的特别,不合适jit模式" }),
        options = toggle,
        default = false,
        disabled_value = false,
        disabled_by = disable_by_lua51
    },
    {
        name = "DisableJITWhenServer",
        label = translate({ en = "Disable JIT on Server", zh = "服务器禁用luajit" }),
        hover = translate({ en = "Disable luajit on the server process", zh = "服务器进程禁用luajit" }),
        options = toggle,
        default = false,
        disabled_value = false,
        disabled_by = disable_by_lua51
    },
    AddSection(translate({ en = "Experimental Features", zh = "实验性功能" })),
    {
        name = "EnabledGenGC",
        label = translate({ en = "Enabled generational GC", zh = "启用分代GC" }),
        hover = translate({
            en = "Enable generational GC",
            zh = "启用分代GC"
        }),
        options = toggle,
        default = false,
    },
    {
        name = "EnableVBPool",
        label = translate({ en = "VB Pool (Preview)", zh = "顶点缓冲池" }),
        hover = translate({
            en = "Reuse GPU vertex buffers to reduce allocation overhead. Preview feature.",
            zh = "复用GPU顶点缓冲区以减少分配开销。预览功能。"
        }),
        options = toggle,
        default = false,
        disabled_value = false,
        require_restart = true,
        disabled_by = disable_by_non_win,
    },
    {
        name = "EnableLagCompensation",
        label = translate({ en = "Lag Compensation (Preview)", zh = "延迟补偿" }),
        hover = translate({
            en = "Extrapolate remote player positions before spatial queries. Server-side only, Win x64 only.",
            zh = "在空间查询前外推远程玩家位置。仅服务端生效，仅支持 Win x64。"
        }),
        options = toggle,
        default = false,
        disabled_value = false,
        disabled_by = disable_by_non_win or disable_by_lua51,
    },
    {
        name = "AngleBackend",
        label = translate({ en = "Rendering Engine", zh = "渲染后端" }),
        hover = translate({
            en = "Choose the rendering backend for ANGLE.",
            zh = "选择ANGLE的渲染后端"
        }),
        options = {
            { description = translate({ en = "Auto", zh = "自动" }), data = "auto" },
            { description = translate({ en = "Vulkan", zh = "Vulkan" }), data = "vulkan" },
            { description = translate({ en = "D3D11", zh = "D3D11" }), data = "d3d11" },
            { description = translate({ en = "D3D9", zh = "D3D9" }), data = "d3d9" },
        },
        default = "auto",
        disabled_by = disable_by_non_win,
        disabled_value = "auto",
        require_restart = true,
    },
    AddSection(translate({ en = "DebugOptions", zh = "调试选项" })),
    {
        name = "ForceDisableTailCall",
        label = translate({ en = "Force Disable Tail Call", zh = "强制禁用尾调用" }),
        hover = translate({
            zh = "强制禁用尾调用优化, 仅用于区别是否因尾调用问题导致的mod不兼容, 非调试不应该使用",
            en =
            "Force disable tail call optimization, used to determine if mod incompatibility is caused by inconsistent tail calls, should not be used in non-debugging"
        }),
        options = toggle,
        default = false,
        disabled_value = false,
        disabled_by = disable_by_lua51
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
        default = 'off'
    },
    {
        name = "EnableTracy",
        label = translate({ en = "Enable Tracy", zh = "启用性能追踪" }),
        options = {
            { description = translate({ en = "off", zh = "关闭" }), data = "off" },
            { description = translate({ en = "on", zh = "开启" }), data = "on" },
        },
        default = 'off'
    },
    AddSection(translate({ en = "Network Simulation", zh = "网络模拟" })),
    {
        name = "EnableNetSim",
        label = translate({ en = "Enable Network Simulator", zh = "启用网络模拟器" }),
        hover = translate({ en = "Simulate packet delay/jitter/loss (client-side, Win x64 only)", zh = "模拟网络延迟/抖动/丢包（仅客户端，仅Win x64）" }),
        options = toggle,
        default = false,
        disabled_value = false,
        disabled_by = disable_by_non_win,
    },
}
--restart_required = true
