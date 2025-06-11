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

version = "1.6.0"

--forumthread = "https://github.com/fesily/DontStarveLuaJit2"

api_version = 10

dont_starve_compatible = true
reign_of_giants_compatible = true
dst_compatible = true

--TODO: need test compatible without the mod
--all_clients_require_mod = true
client_only_mod = true
server_only_mod = true

priority = 2e53

-- Preview image
icon_atlas = "modicon.xml"
icon = "modicon.tex"

local toggle = {
    {description = translate({ en = "On",  zh = "启用" }), data = true},
    {description = translate({ en = "Off", zh = "禁用" }), data = false},
}

configuration_options = {
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
        name = "DisableForceFullGC",
        label = translate({ en = "GC Incremental Only", zh = "禁用强制完全gc,仅gc小部分"}),
        hover = translate({
            en = "Enabling this feature will result in a larger memory footprint, and will alleviate occasional lagging issues",
            zh = "启用该选项会导致更大的内存占用,将缓解偶发卡顿问题"
        }),
        options = {
            { description = translate({ en = "off", zh = "禁用"}), data = 0 },
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
        default = 1
    },
    {
        name = "EnbaleFrameGC",
        label = translate({ en = "Frame GC", zh = "帧间gc" }),
        hover = translate({
            en = "GC during idle time between frames",
            zh = "见缝插针地gc"
        }),
        options = {
            { description = translate({ en = "off", zh = "禁用"}), data = 0 },
            { description = "1ms", data = 1 },
            { description = "2ms", data = 2 },
            { description = "3ms", data = 3 },
            { description = "4ms", data = 4 },
            { description = "5ms", data = 5 },
        },
        default = 1
    },
    {
        name = "TargetLogincFPS",
        label = translate({ en = "Logic FPS", zh = "逻辑帧率" }),
        hover = translate({
            en = "Update FPS of lua scripts. Do not change unless you know what you are doing!!",
            zh = "lua脚本执行帧率,不要乱改,可能会爆炸!!"
        }),
        options = {
            { description = translate({ en = "off", zh = "禁用"}), data = 30 },
            { description = "45fps", data = 45 },
            { description = "60fps", data = 60 },
            { description = "75fps", data = 75 },
            { description = "90fps", data = 90 },
            { description = "105fps", data = 105 },
            { description = "120fps", data = 120 },
        },
        default = 30
    },
    {
        name = "TargetRenderFPS",
        label = translate({ en = "Render FPS", zh = "渲染帧率" }),
        hover = translate({
            en = "Render FPS",
            zh = "渲染帧率"
        }),
        options = {
            { description = translate({ en = "off", zh = "禁用"}), data = 60 },
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
        name = "ClientNetWorkTick",
        label = translate({ en = "Client network sync tick", zh = "客户端网络同步频率" }),
        hover = translate({
            en = "The frequency of communication between the client and the server.(deault:10fps)",
            zh = "客户端与服务器的通讯频率. 默认(10fps)."
        }),
        options = {
            { description = translate({ en = "off", zh = "禁用"}), data = 10 },
            { description = "15fps", data = 15 },
            { description = "20fps", data = 20 },
            { description = "25fps", data = 25 },
            { description = "30fps", data = 30 },
            { description = "32fps", data = 32 },
            { description = "35fps", data = 35 },
            { description = "40fps", data = 40 },
            { description = "45fps", data = 45 },
            { description = "50fps", data = 50 },
            { description = "55fps", data = 55 },
            { description = "60fps", data = 60 },
            { description = "64fps", data = 64 },
            { description = "75fps", data = 75 },
            { description = "90fps", data = 90 },
            { description = "115fps", data = 115 },
            { description = "120fps", data = 120 },
        },
        default = 10
    },
    {
        name = "JitOpt",
        label = translate({ en = "JIT Optimizations", zh = "JIT优化选项" }),
        hover = translate({
            en = "May become faster or slower.",
            zh = "可能更快, 可能更慢."
        }),
        options = toggle,
        default = false,
    },
    {
        name = "ModBlackList",
        label = translate({ en = "Mod JIT Blacklist", zh = "MODJit黑名单" }),
        hover = translate({ en = "Some mods may not be appropriate for JIT", zh = "有些mod可能写的特别,不合适jit模式" }),
        options = toggle,
        default = false
    },
    {
        name = "DisableJITWhenServer",
        label = translate({ en = "Disable JIT on Server", zh = "服务器禁用luajit" }),
        hover = translate({ en = "Disable luajit on the server process", zh = "服务器进程禁用luajit" }),
        options = toggle,
        default = false
    },
    {
        name = "EnableProfiler",
        label = translate({ en = "Enable Profiler Command", zh = "启用性能分析控制台命令" }),
        hover = translate({ en = "ProfilerJit.start | ProfilerJit.stop", zh = "ProfilerJit.start | ProfilerJit.stop" }),
        options = {
            { description = translate({en = "off", zh = "关闭"}),  data = "off" },
            { description = translate({en = "Detailed Sampling Mode", zh = "详细采样模式"}),  data = "fzvp" },
            { description = translate({en = "Origin Sampling Mode", zh = "原始采样模式"}), data = "Gz" },
        },
        default = 'off'
    },
    {
        name = "EnableTracy",
        label = translate({ en = "Enable Tracy", zh = "启用性能追踪" }),
        options = {
            { description = translate({en = "off", zh = "关闭"}),  data = "off" },
            { description = translate({en = "on", zh = "开启"}),  data = "on" },
        },
        default = 'off'
    }
}
--restart_required = true
