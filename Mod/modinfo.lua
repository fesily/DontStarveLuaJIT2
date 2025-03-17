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
        Replacing the underlying VM with luajit speeds up the entire game.
        Be sure to back up your archive, there is no guarantee that there are no bugs!
    ]]
    }
)

author = "fesil"

version = "1.2.0"

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

configuration_options = {
    {
        name = "EnabledJIT",
        label = translate({ en = "EnabledJIT", zh = "开启JIT模式" }),
        hover = translate({
            en = "It is recommended to turn off if the lag is severe in the game",
            zh = "在游戏中卡顿现象很严重的建议关闭"
        }),
        options = {
            { description = "On",  data = true },
            { description = "Off", data = false },
        },
        default = true
    },
    {
        name = "DisableForceFullGC",
        label = translate({ en = "Disable Force FullGC, only gc small", zh = "禁用强制完全gc,仅gc小部分"}),
        hover = translate({
            en = "Enabling this feature will result in a larger memory footprint, which will alleviate occasional lagging issues",
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
        label = translate({ en = "frame gc", zh = "帧间gc" }),
        hover = translate({
            en = "use free time gc",
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
        label = translate({ en = "logic fps", zh = "逻辑帧率" }),
        hover = translate({
            en = "lua scripts update fps, changed this, maybe boom!!",
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
        label = translate({ en = "render fps", zh = "渲染帧率" }),
        hover = translate({
            en = "Render fps",
            zh = "渲染帧率"
        }),
        options = {
            { description = translate({ en = "off", zh = "禁用"}), data = false },
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
        name = "JitOpt",
        label = translate({ en = "JitOpt", zh = "JIT优化选项" }),
        hover = translate({
            en = "maybe faster, maybe slower.",
            zh = "可能更快, 可能更慢."
        }),
        options = {
            { description = "On",  data = true },
            { description = "Off", data = false },
        },
        default = false,
    },
    {
        name = "ModBlackList",
        label = translate({ en = "ModJitBlackList", zh = "MODJit黑名单" }),
        hover = translate({ en = "some mod is't not appropriate", zh = "有些mod可能写的特别,不合适jit模式" }),
        options = {
            { description = "On",  data = true },
            { description = "Off", data = false },
        },
        default = false
    },
    {
        name = "DisableJITWhenServer",
        label = translate({ en = "DisableJITWhenServer", zh = "服务器禁用luajit" }),
        hover = translate({ en = "server process disable luajit mod", zh = "服务器进程禁用luajit" }),
        options = {
            { description = "On",  data = true },
            { description = "Off", data = false },
        },
        default = false
    },
    {
        name = "EnableProfiler",
        label = translate({ en = "EnableProfilerCosoleCommand", zh = "启用性能分析控制台命令" }),
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
        label = translate({ en = "EnableTracy", zh = "启用性能追踪" }),
        options = {
            { description = translate({en = "off", zh = "关闭"}),  data = "off" },
            { description = translate({en = "on", zh = "开启"}),  data = "on" },
        },
        default = 'off'
    }
}
--restart_required = true
