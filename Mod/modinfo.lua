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

version = "0.7.0"

forumthread = "https://github.com/fesily/DontStarveLuaJit2"

api_version = 10

dont_starve_compatible = true
reign_of_giants_compatible = true
dst_compatible = true

--TODO: need test compatible without the mod
--all_clients_require_mod = true
client_only_mod = true

priority = 2e53

-- Preview image
icon_atlas = "images/modicon.xml"
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
        default = true
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
    }
}
--restart_required = true
