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

version = "0.2.3"

forumthread = "https://github.com/fesily/DontStarveLuaJit2"

api_version = 10

dont_starve_compatible = true
reign_of_giants_compatible = true
dst_compatible = true

--TODO: need test compatible without the mod
client_only_mod = true
server_only_mod = true

configuration_options = {
    {
        name = "EnabledJIT",
        labe1 = translate({ en = "EnabledJIT", zh = "开启JIT模式" }),
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
        labe1 = translate({ en = "JitOpt", zh = "JIT优化选项" }),
        hover = translate({
            en = "maybe faster, maybe slower.",
            zh = "可能更快, 可能更慢."
        }),
        options = {
            { description = "On",  data = true },
            { description = "Off", data = false },
        },
        default = true,
    },
    {
        name = "ModBlackList",
        labe1 = translate({ en = "ModJitBlackList", zh = "MODJit黑名单" }),
        hover = translate({ en = "some mod is't not appropriate", zh = "有些mod可能写的特别,不合适jit模式" }),
        options = {
            { description = "On",  data = true },
            { description = "Off", data = false },
        },
        default = true
    }
}
restart_required = true
