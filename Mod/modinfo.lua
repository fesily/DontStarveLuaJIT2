name = "DontStarveLuaJit2"

description = [[
    替换游戏底层虚拟机为LUAJIT,加速整个游戏
    Replacing the underlying VM with luajit speeds up the entire game.
    
    务必备份你的存档,不保证没错误
    Be sure to back up your archive, there is no guarantee that there are no bugs!
]]

author = "fesil"

version = "0.1.1"

forumthread = "https://github.com/fesily/DontStarveLuaJit2"

api_version = 10

dont_starve_compatible = true
reign_of_giants_compatible = true
dst_compatible = true

--TODO: need test compatible without the mod
client_only_mod = true

configuration_options = {}