-- 世界生成阶段的 jit 隐藏。
--
-- 风雪/daxsg 系加密模组（如《神话书说》workshop-1991746508）的加载器会探测
-- require("jit") / package.loaded.jit；一旦取到，就在 LuaJIT 下走进坏路径——
-- 其字节码 VM 报 "attempt to index local 'K'" 或死循环（lj_BC_TGETV），把
-- worldgen 状态带坏，地表世界生成卡死/崩在海洋 pass。
--
-- 只作用于真正的世界生成状态：worldgen 状态由 scripts/worldgen_main.lua 驱动，
-- 它在 ModManager:LoadMods(true) 之前设置 WORLDGEN_MAIN = 1（引擎自己判定
-- "是否世界生成"用的就是它，见 tilegroups.lua）。客户端前端/自定义界面等其它
-- 加载路径没有这个全局，本文件直接返回，不影响普通 mod 加载。
-- worldgen 状态只加载 modworldgenmain.lua（scripts/mods.lua:579），modmain 里的
-- HideGlobalJIT（jit.runtime）不会在这里执行，所以在此补一次；本模组
-- priority=2e53 最先加载，先于其它模组的 worldgen 代码。
--
-- 注意：
--  * mod env 只有白名单全局（无 pcall/debug/package），一律走 GLOBAL；
--  * rawset 避免 strict.lua 的 "assign to undeclared variable 'jit'"；
--  * 选项 HideGlobalJIT（默认开）关闭时不做隐藏。
local global = GLOBAL
if not global or global.rawget(global, "WORLDGEN_MAIN") == nil then
    return
end

local hide = true
if type(global.GetModConfigData) == "function" then
    local ok, value = global.pcall(global.GetModConfigData, "HideGlobalJIT")
    if ok and value ~= nil then
        hide = value
    end
end
if not hide then
    return
end

global.rawset(global, "jit", nil)
if global.package and global.package.loaded then
    global.package.loaded["jit"] = nil
end
