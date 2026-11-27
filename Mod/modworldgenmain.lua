-- 世界生成阶段的环境接管。
--
-- 世界生成状态由 scripts/worldgen_main.lua 驱动，它在 ModManager:LoadMods(true) 之前设置
-- WORLDGEN_MAIN = 1；客户端前端/自定义界面等其它加载路径没有这个全局，本文件直接返回。
-- worldgen 状态只加载 modworldgenmain.lua，modmain 里的接管不会在这里执行，所以必须在
-- 此走同一条路径：本模组 priority=2e53 最先加载，先于其它模组的 worldgen 代码。
--
-- 与 modmain 完全相同的一次性交接（见 scripts/luajit_env_bootstrap.lua）：原生入口把
-- GameInjector/GameLuaInjector 绑定到本 mod env 并给出私有 registry 根，管理器安装
-- string.dump 归属策略、捕获 LuaJIT 能力、清理共享 GLOBAL/package/registry。缺任何一个原生
-- 入口都是初始化错误，不带着半套环境继续。
local _G = GLOBAL
-- The mod env is a whitelist (type is available; assert is not).
if type(_G) ~= "table" then
	return
end
-- Only the worldgen load installs: the front end and the custom UI load this file too, and
-- there is no WORLDGEN_MAIN then.
if _G.rawget(_G, "WORLDGEN_MAIN") == nil then
	return
end
-- Native side gate, same rule as modmain: without the injector's entry point there is nothing to
-- hand off to, and the worldgen entry loads no further module (the front-end notice belongs to
-- modmain).
local GameInjector = _G.rawget(_G, "GameInjector")
if type(GameInjector) ~= "table" or type(GameInjector.InitializeModEnvironment) ~= "function" then
	print("[luajit] native GameInjector missing: worldgen hand-off skipped")
	return
end

modimport("scripts/env")
modrequire("scripts/luajit_env_bootstrap")
