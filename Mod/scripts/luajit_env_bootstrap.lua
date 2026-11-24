-- Mod/scripts/luajit_env_bootstrap.lua — the one hand-off from the engine to this mod.
--
-- Loaded through modrequire (scripts/env.lua) from modmain.lua and modworldgenmain.lua, so it
-- keeps its return value and runs in the mod env. It
--   1. asks the native GameInjector for this state's private registry root, the real registry
--      and the mod environment binding (GameInjector.InitializeModEnvironment),
--   2. installs scripts/luajit_env_runtime.lua (environment: surface, hook, env registry) with
--      that root,
--   3. clears the real GLOBAL.GameInjector / GLOBAL.GameLuaInjector: from here on the injector
--      tables exist only in this mod's own environment and in the root.
-- A missing native entry, root or registry is an initialization error; the loader never
-- continues with half an environment. The mod env reaches GLOBAL's raw fields through the
-- scripts/env.lua fallthrough (assert/getfenv/GameInjector resolve there); `_G` stays a chunk
-- local and is never written into the env.
local _G = GLOBAL
local modname = modname
local modenv = getfenv(1)
assert(type(modenv) == "table")
assert(type(GameInjector) == "table"
	and type(GameInjector.InitializeModEnvironment) == "function",
	"GameInjector.InitializeModEnvironment")


local private_root, real_registry = GameInjector.InitializeModEnvironment(modenv)
assert(type(private_root) == "table" and type(real_registry) == "table",
	"InitializeModEnvironment did not return (private root, registry)")

local runtime = modrequire("scripts/luajit_env_runtime")
assert(type(runtime) == "function", "scripts/luajit_env_runtime.lua returned no install function")
local context = runtime(_G, modname, modenv, private_root, real_registry)
assert(type(context) == "table" and type(context.surface) == "table",
	"the LuaJIT runtime install returned no context")
local manager = context.surface

-- The two injector tables are bound into this mod's env by the native entry; the real globals
-- must not offer them to any other mod.
_G.rawset(_G, "GameInjector", nil)
_G.rawset(_G, "GameLuaInjector", nil)

return {
	manager = manager,
	root = private_root,
	registry = real_registry,
}
