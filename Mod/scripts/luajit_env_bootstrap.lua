-- Mod/scripts/luajit_env_bootstrap.lua — the one hand-off from the engine to this mod.
--
-- Loaded through modrequire (scripts/env.lua) from modmain.lua and modworldgenmain.lua, so it
-- keeps its return value and runs in the mod env. It
--   1. asks the native GameInjector for this state's private registry root, the real registry
--      and the mod environment binding (GameInjector.InitializeModEnvironment),
--   2. installs scripts/luajit_mod_blacklist.lua with that root; the blacklist module owns the
--      ledger and pulls in scripts/luajit_surface.lua for the hide/inject halves,
--   3. clears the real GLOBAL.GameInjector / GLOBAL.GameLuaInjector: from here on the injector
--      tables exist only in this mod's own environment and in the root.
-- A missing native entry, root or registry is an initialization error; the loader never
-- continues with half an environment. The mod env is a whitelist (no assert/pcall/rawget):
-- everything privileged is reached through GLOBAL.
local _G = GLOBAL
if type(_G) ~= "table" then
	return
end

local function fail(message)
	_G.error("[luajit] Cannot initialize mod environment: " .. message, 0)
end

local modname = modname
local modenv = _G.getfenv(1)
if type(modenv) ~= "table" then
	fail("mod environment")
end

local native = _G.rawget(_G, "GameInjector")
if type(native) ~= "table"
	or type(_G.rawget(native, "InitializeModEnvironment")) ~= "function" then
	fail("GameInjector.InitializeModEnvironment")
end

local private_root, real_registry = native.InitializeModEnvironment(modenv)
if type(private_root) ~= "table" or type(real_registry) ~= "table" then
	fail("InitializeModEnvironment did not return (private root, registry)")
end

local installer = modrequire("scripts/luajit_mod_blacklist")
if type(installer) ~= "function" then
	fail("scripts/luajit_mod_blacklist.lua returned no install function")
end

local manager = installer(_G, modname, modenv, private_root, real_registry)
if type(manager) ~= "table" then
	fail("mod blacklist install returned no manager")
end

-- The two injector tables are bound into this mod's env by the native entry; the real globals
-- must not offer them to any other mod.
_G.rawset(_G, "GameInjector", nil)
_G.rawset(_G, "GameLuaInjector", nil)

return {
	manager = manager,
	root = private_root,
	registry = real_registry,
}
