-- Mod/scripts/luajit_env_bootstrap.lua — the one hand-off from the engine to this mod.
--
-- Loaded with kleiloadlua + setfenv from modmain.lua and modworldgenmain.lua (never modimport:
-- that loses the return value). It
--   1. asks the native GameInjector for this state's private registry root, the real registry
--      and the mod environment binding (GameInjector.InitializeModEnvironment),
--   2. loads scripts/luajit_mod_blacklist.lua explicitly and installs it with that root,
--   3. clears the real GLOBAL.GameInjector / GLOBAL.GameLuaInjector: from here on the injector
--      tables exist only in this mod's own environment and in the root.
-- A missing native entry, root or registry is an initialization error; the loader never
-- continues with half an environment.
local global = GLOBAL
if type(global) ~= "table" then
	error("[luajit] Cannot initialize mod environment: GLOBAL", 0)
end

local modname = modname
local modenv = global.getfenv(1)

local function fail(message)
	global.error("[luajit] Cannot initialize mod environment: " .. message, 0)
end

local native = global.rawget(global, "GameInjector")
if type(native) ~= "table"
	or type(global.rawget(native, "InitializeModEnvironment")) ~= "function" then
	fail("GameInjector.InitializeModEnvironment")
end

local private_root, real_registry = native.InitializeModEnvironment(modenv)
if type(private_root) ~= "table" or type(real_registry) ~= "table" then
	fail("InitializeModEnvironment did not return (private root, registry)")
end

local modroot = modenv.MODROOT
if type(modroot) ~= "string" or modroot == "" then
	fail("MODROOT")
end
local filepath = modroot .. "scripts/luajit_mod_blacklist.lua"
local chunk, load_error = global.kleiloadlua(filepath)
if type(chunk) ~= "function" then
	fail("cannot load scripts/luajit_mod_blacklist.lua: " .. tostring(load_error or chunk))
end
global.setfenv(chunk, modenv)
local module = chunk()
if type(module) ~= "table" or type(module.install) ~= "function" then
	fail("scripts/luajit_mod_blacklist.lua returned no install function")
end

local manager = module.install(global, modname, modenv, private_root, real_registry)
if type(manager) ~= "table" then
	fail("mod blacklist install returned no manager")
end

-- The two injector tables are bound into this mod's env by the native entry; the real globals
-- must not offer them to any other mod.
global.rawset(global, "GameInjector", nil)
global.rawset(global, "GameLuaInjector", nil)

return {
	manager = manager,
	root = private_root,
	registry = real_registry,
}
