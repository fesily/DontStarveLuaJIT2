-- The LuaJIT runtime: the environment half of one VM state.
--
-- scripts/luajit_env_bootstrap.lua calls this (through modrequire) with what the native
-- GameInjector.InitializeModEnvironment returned:
--   global          real GLOBAL (holds io/string/ModManager/debug/getfenv)
--   modname         folder name of the mod that installs the runtime
--   modenv          that mod's environment (registered for string.dump attribution)
--   private_root    this state's single private registry root
--   real_registry   the real registry table (root writes stay private to this mod)
-- It validates the assembly preconditions, builds the privileged-API table, creates the
-- surface (scripts/luajit_surface.lua), publishes it at private_root.controller, captures the
-- extension surface, prepares the shared package views, installs the one
-- ModManager:InitializeModMain hook and registers the installing env.
--
-- Returns the state context: {api, surface, root, registry, global, modmanager}. A second
-- install in the same state returns the same surface.
--
-- The chunk env is the mod env (modrequire), a whitelist without getfenv/pcall/rawget: the
-- checks here use the mod env's `type`/`assert`/`error` exactly like
-- scripts/luajit_env_bootstrap.lua, and every privileged API goes through the api table.

local surface_lib = modrequire("scripts/luajit_surface")

local function missing_apis(global)
	local missing = {}
	local function need(cond, name)
		if not cond then
			missing[#missing + 1] = name
		end
	end
	local io_table = global.io
	need(io_table ~= nil and type(io_table.open) == "function", "io.open")
	local string_table = global.string
	need(string_table ~= nil and type(string_table.dump) == "function", "string.dump")
	need(string_table ~= nil and type(string_table.format) == "function", "string.format")
	local table_table = global.table
	need(table_table ~= nil and type(table_table.sort) == "function", "table.sort")
	need(table_table ~= nil and type(table_table.concat) == "function", "table.concat")
	local modmanager = global.ModManager
	need(modmanager ~= nil and type(modmanager.InitializeModMain) == "function", "ModManager.InitializeModMain")
	local debug_table = global.debug
	need(debug_table ~= nil and type(debug_table.getinfo) == "function", "debug.getinfo")
	need(type(global.getfenv) == "function", "getfenv")
	need(type(global.setfenv) == "function", "setfenv")
	need(type(global.getmetatable) == "function", "getmetatable")
	need(type(global.kleiloadlua) == "function", "kleiloadlua")
	need(type(global.error) == "function", "error")
	need(type(global.print) == "function", "print")
	need(type(global.pcall) == "function", "pcall")
	need(type(global.setmetatable) == "function", "setmetatable")
	need(type(global.rawget) == "function", "rawget")
	need(type(global.rawset) == "function", "rawset")
	need(type(global.pairs) == "function", "pairs")
	need(type(global.tostring) == "function", "tostring")
	local json = global.json
	need(json ~= nil and type(json.encode) == "function", "json.encode")
	need(json ~= nil and type(json.decode) == "function", "json.decode")
	return missing
end

-- The privileged-API table every module of this runtime receives. Built from the real GLOBAL
-- once per install; the ledger manager and the surface only see these functions, never the
-- chunk env.
local function build_api(global)
	return {
		type = type,
		tostring = global.tostring,
		pairs = global.pairs,
		pcall = global.pcall,
		error = global.error,
		print = global.print,
		format = global.string.format,
		sort = global.table.sort,
		concat = global.table.concat,
		encode = global.json.encode,
		decode = global.json.decode,
		getinfo = global.debug.getinfo,
		getfenv = global.getfenv,
		setfenv = global.setfenv,
		getmetatable = global.getmetatable,
		setmetatable = global.setmetatable,
		rawget = global.rawget,
		rawset = global.rawset,
		open = global.io.open,
	}
end

local function make_context(api, surface, private_root, real_registry, global, modmanager)
	return {
		api = api,
		surface = surface,
		root = private_root,
		registry = real_registry,
		global = global,
		modmanager = modmanager,
	}
end

-- The one entry point. A second install in the same state (modmain and worldgen_main) only
-- registers its env again and returns the same surface.
local function install(global, modname, modenv, private_root, real_registry)
	local error = global.error or error
	local assert = global.assert or assert

	assert(type(private_root) == "table",
		"[luajit] Cannot initialize the LuaJIT runtime: private registry root is required")
	assert(type(real_registry) == "table",
		"[luajit] Cannot initialize the LuaJIT runtime: real registry is required")

	local modmanager = global.ModManager
	local existing = private_root.controller
	if existing ~= nil then
		assert(type(existing) == "table" and getmetatable(existing) == surface_lib.Surface,
			"[luajit] Cannot initialize the LuaJIT runtime: private registry root is already owned")
		existing:register_env(modname, modenv)
		return make_context(build_api(global), existing, private_root, real_registry, global,
			modmanager)
	end
	local missing = missing_apis(global)
	if #missing > 0 then
		local names = missing[1]
		for index = 2, #missing do
			names = names .. ", " .. missing[index]
		end
		error("[luajit] Cannot initialize the LuaJIT runtime: " .. names)
	end
	assert(surface_lib.is_valid_modname(modname),
		"[luajit] Cannot initialize the LuaJIT runtime: invalid modname")

	local api = build_api(global)
	local surface = surface_lib.new(api, {
		global = global,
		modname = modname,
		modenv = modenv,
		private_root = private_root,
		real_registry = real_registry,
	})
	-- Publish the surface first: a second install in this state reuses it instead of building a
	-- second one, and a failure below leaves a controller no one can mistake for absent.
	private_root.controller = surface

	surface:capture()
	surface:prepare_shared()

	-- One InitializeModMain hook: every mod env is registered and, before the engine runs it,
	-- either granted the surface or scrubbed.
	local old_initialize = modmanager.InitializeModMain
	local function initialize_hook(self, register_modname, register_env, ...)
		surface:register_env(register_modname, register_env)
		return old_initialize(self, register_modname, register_env, ...)
	end
	surface:mark_own(initialize_hook)
	modmanager.InitializeModMain = initialize_hook

	surface:register_env(modname, modenv)
	return make_context(api, surface, private_root, real_registry, global, modmanager)
end

return install
