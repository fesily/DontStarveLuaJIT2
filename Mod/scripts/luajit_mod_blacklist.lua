-- Shared LuaJIT mod string.dump policy: the ledger and its caller attribution.
--
-- A mod that calls string.dump is recorded in a JSON array of mod folder names in
-- the game save scope:
--   unsafedata/luajit_mod_blacklist.json   e.g. ["workshop-1991746508"]
-- The record is a compatibility log, not a kill switch: a recorded mod still
-- loads on the next start, and the name is never used to skip a chunk. It is
-- read/written with the engine's json (module("json") sets _G.json, and
-- main.lua/worldgen_main.lua load it before LoadMods) and with the game io, which
-- only treats mode "w" as a write ("a"/"w+" are reads) and only allows a single
-- unsafedata/* id (docs/mac-lua51-parity-audit.md 4.2, src/lua51/src/liolib.c).
-- That json4lua build escapes ' as \' (engine-specific, round-trips through its
-- own decode); this file is internal state, never exported or shared.
--
-- Entry point: install(global, modname, modenv, private_root, real_registry). The bootstrap
-- (scripts/luajit_env_bootstrap.lua) loads this chunk through modrequire and passes what the
-- native GameInjector.InitializeModEnvironment returned:
--   global          real GLOBAL (holds io/string/ModManager/debug/getfenv)
--   modname         folder name of the mod that installs this module
--   modenv          that mod's environment (registered for string.dump attribution)
--   private_root    this state's single private registry root
--   real_registry   the real registry table (root writes stay private to this mod)
-- The surface object (scripts/luajit_surface.lua) is published at private_root.controller:
-- it owns the hide/inject halves and the env registry this module attributes against. Neither
-- it nor this module is ever published on ModManager or in the shared registry.
--
-- The chunk env is not guaranteed to be GLOBAL (modrequire hands the mod env, a
-- whitelist without getfenv/pcall/rawget), so every privileged API is reached
-- through the global argument; the only chunk-env globals used are type (name
-- validation) and error as a last-resort fallback.
--
-- How the mod gets real bytecode: the injector installs a C-function hook on
-- `string.dump` (a closure implementation rewrite, game/DumpAttribution.cpp) and that hook asks
-- the Lua function stored in the private root (root.LJ_DS_PUC51_DUMP_POLICY) who is calling
-- before it calls the original. This module answers with the calling mod's folder name (or nil
-- for the engine); the VM path itself is pure C and returns genuine PUC Lua 5.1 bytecode for
-- every Lua function while the bridge exists -- the mod's own detection canary keeps working
-- and no mod is refused. The policy function is the only thing installed here:
-- GLOBAL.string.dump keeps its native C identity (the hook only rewrites the closure's
-- implementation word, which Lua cannot observe), so an alias saved before the install still
-- reaches the same decision point.
--
-- A torn write cannot be repaired here: the game io only offers "w" (truncate),
-- there is no atomic replace, so a crash mid-write leaves partial JSON. That is
-- reported as an initialization error (the file must be deleted), never silently
-- treated as an empty list.
--
-- Attribution is always by caller: mod B dumping mod A's function records B, and
-- the bytecode still comes from A's function (its own saved source). The registry policy
-- closure the VM consults is the only Lua entry; it walks its own caller stack and asks the
-- surface which env (or MODROOT prefix) owns each frame. Attribution is always on: no config
-- key, no luajit_compatible exemption, no HideGlobalJIT interaction.
-- Heuristic *encrypted* mod detection keeps its own JIT-off behaviour in
-- jit.runtime and never feeds this list.
-- The installing mod is not exempt either: its own scripts (including the bundled
-- jit/*.lua) must never call string.dump through the mod env, or it records itself.

local BLACKLIST_PATH = "unsafedata/luajit_mod_blacklist.json"
local POLICY_KEY = "LJ_DS_PUC51_DUMP_POLICY"
local DUMP_FAILED = "[luajit] Mod '%s': PUC 5.1 string.dump failed: %s"
local INVALID_ENTRY = "[luajit] Invalid mod blacklist entry ignored"

local surface_lib = modrequire("scripts/luajit_surface")
local is_valid_modname = surface_lib.is_valid_modname

-- Decodes the JSON array of names. A whitespace-only file is an empty list (no
-- record can be lost); anything that is not an array of strings is an error, so a
-- damaged file is reported instead of silently read as "nothing recorded".
local function parse_entries(api, text)
	local names = {}
	if text:match("^%s*$") then
		return names
	end
	local ok, decoded = api.pcall(api.decode, text)
	if not ok then
		return nil, "cannot decode " .. BLACKLIST_PATH .. ": " .. api.tostring(decoded)
	end
	if api.type(decoded) ~= "table" then
		return nil, "cannot decode " .. BLACKLIST_PATH .. ": expected a JSON array of mod folder names"
	end
	local count = #decoded
	for key in api.pairs(decoded) do
		if api.type(key) ~= "number" or key % 1 ~= 0 or key < 1 or key > count then
			return nil, "cannot decode " .. BLACKLIST_PATH .. ": expected a JSON array of mod folder names"
		end
	end
	for index = 1, count do
		local name = decoded[index]
		if is_valid_modname(name) then
			names[name] = true
		else
			api.print(INVALID_ENTRY)
		end
	end
	return names
end

-- Reads the whole list. A missing file (io.open -> nil) is an empty list, the
-- same semantics the other unsafedata readers use; a failing read/close is an
-- error with the path, never a silent empty list.
local function read_entries(api)
	local ok_open, fp, open_err = api.pcall(api.open, BLACKLIST_PATH, "r")
	if not ok_open then
		return nil, "io.open raised for " .. BLACKLIST_PATH .. ": " .. api.tostring(fp)
	end
	if not fp then
		return {}, nil
	end
	local first_err
	local ok_read, text, read_err = api.pcall(fp.read, fp, "*a")
	if not ok_read then
		first_err = "read raised: " .. api.tostring(text)
	elseif api.type(text) ~= "string" then
		first_err = "read failed: " .. api.tostring(read_err)
	end
	local ok_close, close_res, close_err = api.pcall(fp.close, fp)
	if not ok_close then
		first_err = first_err or ("close raised: " .. api.tostring(close_res))
	elseif close_res == nil or close_res == false then
		first_err = first_err or ("close failed: " .. api.tostring(close_err))
	end
	if first_err then
		return nil, "cannot read " .. BLACKLIST_PATH .. ": " .. first_err
	end
	return parse_entries(api, text)
end

-- Rewrites the whole list (sorted, LF, one name per line). Every step is checked:
-- open, write and close nil/false results and raised errors all report failure.
local function write_entries(api, names)
	local list = {}
	for name in api.pairs(names) do
		list[#list + 1] = name
	end
	api.sort(list)
	local ok_encode, content = api.pcall(api.encode, list)
	if not ok_encode or api.type(content) ~= "string" then
		return false, "cannot encode " .. BLACKLIST_PATH .. ": " .. api.tostring(content)
	end
	content = content .. "\n"
	local ok_open, fp, open_err = api.pcall(api.open, BLACKLIST_PATH, "w")
	if not ok_open then
		return false, "io.open raised for " .. BLACKLIST_PATH .. ": " .. api.tostring(fp)
	end
	if not fp then
		return false, "cannot open " .. BLACKLIST_PATH .. " for writing: " .. api.tostring(open_err)
	end
	local first_err
	local ok_write, write_res, write_err = api.pcall(fp.write, fp, content)
	if not ok_write then
		first_err = "write raised: " .. api.tostring(write_res)
	elseif write_res == nil or write_res == false then
		first_err = "write failed: " .. api.tostring(write_err)
	end
	local ok_close, close_res, close_err = api.pcall(fp.close, fp)
	if not ok_close then
		first_err = first_err or ("close raised: " .. api.tostring(close_res))
	elseif close_res == nil or close_res == false then
		first_err = first_err or ("close failed: " .. api.tostring(close_err))
	end
	if first_err then
		return false, "cannot write " .. BLACKLIST_PATH .. ": " .. first_err
	end
	return true, nil
end
local Manager = {}
Manager.__index = Manager

-- Adds a mod name to the in-memory list and, on the first hit, merges the file
-- and rewrites it. The record is a compatibility log: a failure here does not
-- block the dump, it is reported (see dump_policy). Nothing expires.
function Manager:record(modname)
	if not is_valid_modname(modname) then
		return false, "invalid mod name " .. self.api.tostring(modname)
	end
	self.recorded[modname] = true
	if self.persisted[modname] then
		return true, nil
	end
	local disk, read_err = read_entries(self.api)
	if read_err then
		return false, read_err
	end
	for name in self.api.pairs(disk) do
		self.recorded[name] = true
	end
	local ok, write_err = write_entries(self.api, self.recorded)
	if not ok then
		return false, write_err
	end
	self.persisted[modname] = true
	return true, nil
end
function Manager:current_loading_modname()
	local ok, name = self.api.pcall(function()
		return self.modmanager.currentlyloadingmod
	end)
	if ok and is_valid_modname(name) then
		return name
	end
	return nil
end

-- Walks outward from the innermost frame until a frame can name a mod. C frames,
-- tail-call pseudo frames and frames of this module or the surface module are skipped. The
-- ownership table and the MODROOT prefixes come from the surface. Priority:
-- visible mod frame -> currentlyloadingmod.
function Manager:caller_modname()
	local level = 1
	local surface = self.surface
	while true do
		local ok, info = self.api.pcall(self.api.getinfo, level, "fS")
		if not ok or self.api.type(info) ~= "table" then
			break
		end
		local func = info.func
		local source = info.source
		local skip = true
		if func and info.what ~= "C" then
			if surface:is_own(func) then
				skip = true
			elseif self.api.type(source) == "string" and source:sub(1, 1) == "=" then
				skip = true
			else
				skip = false
			end
		end
		if not skip then
			local ok_env, fenv = self.api.pcall(self.api.getfenv, func)
			if ok_env and self.api.type(fenv) == "table" and fenv ~= self.global then
				local owner = surface:owner_of(fenv)
				if is_valid_modname(owner) then
					return owner
				end
				local raw = self.api.rawget(fenv, "modname")
				if is_valid_modname(raw) then
					return raw
				end
			end
			local modname = surface:locate(source)
			if modname then
				return modname
			end
		end
		level = level + 1
	end
	return self:current_loading_modname()
end

-- The string.dump hook calls this only to attribute the call to the blacklist record; the
-- answer is not a bytecode decision (the VM dumps PUC 5.1 for every Lua function while the
-- host bridge exists). The hit is recorded (and persisted) before the hook calls the original,
-- so the JSON always contains the mod whose dump is about to be converted; a failing write is
-- reported instead of silently losing it.
function Manager:dump_policy()
	local modname = self:caller_modname()
	if not is_valid_modname(modname) then
		return nil
	end
	local ok, err = self:record(modname)
	if not ok then
		self.api.error(self.api.format(DUMP_FAILED, modname,
			"blacklist persistence failed: " .. self.api.tostring(err)), 0)
	end
	return modname
end
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

-- The one entry point. `private_root` and `real_registry` are what the native
-- GameInjector.InitializeModEnvironment returned; the surface object owns every piece of
-- state and is the published controller. A second install in the same state (modmain and
-- worldgen_main) only registers its env again.
local function install(global, modname, modenv, private_root, real_registry)
	local error = global.error or error
	local assert = global.assert or assert

	assert(type(private_root) == "table", "[luajit] Cannot initialize mod blacklist: private registry root is required")
	assert(type(real_registry) == "table", "[luajit] Cannot initialize mod blacklist: real registry is required")

	local modmanager = global.ModManager
	local existing = private_root.controller
	if existing ~= nil then
		assert(type(existing) == "table" and getmetatable(existing) == surface_lib.Surface,
			"[luajit] Cannot initialize mod blacklist: private registry root is already owned")
		existing:register_env(modname, modenv)
		return existing
	end
	assert(private_root[POLICY_KEY] == nil, "[luajit] Cannot initialize mod blacklist: registry key already in use")
	local missing = missing_apis(global)
	if #missing > 0 then
		local names = missing[1]
		for index = 2, #missing do
			names = names .. ", " .. missing[index]
		end
		error("[luajit] Cannot initialize mod blacklist: " .. names)
	end
	assert(is_valid_modname(modname), "[luajit] Cannot initialize mod blacklist: invalid modname")

	local api = {
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
	local recorded, read_err = read_entries(api)
	if read_err then
		error("[luajit] Cannot initialize mod blacklist: " .. read_err)
	end

	local manager = api.setmetatable({
		api = api,
		global = global,
		modmanager = modmanager,
		installing_modname = modname,
		recorded = recorded,
		persisted = {},
	}, Manager)

	local surface = surface_lib.new(api, {
		global = global,
		modname = modname,
		modenv = modenv,
		private_root = private_root,
		real_registry = real_registry,
	})
	manager.surface = surface
	-- Frames of this module are never attribution candidates either.
	for _, value in api.pairs(Manager) do
		surface:mark_own(value)
	end

	-- Publish the owner first: a second install in this state reuses it instead of building a
	-- second surface, and a failure below leaves a controller no one can mistake for absent.
	private_root.controller = surface

	surface:capture()

	-- The VM consults this closure through the private root. Another live surface must not be
	-- silently displaced (checked above, before any state was replaced).
	if surface.has_luajit then
		local policy = function()
			return manager:dump_policy()
		end
		surface:mark_own(policy)
		private_root[POLICY_KEY] = policy
		if private_root[POLICY_KEY] ~= policy then
			error("[luajit] Cannot initialize mod blacklist: cannot publish " .. POLICY_KEY)
		end
	end

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
	return surface
end

return install

