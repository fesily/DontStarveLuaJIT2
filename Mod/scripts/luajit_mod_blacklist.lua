-- Shared LuaJIT mod blacklist.
--
-- A mod that calls string.dump is reported as incompatible with LuaJIT and is
-- refused the next time it loads, before any of its chunks run. The record is a
-- JSON array of mod folder names in the game save scope:
--   unsafedata/luajit_mod_blacklist.json   e.g. ["workshop-1991746508"]
-- It is read/written with the engine's json (module("json") sets _G.json, and
-- main.lua/worldgen_main.lua load it before LoadMods) and with the game io, which
-- only treats mode "w" as a write ("a"/"w+" are reads) and only allows a single
-- unsafedata/* id (docs/mac-lua51-parity-audit.md 4.2, src/lua51/src/liolib.c).
-- That json4lua build escapes ' as \' (engine-specific, round-trips through its
-- own decode); this file is internal state, never exported or shared.
--
-- Loaded with modimport("scripts/luajit_mod_blacklist") from modmain and
-- modworldgenmain: the chunk runs in the mod env, which carries GLOBAL + modname,
-- so it installs itself. Explicit entry point: install(global, modname, modenv).
--   global  real GLOBAL (holds io/string/ModManager/kleiloadlua/debug/getfenv)
--   modname folder name of the mod that installs this module
--   modenv  that mod's environment (registered for string.dump attribution)
--
-- The chunk env is not guaranteed to be GLOBAL (modimport hands the mod env, a
-- whitelist without getfenv/pcall/rawget), so every privileged API is reached
-- through the global argument; the only chunk-env globals used are type (name
-- validation), string/table methods, and error as a last-resort fallback.
--
-- A torn write cannot be repaired here: the game io only offers "w" (truncate),
-- there is no atomic replace, so a crash mid-write leaves partial JSON. That is
-- reported as an initialization error (the file must be deleted), never silently
-- treated as an empty list -- an empty list would let a recorded mod dump again.
--
-- The manager installs, once per process:
--   * a copied per-mod env string table whose dump front end blames that mod,
--   * a global string.dump wrapper (GLOBAL.string.dump / engine Lua wrappers),
--   * a kleiloadlua wrapper that refuses a recorded mod's entry files (a chunk that
--     reports and raises) and blanks every other script of it (an empty chunk: the
--     code never runs, but a late engine require cannot abort on our error),
--   * a ModManager:InitializeModMain hook that registers every mod env.
-- It is enforced whenever LuaJIT is the VM: no config key, no luajit_compatible
-- exemption, no HideGlobalJIT interaction. Heuristic *encrypted* mod detection
-- keeps its own JIT-off behaviour in jit.runtime and never feeds this list.
-- The installing mod is not exempt either: its own scripts (including the bundled
-- jit/*.lua) must never call string.dump through the mod env, or it records itself
-- and its own entry files are refused on the next start.

local BLACKLIST_PATH = "unsafedata/luajit_mod_blacklist.json"
local ERROR_TEXT = "[luajit] Mod '%s' is incompatible with LuaJIT (此模组不兼容): string.dump is not supported for mods."
local PERSIST_FAILED = "; blacklist persistence failed: "
local INVALID_ENTRY = "[luajit] Invalid mod blacklist entry ignored"
-- Compiles to a factory: chunkname is the target file, the message is passed as
-- an argument (never spliced into source), and the result only uses upvalues, so
-- the engine's later setfenv/RunInEnvironment cannot change its behaviour.
local FACTORY_SOURCE = "local report, fail, message = ...\n"
	.. "return function() report(message) fail(message) end\n"

local function is_valid_modname(name)
	if type(name) ~= "string" or name == "" then
		return false
	end
	if name == "." or name == ".." then
		return false
	end
	if name:find("/", 1, true) or name:find("\\", 1, true) then
		return false
	end
	if name:find("\0", 1, true) or name:find("\r", 1, true) or name:find("\n", 1, true) then
		return false
	end
	return true
end

-- Decodes the JSON array of names. A whitespace-only file is an empty list (no
-- record can be lost); anything that is not an array of strings is an error, so a
-- damaged file never silently drops a recorded mod.
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
-- and rewrites it. Persistence failure never blocks the refusal; the caller
-- reports it in the error text. Nothing here expires a record.
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

-- Fixed template + original modname: never a display name, translation or modinfo.
function Manager:message(modname, persist_ok, persist_err)
	local message = self.api.format(ERROR_TEXT, modname)
	if not persist_ok and persist_err then
		message = message .. PERSIST_FAILED .. persist_err
	end
	return message
end

-- Persist first, then report, then raise: the original dump never runs and the
-- caller's protection layer (xpcall/RunInEnvironment) attributes the error here.
function Manager:reject(modname)
	local persist_ok, persist_err = self:record(modname)
	local message = self:message(modname, persist_ok, persist_err)
	self.api.print(message)
	self.api.error(message, 0)
end

-- Maps a game path (or a debug source) to a mod folder name. Only the exact
-- "../mods/<name>/..." layout and registered MODROOT prefixes count, so a path
-- that merely mentions "mods" is not guessed at. Returns name, remainder.
function Manager:locate(path)
	if self.api.type(path) ~= "string" then
		return nil, nil
	end
	local norm = path:gsub("\\", "/")
	if norm:sub(1, 1) == "@" then
		norm = norm:sub(2)
	end
	local root_prefix = "../mods/"
	if norm:sub(1, #root_prefix) == root_prefix then
		local rest = norm:sub(#root_prefix + 1)
		local slash = rest:find("/", 1, true)
		if slash then
			local name = rest:sub(1, slash - 1)
			if is_valid_modname(name) then
				return name, rest:sub(slash + 1)
			end
		end
		return nil, nil
	end
	local best_name, best_len
	for root, name in self.api.pairs(self.roots) do
		if #norm >= #root and norm:sub(1, #root) == root then
			if not best_len or #root > best_len then
				best_name, best_len = name, #root
			end
		end
	end
	if best_name then
		return best_name, norm:sub(best_len + 1)
	end
	return nil, nil
end

-- Walks outward from the innermost frame until a frame can name a mod:
-- registered env, env raw modname, then its source path. C frames, tail-call
-- pseudo frames and this manager's own frames are skipped.
function Manager:caller_modname()
	local level = 1
	while true do
		local ok, info = self.api.pcall(self.api.getinfo, level, "fS")
		if not ok or self.api.type(info) ~= "table" then
			return nil
		end
		local func = info.func
		local source = info.source
		if not func or info.what == "C" or self.own_functions[func]
			or (self.api.type(source) == "string" and source:sub(1, 1) == "=") then
			level = level + 1
		else
			local ok_env, fenv = self.api.pcall(self.api.getfenv, func)
			if ok_env and self.api.type(fenv) == "table" and fenv ~= self.global then
				local owner = self.env_owner[fenv]
				if is_valid_modname(owner) then
					return owner
				end
				local raw = self.api.rawget(fenv, "modname")
				if is_valid_modname(raw) then
					return raw
				end
			end
			local modname = self:locate(source)
			if modname then
				return modname
			end
			level = level + 1
		end
	end
end

-- Attribution is always by caller, never by the dumped function: mod B dumping
-- mod A's function records B, and the engine dumping it records nobody.
function Manager:dump_from_owner(owner, ...)
	local modname = self:caller_modname()
	if not is_valid_modname(modname) then
		modname = owner
	end
	if not is_valid_modname(modname) then
		return self.original_dump(...)
	end
	self:reject(modname)
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

function Manager:global_dump(...)
	local modname = self:caller_modname()
	if not is_valid_modname(modname) then
		modname = self:current_loading_modname()
	end
	if not is_valid_modname(modname) then
		return self.original_dump(...)
	end
	self:reject(modname)
end

-- Builds the load-time refusal chunk. Never errors from inside kleiloadlua: the
-- engine runs the returned function in the target mod, so the failure lands on
-- that mod instead of on whoever requested the file.
function Manager:refusal_chunk(modname, filename)
	local message = self:message(modname, true, nil)
	local ok, factory = self.api.pcall(self.api.loadstring, FACTORY_SOURCE, "@" .. self.api.tostring(filename))
	if ok and self.api.type(factory) == "function" then
		return factory(self.api.print, self.api.error, message)
	end
	-- No compiler available: still hand back a chunk that only uses upvalues, so the
	-- engine's loader is not aborted from inside this call.
	return function()
		self.api.print(message)
		self.api.error(message, 0)
	end
end

-- Returns the refusal chunk for a recorded mod (modinfo stays readable so the
-- game can still list/manage it) and delegates everything else untouched.
-- `inner` is the exact loader this wrapper replaced: it is captured per wrapper,
-- never read from the manager, because jit.runtime may have wrapped an older
-- wrapper of ours in between (re-pointing a shared field would cycle).
function Manager:dispatch_load(inner, filename, ...)
	local modname, rest = self:locate(filename)
	if modname and self.recorded[modname] then
		if rest == "modinfo.lua" then
			return inner(filename, ...)
		end
		if rest == "modmain.lua" or rest == "modworldgenmain.lua" then
			local chunk = self:refusal_chunk(modname, filename)
			if chunk ~= nil then
				return chunk
			end
		end
		-- The engine keeps loading base modules after the mod error
		-- (`require "stacktrace"`, "debughelpers", "consolecommands", ...), and
		-- package.path may resolve them to the blacklisted mod's copies. Never run
		-- the mod's code, but do not raise from here either: a failing require
		-- aborts main.lua ("Error loading main.lua") and crashes shutdown. An empty
		-- chunk keeps the engine's error path alive; the entry refusal above is what
		-- reports the incompatibility and disables the mod.
		return function() end
	end
	return inner(filename, ...)
end

-- Wrapping is identity checked: when jit.runtime replaces kleiloadlua with its
-- frostxx/encrypted hook, the next call makes this check outermost again.
function Manager:wrap_loader()
	local current = self.api.rawget(self.global, "kleiloadlua")
	if current == self.loader_wrapper then
		return self
	end
	if self.api.type(current) ~= "function" then
		self.api.print("[luajit] Cannot wrap kleiloadlua for the mod blacklist: not a function")
		return self
	end
	local wrapper = function(filename, ...)
		return self:dispatch_load(current, filename, ...)
	end
	self.loader_wrapper = wrapper
	self.api.rawset(self.global, "kleiloadlua", wrapper)
	return self
end

-- Registers a mod env: attribution for its frames, its MODROOT prefix, and a
-- copy of its string table with only dump replaced (idempotent per env).
function Manager:register_env(modname, env)
	if not is_valid_modname(modname) or self.api.type(env) ~= "table" then
		return false
	end
	self.env_owner[env] = modname
	local ok_root, root = self.api.pcall(function()
		return env.MODROOT
	end)
	if ok_root and self.api.type(root) == "string" and root ~= "" then
		local norm = root:gsub("\\", "/")
		if norm:sub(-1) ~= "/" then
			norm = norm .. "/"
		end
		self.roots[norm] = modname
	end
	local env_string = self.api.rawget(env, "string")
	if self.api.type(env_string) ~= "table" then
		-- Proxy envs (e.g. modmain's own env) only expose string through __index.
		local ok, indexed = self.api.pcall(function()
			return env.string
		end)
		if ok then
			env_string = indexed
		end
	end
	if self.api.type(env_string) == "table" and self.string_copies[env_string] ~= modname then
		local copy = {}
		for key, value in self.api.pairs(env_string) do
			copy[key] = value
		end
		local dump_wrapper = function(...)
			return self:dump_from_owner(modname, ...)
		end
		self.own_functions[dump_wrapper] = true
		copy.dump = dump_wrapper
		self.string_copies[copy] = modname
		self.api.rawset(env, "string", copy)
	end
	return true
end

local M = {}

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
	need(type(global.kleiloadlua) == "function", "kleiloadlua")
	local debug_table = global.debug
	need(debug_table ~= nil and type(debug_table.getinfo) == "function", "debug.getinfo")
	need(type(global.getfenv) == "function", "getfenv")
	need(type(global.loadstring) == "function", "loadstring")
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

function M.install(global, modname, modenv)
	local missing = missing_apis(global)
	local error_fn = global.error
	if type(error_fn) ~= "function" then
		error_fn = error
	end
	if #missing > 0 then
		local names = missing[1]
		for index = 2, #missing do
			names = names .. ", " .. missing[index]
		end
		error_fn("[luajit] Cannot initialize mod blacklist: " .. names, 0)
	end
	if not is_valid_modname(modname) then
		error_fn("[luajit] Cannot initialize mod blacklist: invalid modname", 0)
	end

	local modmanager = global.ModManager
	local existing = global.rawget(modmanager, "_ds_luajit_mod_blacklist_installed")
	if type(existing) == "table" then
		existing:register_env(modname, modenv)
		return existing
	end

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
		loadstring = global.loadstring,
		setmetatable = global.setmetatable,
		rawget = global.rawget,
		rawset = global.rawset,
		open = global.io.open,
	}
	local recorded, read_err = read_entries(api)
	if read_err then
		api.error("[luajit] Cannot initialize mod blacklist: " .. read_err, 0)
	end

	local manager = api.setmetatable({
		global = global,
		api = api,
		modmanager = modmanager,
		recorded = recorded,
		persisted = {},
		env_owner = api.setmetatable({}, { __mode = "k" }),
		string_copies = api.setmetatable({}, { __mode = "k" }),
		own_functions = api.setmetatable({}, { __mode = "k" }),
		roots = {},
		original_dump = global.string.dump,
	}, Manager)
	for _, value in api.pairs(Manager) do
		if api.type(value) == "function" then
			manager.own_functions[value] = true
		end
	end

	-- Hooks in order; the manager is published only after all of them are in.
	local global_dump_wrapper = function(...)
		return manager:global_dump(...)
	end
	manager.own_functions[global_dump_wrapper] = true
	api.rawset(global.string, "dump", global_dump_wrapper)

	local old_initialize = modmanager.InitializeModMain
	function modmanager:InitializeModMain(register_modname, register_env, ...)
		manager:register_env(register_modname, register_env)
		return old_initialize(self, register_modname, register_env, ...)
	end

	manager:register_env(modname, modenv)
	manager:wrap_loader()

	api.rawset(modmanager, "_ds_luajit_mod_blacklist_installed", manager)
	return manager
end

local install = M.install

-- modimport("scripts/luajit_mod_blacklist") runs this chunk in the mod env, which
-- carries GLOBAL and modname, so one import is enough. Explicit callers (tests and
-- other loaders) have no modname in this env and call install(...) themselves.
local auto_global = GLOBAL
local auto_modname = modname
if type(auto_global) == "table" and type(auto_modname) == "string" and auto_modname ~= "" then
	install(auto_global, auto_modname, auto_global.getfenv(1))
end

return { install = install }
