-- Shared LuaJIT mod string.dump policy.
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
-- (Mod/scripts/luajit_env_bootstrap.lua) loads this chunk with kleiloadlua + setfenv and passes
-- what the native GameInjector.InitializeModEnvironment returned:
--   global          real GLOBAL (holds io/string/ModManager/debug/getfenv)
--   modname         folder name of the mod that installs this module
--   modenv          that mod's environment (registered for string.dump attribution)
--   private_root    this state's single private registry root (the manager owns it)
--   real_registry   the real registry table (root writes stay private to this mod)
-- The manager is published at private_root.controller, never on ModManager or in the registry.
--
-- The chunk env is not guaranteed to be GLOBAL (modimport hands the mod env, a
-- whitelist without getfenv/pcall/rawget), so every privileged API is reached
-- through the global argument; the only chunk-env globals used are type (name
-- validation), string/table methods, and error as a last-resort fallback.
--
-- How the mod gets real bytecode: the VM's own string.dump asks the Lua function stored in the
-- private root (root.LJ_DS_PUC51_DUMP_POLICY) who is calling. This manager
-- answers with the calling mod's folder name (or nil for the engine), and the VM
-- then returns genuine PUC Lua 5.1 bytecode for that function -- the mod's own
-- detection canary keeps working and no mod is refused. The policy function is
-- the only thing installed here: GLOBAL.string.dump keeps its native C identity,
-- so an alias saved before the install still reaches the same decision point.
--
-- A torn write cannot be repaired here: the game io only offers "w" (truncate),
-- there is no atomic replace, so a crash mid-write leaves partial JSON. That is
-- reported as an initialization error (the file must be deleted), never silently
-- treated as an empty list.
--
-- Attribution is always by caller: mod B dumping mod A's function records B, and
-- the bytecode still comes from A's function (its own saved source). The manager
-- installs, once per state:
--   * a copied per-mod env string table whose dump front end names that mod,
--   * the registry policy closure the VM consults (Lua cannot be reached from C
--     any other way, and only Lua can walk its own caller stack),
--   * a ModManager:InitializeModMain hook that registers every mod env.
-- It is enforced whenever LuaJIT is the VM: no config key, no luajit_compatible
-- exemption, no HideGlobalJIT interaction.
-- Heuristic *encrypted* mod detection keeps its own JIT-off behaviour in
-- jit.runtime and never feeds this list.
-- The installing mod is not exempt either: its own scripts (including the bundled
-- jit/*.lua) must never call string.dump through the mod env, or it records itself.

local BLACKLIST_PATH = "unsafedata/luajit_mod_blacklist.json"
local POLICY_KEY = "LJ_DS_PUC51_DUMP_POLICY"
local DUMP_FAILED = "[luajit] Mod '%s': PUC 5.1 string.dump failed: %s"
local INVALID_ENTRY = "[luajit] Invalid mod blacklist entry ignored"

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

-- Module names that exist only in LuaJIT. Masked for mod callers; engine/tools keep
-- the real loader. `bit` is a LuaJIT library too: the reference PUC 5.1 VM does not load it
-- (src/lua51/src/linit.c), so it is part of the same grant.
local function is_luajit_module(name)
	if type(name) ~= "string" then
		return false
	end
	if name == "ffi" or name == "bit" or name == "jit" or name:sub(1, 4) == "jit." then
		return true
	end
	return name == "table.new" or name == "table.clear" or name == "string.buffer"
		or name == "memprof"
end

-- package.loadlib init names that either return a LuaJIT extension or repopulate its preload
-- entries (luaopen_table/string/debug are stock but reinstall table.new/clear, string.buffer and
-- upvalueid/upvaluejoin into the shared registry).
local function is_extension_opener(name)
	if type(name) ~= "string" or name:sub(1, 8) ~= "luaopen_" then
		return false
	end
	return name == "luaopen_ffi" or name == "luaopen_bit" or name == "luaopen_jit"
		or name == "luaopen_memprof" or name == "luaopen_string_buffer"
		or name == "luaopen_string" or name == "luaopen_table" or name == "luaopen_debug"
		or name:sub(1, 12) == "luaopen_jit_"
end

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
-- tail-call pseudo frames and this manager's own frames are skipped. Priority:
-- visible mod frame -> currentlyloadingmod.
function Manager:caller_modname()
	local level = 1
	while true do
		local ok, info = self.api.pcall(self.api.getinfo, level, "fS")
		if not ok or self.api.type(info) ~= "table" then
			break
		end
		local func = info.func
		local source = info.source
		local skip = true
		if func and info.what ~= "C" then
			if self.own_functions[func] then
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
		end
		level = level + 1
	end
	return self:current_loading_modname()
end

-- The VM's string.dump policy only names the caller for the blacklist record and
-- error text. The VM dumps PUC 5.1 for every Lua function while the host bridge
-- exists, so nil here is not a bytecode decision.
-- before the answer, so the JSON always contains the mod whose dump the VM is
-- about to convert; a failing write is reported instead of silently losing it.
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

-- Registers a mod env. Attribution (frames + MODROOT prefix) is recorded for every mod;
-- then the env either gets the LuaJIT access environment (a mod that declared
-- `modinfo.luajit_compatible`) or the stock surface scrub (everyone else). This runs from the
-- one InitializeModMain hook, before the engine executes the mod's own modmain.
function Manager:register_env(modname, env)
	if not is_valid_modname(modname) or self.api.type(env) ~= "table" then
		return false
	end
	self.env_owner[env] = modname
	self.envs[modname] = env
	self:remember_root(modname, env)
	if not self.has_luajit then
		-- The classic VM has no LuaJIT surface to hand out and nothing to scrub.
		return true
	end
	if self.compat[env] ~= nil then
		return true
	end
	if modname == self.installing_modname then
		-- This mod's own env is where the manager itself lives: it gets the same local
		-- capability containers, plus the private registry and the two injector tables.
		return self:grant(env, true)
	end
	if self:declares_compat(env) then
		return self:grant(env, false)
	end
	return self:scrub_env(modname, env)
end

-- The authorised local env of a registered mod (discovery hands it to that mod's external
-- packages as their parent; it never goes through a plugin context).
function Manager:mod_env(modname)
	if not is_valid_modname(modname) then
		return nil
	end
	return self.envs[modname]
end

function Manager:remember_root(modname, env)
	local api = self.api
	local ok, root = api.pcall(function()
		return env.MODROOT
	end)
	if ok and api.type(root) == "string" and root ~= "" then
		local norm = root:gsub("\\", "/")
		if norm:sub(-1) ~= "/" then
			norm = norm .. "/"
		end
		self.roots[norm] = modname
	end
end

-- The declaration is the only grant: `modinfo.luajit_compatible == true` or a table. A mod
-- name substring, the caller stack or EnabledJIT/HideGlobalJIT never grants access.
function Manager:declares_compat(env)
	local api = self.api
	local info = api.rawget(env, "modinfo")
	if api.type(info) ~= "table" then
		local ok, value = api.pcall(function()
			return env.modinfo
		end)
		if ok then
			info = value
		end
	end
	if api.type(info) ~= "table" then
		return false
	end
	local flag = api.rawget(info, "luajit_compatible")
	if flag == nil then
		local ok, value = api.pcall(function()
			return info.luajit_compatible
		end)
		if ok then
			flag = value
		end
	end
	return flag == true or api.type(flag) == "table"
end

-- Shallow copy of a family table (jit/bit/ffi/debug/table/string and the jit submodules).
-- Functions and the VM state behind them stay shared by reference; the metatable stays the
-- original one, so a copy is interchangeable with stock.
function Manager:copy_family(source)
	local api = self.api
	local copy = {}
	for key, value in api.pairs(source) do
		copy[key] = value
	end
	return api.setmetatable(copy, api.getmetatable(source))
end

-- The env's own copy for an extension module name, or nil when this build does not ship it.
function Manager:extension_value(name, state)
	local copies = state.copies
	if name == "jit" then return copies.jit end
	if name == "bit" then return copies.bit end
	if name == "ffi" then return copies.ffi end
	if name == "table.new" then return copies["table.new"] end
	if name == "table.clear" then return copies["table.clear"] end
	if name == "string.buffer" then return copies["string.buffer"] end
	if name == "jit.opt" or name == "jit.util" or name == "jit.profile" then
		return copies[name]
	end
	if name == "memprof" then return copies.memprof end
	return nil
end

-- Per-env LuaJIT capability (the "authorised view"). Every container is private to this env
-- and points at exactly the same function objects; nothing is deep-copied and the VM state
-- stays one. Callers: a game mod that declares `luajit_compatible`, and this mod's own
-- environments (installer env and every plugin face/package).
function Manager:grant(env, is_installer)
	local api = self.api
	local copies = {}
	for _, name in api.pairs({"jit", "bit", "ffi", "debug", "table", "string"}) do
		local source = self.modules[name]
		if api.type(source) == "table" then
			copies[name] = self:copy_family(source)
		end
	end
	if copies.jit then
		for _, sub in api.pairs({"jit.opt", "jit.util", "jit.profile"}) do
			if api.type(self.modules[sub]) == "table" then
				copies[sub] = self:copy_family(self.modules[sub])
				copies.jit[sub:sub(5)] = copies[sub]
			end
		end
	end
	if api.type(self.modules.memprof) == "table" then
		copies.memprof = self:copy_family(self.modules.memprof)
	end
	if copies.debug then
		copies.debug.upvalueid = self.modules.upvalueid
		copies.debug.upvaluejoin = self.modules.upvaluejoin
	end
	-- Require-only extension modules: their values are also fields of the family copy, so
	-- `luajit.table.new` and `require("table.new")` are the same function.
	for _, name in api.pairs({"table.new", "table.clear", "string.buffer"}) do
		local module = self.modules[name]
		if module ~= nil then
			copies[name] = api.type(module) == "table" and self:copy_family(module) or module
		end
	end
	if copies.table then
		copies.table.new = copies["table.new"]
		copies.table.clear = copies["table.clear"]
	end
	if copies.string then
		copies.string.buffer = copies["string.buffer"]
	end

	local luajit = {}
	for _, name in api.pairs({"jit", "bit", "ffi", "debug", "table", "string"}) do
		luajit[name] = copies[name]
	end
	if is_installer then
		-- Only this mod reads/writes the real registry (the engine's own table, not the
		-- filtered getregistry snapshot other mods see).
		luajit.registry = self.registry
	end

	-- Declared mods see the real package table. Its loaded/preload are overlays over the safe
	-- base, so this env can use the captured extensions without the ordinary surface seeing
	-- them; the shared require remains bound to the safe package.
	local package_copy = self.real_package or self.safe_package or self.global.package
	local loaded = {}
	local preload = {}
	for _, name in api.pairs({"jit", "bit", "ffi", "table.new", "table.clear",
		"string.buffer", "memprof", "jit.opt", "jit.util", "jit.profile"}) do
		local value = self:extension_value(name, { copies = copies })
		if value ~= nil then
			loaded[name] = value
		end
	end
	if api.type(self.real_package) == "table" then
		if api.type(self.real_package.loaded) == "table" then
			api.setmetatable(loaded, { __index = self.real_package.loaded })
		end
		if api.type(self.real_package.preload) == "table" then
			api.setmetatable(preload, { __index = self.real_package.preload })
		end
	end

	-- Local GLOBAL: explicit extension fields stay here, every other game field is read live
	-- from the real GLOBAL and ordinary writes keep going to the shared table, so the game's
	-- state (TheWorld, ...) is one table for all mods.
	local proxy = {}
	api.setmetatable(proxy, {
		__index = function(_, key)
			return self.global[key]
		end,
		__newindex = function(_, key, value)
			self.global[key] = value
		end,
	})
	api.rawset(proxy, "_G", proxy)
	for _, name in api.pairs({"jit", "bit", "ffi", "debug", "table", "string"}) do
		if copies[name] ~= nil then
			api.rawset(proxy, name, copies[name])
		end
	end
	api.rawset(proxy, "package", package_copy)

	local state = {
		copies = copies,
		luajit = luajit,
		proxy = proxy,
		package = package_copy,
		loaded = loaded,
		loading = {},
	}
	self.compat[env] = state

	local function require_wrapper(name, ...)
		local module = self:require_extension(name, state)
		if module ~= nil then
			return module
		end
		if is_luajit_module(name) then
			return self:require_lua_extension(name, env, state)
		end
		return self.real_require(name, ...)
	end
	self.own_functions[require_wrapper] = true

	api.rawset(env, "luajit", luajit)
	api.rawset(env, "GLOBAL", proxy)
	for _, name in api.pairs({"jit", "bit", "ffi", "debug", "table", "string"}) do
		if copies[name] ~= nil then
			api.rawset(env, name, copies[name])
		end
	end
	api.rawset(env, "package", package_copy)
	api.rawset(env, "require", require_wrapper)
	return true
end

-- The authorised view our own Lua faces run in (Mod/plugins/*, plugin packages and the
-- scripts loaded next to them). Same grant as the installing mod, plus the two injector
-- tables, and `_G` is the view itself: a normal lookup finds the granted surface, and engine
-- globals still fall through to the real GLOBAL. Built once per state.
function Manager:grant_plugin_view()
	local api = self.api
	if self.plugin_view ~= nil then
		return self.plugin_view
	end
	local view = {}
	if self.has_luajit then
		self:grant(view, true)
	end
	api.setmetatable(view, {
		__index = self.global,
		__newindex = self.global,
	})
	api.rawset(view, "_G", view)
	api.rawset(view, "GameInjector", api.rawget(self.root, "GameInjector"))
	api.rawset(view, "GameLuaInjector", api.rawget(self.root, "GameLuaInjector"))
	-- Add*PostInit are installed into each mod env by the engine, not into GLOBAL; our faces
	-- call them exactly like the tool mod does.
	local installer_env = self.envs[self.installing_modname]
	if api.type(installer_env) == "table" then
		for _, name in api.pairs({"AddGamePostInit", "AddSimPostInit", "AddPlayerPostInit",
			"AddPrefabPostInit"}) do
			-- pcall: a mod env may carry strict.lua, which raises on an undeclared read.
			local ok, fn = api.pcall(function()
				return installer_env[name]
			end)
			if ok and api.type(fn) == "function" then
				api.rawset(view, name, fn)
			end
		end
	end
	self.plugin_view = view
	return view
end

-- Ordinary mods keep the stock PUC surface: copies of the whitelisted libraries with every
-- LuaJIT-only entry removed, and a require that answers extension names with the stock
-- "module not found" error. No loader can reach root.modules from here.
function Manager:scrub_env(modname, env)
	local api = self.api
	local function env_field(name)
		local value = api.rawget(env, name)
		if value == nil then
			local ok, indexed = api.pcall(function()
				return env[name]
			end)
			if ok then
				value = indexed
			end
		end
		return value
	end
	local function masked_copy(source, nil_keys)
		if api.type(source) ~= "table" then
			return nil
		end
		local result = {}
		for key, value in api.pairs(source) do
			result[key] = value
		end
		for _, key in api.pairs(nil_keys) do
			result[key] = nil
		end
		return result
	end
	local debug_copy = masked_copy(env_field("debug") or self.global.debug,
		{"upvalueid", "upvaluejoin"})
	if debug_copy then
		api.rawset(env, "debug", debug_copy)
	end
	local table_copy = masked_copy(env_field("table") or self.global.table, {"new", "clear"})
	if table_copy then
		api.rawset(env, "table", table_copy)
	end
	local string_copy = api.rawget(env, "string")
	if api.type(string_copy) == "table" then
		api.rawset(string_copy, "buffer", nil)
	end
	local env_package = env_field("package")
	if api.type(env_package) == "table" then
		api.rawset(env, "package", self.safe_package or env_package)
	end
	local env_require = api.rawget(env, "require")
	if api.type(env_require) ~= "function" then
		local ok, indexed = api.pcall(function()
			return env.require
		end)
		if ok then
			env_require = indexed
		end
	end
	if api.type(env_require) == "function" then
		api.rawset(env, "require", self.safe_require or env_require)
	end
	return true
end

function Manager:require_extension(name, state)
	return self:extension_value(name, state)
end

-- LuaJIT's own jit/*.lua modules (jit.bc, jit.v, jit.dis_*) do not exist as C modules. They
-- load through this env's private cache: this mod's scripts/jit first, then the loaders saved
-- at install, always into the calling mod's authorised env. Nothing is written to the shared
-- package.loaded/preload.
function Manager:require_lua_extension(name, env, state)
	local api = self.api
	local loaded = state.loaded
	local loading = state.loading
	if loaded[name] ~= nil then
		if loaded[name] == loading then
			api.error("loop or previous error loading module '" .. name .. "'", 2)
		end
		return loaded[name]
	end
	loaded[name] = loading
	local ok, result = api.pcall(self.load_lua_extension, self, name, env)
	if not ok then
		loaded[name] = nil
		api.error(result, 0)
	end
	if result == nil then
		result = true
	end
	loaded[name] = result
	if api.type(self.real_package) == "table" and api.type(self.real_package.loaded) == "table" then
		api.rawset(self.real_package.loaded, name, result)
	end
	return result
end

function Manager:load_lua_extension(name, env)
	local api = self.api
	local searched = {}
	local roots = {}
	if api.type(self.installer_modroot) == "string" and self.installer_modroot ~= "" then
		roots[#roots + 1] = self.installer_modroot
	end
	local modroot = api.rawget(env, "MODROOT")
	if api.type(modroot) ~= "string" or modroot == "" then
		local ok, value = api.pcall(function()
			return env.MODROOT
		end)
		if ok then
			modroot = value
		end
	end
	if api.type(modroot) == "string" and modroot ~= "" and modroot ~= self.installer_modroot then
		roots[#roots + 1] = modroot
	end
	for _, root in api.pairs(roots) do
		local filepath = root .. "scripts/" .. name:gsub("%.", "/") .. ".lua"
		local chunk = self.kleiloadlua(filepath)
		if api.type(chunk) == "function" then
			api.setfenv(chunk, env)
			return chunk(name)
		end
		if api.type(chunk) == "string" then
			searched[#searched + 1] = "\n\tno file '" .. filepath .. "'"
		end
	end
	for index = 1, #self.loaders do
		local ok, result = api.pcall(self.loaders[index], name)
		if ok then
			if api.type(result) == "function" then
				local set_ok, set_err = api.pcall(api.setfenv, result, env)
				if not set_ok then
					api.error("module '" .. name .. "': loader returned a C function ("
						.. api.tostring(set_err) .. ")", 2)
				end
				return result(name)
			elseif api.type(result) == "string" then
				searched[#searched + 1] = result
			end
		end
	end
	api.error("module '" .. name .. "' not found:" .. api.concat(searched), 2)
end

function Manager:caller_info(start_level)
	for level = start_level or 2, 16 do
		local ok, info = self.api.pcall(self.api.getinfo, level, "Sf")
		if not ok or self.api.type(info) ~= "table" then
			return nil
		end
		if info.what ~= "C" and not self.own_functions[info.func] then
			local source = info.source
			if not (self.api.type(source) == "string"
				and source:find("luajit_mod_blacklist", 1, true)) then
				return info
			end
		end
	end
	return nil
end

function Manager:frame_mod_owner(info)
	if not info then
		return nil
	end
	local owner = self:locate(info.source)
	if is_valid_modname(owner) then
		return owner
	end
	local source = info.source
	if self.api.type(source) == "string"
		and not source:find("GameLuaInjectFramework", 1, true)
		and not source:find("luajit_mod_blacklist", 1, true) then
		local ok, fenv = self.api.pcall(self.api.getfenv, info.func)
		if ok and self.api.type(fenv) == "table" then
			owner = self.env_owner[fenv]
			if is_valid_modname(owner) then
				return owner
			end
		end
	end
	return nil
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
-- GameInjector.InitializeModEnvironment returned; the manager never publishes itself on
-- ModManager or in the shared registry. Every piece of state it owns lives in the root.
function M.install(global, modname, modenv, private_root, real_registry)
	local error_fn = global.error
	if type(error_fn) ~= "function" then
		error_fn = error
	end
	local function init_error(message)
		error_fn(message, 0)
	end
	if type(private_root) ~= "table" then
		init_error("[luajit] Cannot initialize mod blacklist: private registry root is required")
	end
	if type(real_registry) ~= "table" then
		init_error("[luajit] Cannot initialize mod blacklist: real registry is required")
	end
	local modmanager = global.ModManager
	local existing = private_root.controller
	if existing ~= nil then
		if type(existing) ~= "table" or getmetatable(existing) ~= Manager then
			init_error("[luajit] Cannot initialize mod blacklist: private registry root is already owned")
		end
		existing:register_env(modname, modenv)
		return existing
	end
	if private_root[POLICY_KEY] ~= nil then
		init_error("[luajit] Cannot initialize mod blacklist: registry key " .. POLICY_KEY .. " already in use")
	end
	local missing = missing_apis(global)
	if #missing > 0 then
		local names = missing[1]
		for index = 2, #missing do
			names = names .. ", " .. missing[index]
		end
		init_error("[luajit] Cannot initialize mod blacklist: " .. names)
	end
	if not is_valid_modname(modname) then
		init_error("[luajit] Cannot initialize mod blacklist: invalid modname")
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
		setfenv = global.setfenv,
		getmetatable = global.getmetatable,
		loadstring = global.loadstring,
		setmetatable = global.setmetatable,
		rawget = global.rawget,
		rawset = global.rawset,
		open = global.io.open,
	}
	local recorded, read_err = read_entries(api)
	if read_err then
		init_error("[luajit] Cannot initialize mod blacklist: " .. read_err)
	end
	-- The native require as it is right now: the file hijack is already installed on it and
	-- normal modules must keep going through that exact object.
	local real_require = global.require

	local manager = api.setmetatable({
		global = global,
		api = api,
		modmanager = modmanager,
		installing_modname = modname,
		recorded = recorded,
		persisted = {},
		env_owner = api.setmetatable({}, { __mode = "k" }),
		own_functions = api.setmetatable({}, { __mode = "k" }),
		envs = {},
		roots = {},
		root = private_root,
		registry = real_registry,
		modules = {},
		compat = api.setmetatable({}, { __mode = "k" }),
		real_require = real_require,
		kleiloadlua = global.kleiloadlua,
		loaders = {},
		has_luajit = api.type(global.jit) == "table",
	}, Manager)
	for _, value in api.pairs(Manager) do
		if api.type(value) == "function" then
			manager.own_functions[value] = true
		end
	end
	-- The installing mod's scripts/jit/*.lua directory is the first place a compatible mod's
	-- private jit.* loader looks (this module ships them); a caller's own MODROOT is second.
	local ok_root, installer_root = api.pcall(function()
		return modenv.MODROOT
	end)
	if ok_root and api.type(installer_root) == "string" and installer_root ~= "" then
		manager.installer_modroot = installer_root
	end
	-- Publish the owner first: a second install in this state reuses it instead of building a
	-- second ledger, and a failure below leaves a controller no one can mistake for absent.
	private_root.controller = manager

	-- Capture the extension surface before the first scrub. C submodules load only when this
	-- build already exposes them (loaded or preload): a missing module means this VM does not
	-- ship it, and an existing one that fails to load is an initialization error. Lua jit.*
	-- modules are loaded lazily per compatible env (require_lua_extension).
	if manager.has_luajit then
		manager.modules.jit = global.jit
		manager.modules.bit = global.bit
		-- require's C implementation uses the package table in its own environment, which is
		-- not necessarily the current GLOBAL.package (the engine may have replaced the field).
		local package_table = global.package
		local injector = modenv and api.rawget(modenv, "GameInjector")
		if api.type(injector) ~= "table" then
			injector = global.GameInjector
		end
		local get_env = api.type(injector) == "table"
			and api.rawget(injector, "GetFunctionEnvironment") or nil
		if api.type(get_env) == "function" then
			local ok_env, require_env = api.pcall(get_env, real_require)
			if ok_env and api.type(require_env) == "table" then
				package_table = require_env
			end
		end
		manager.source_package = package_table
		local function available(name)
			if api.type(package_table) ~= "table" then
				return false
			end
			for _, map_name in api.pairs({"loaded", "preload"}) do
				local map = package_table[map_name]
				if api.type(map) == "table" and map[name] ~= nil then
					return true
				end
			end
			return false
		end
		-- table.new / table.clear / string.buffer are require-only modules in LuaJIT (they are
		-- not fields of the libraries), so they are captured through the loader like ffi.
		for _, name in api.pairs({"ffi", "memprof", "jit.opt", "jit.util", "jit.profile",
			"table.new", "table.clear", "string.buffer"}) do
			if api.type(real_require) == "function" and available(name) then
				local ok, module = api.pcall(real_require, name)
				if not ok then
					init_error("[luajit] Cannot initialize mod blacklist: cannot load " .. name
						.. ": " .. api.tostring(module))
				end
				if module ~= nil then
					manager.modules[name] = module
				end
			end
		end
		local debug_table = api.rawget(global, "debug")
		if api.type(debug_table) == "table" then
			manager.modules.debug = debug_table
			manager.modules.upvalueid = api.rawget(debug_table, "upvalueid")
			manager.modules.upvaluejoin = api.rawget(debug_table, "upvaluejoin")
		end
		local table_table = api.rawget(global, "table")
		if api.type(table_table) == "table" then
			manager.modules.table = table_table
		end
		local string_table = api.rawget(global, "string")
		if api.type(string_table) == "table" then
			manager.modules.string = string_table
		end
		local loaders = {}
		if api.type(package_table) == "table" and api.type(package_table.loaders) == "table" then
			for index = 1, #package_table.loaders do
				loaders[index] = package_table.loaders[index]
			end
		end
		manager.loaders = loaders
		api.rawset(private_root, "modules", manager.modules)
	end

	-- The VM consults this closure through the private root. Another live manager must not be
	-- silently displaced (checked above, before any state was replaced).
	if manager.has_luajit then
		local policy = function()
			return manager:dump_policy()
		end
		manager.own_functions[policy] = true
		private_root[POLICY_KEY] = policy
		if private_root[POLICY_KEY] ~= policy then
			init_error("[luajit] Cannot initialize mod blacklist: cannot publish " .. POLICY_KEY)
		end
	end

	-- Build the two package views:
	--   safe_package: a separate table for ordinary mod envs. Its loaded/preload are the
	--     scrubbed shared tables, and path/cpath/loaders forward to the stock package that
	--     require actually uses (so game loaders inserted later stay visible).
	--   real_package: a separate view for declared mods. Its loaded is an overlay
	--     (extension entries on top of the safe base); preload/loaders/loadlib match safe.
	-- The stock package table itself keeps its loaded=registry._LOADED identity, its real
	-- loader array and its path; only extension entries and loadlib are replaced.
	if manager.has_luajit then
		local package_table = manager.source_package or global.package
		local safe_loaded = api.rawget(package_table, "loaded")
		if api.type(safe_loaded) ~= "table" then
			safe_loaded = {}
		end
		for key in api.pairs(safe_loaded) do
			if is_luajit_module(key) then
				api.rawset(safe_loaded, key, nil)
			end
		end
		local safe_preload = {}
		if api.type(api.rawget(package_table, "preload")) == "table" then
			for name, value in api.pairs(package_table.preload) do
				if not is_luajit_module(name) then
					safe_preload[name] = value
				end
			end
		end
		local real_loaded = api.setmetatable({}, { __index = safe_loaded })
		for name, value in api.pairs(manager.modules) do
			if is_luajit_module(name) and value ~= nil then
				api.rawset(real_loaded, name, value)
			end
		end

		local safe_loaders = package_table.loaders
		local real_loadlib = api.rawget(package_table, "loadlib")
		local function safe_loadlib(path, init)
			if is_extension_opener(init) then
				return nil, "LuaJIT extension libraries are disabled in this package"
			end
			if api.type(real_loadlib) ~= "function" then
				return nil, "package.loadlib is unavailable"
			end
			return real_loadlib(path, init)
		end

		-- The stock require closure keeps its original package table and environment. That
		-- table keeps its loaded=registry._LOADED identity and its loader array (the game adds
		-- its custom loader after this mod), so only the extension entries and loadlib are
		-- touched. A separate real view is for declared mods; both are new tables so the
		-- loader/package identities the game mutates stay intact.
		api.rawset(package_table, "preload", safe_preload)
		api.rawset(package_table, "loadlib", safe_loadlib)
		local function forward_path(path)
			if api.type(path) ~= "string" then
				return path
			end
			if not path:find("scripts/?.lua", 1, true) then
				path = path .. ";scripts/?.lua"
			end
			if not path:find("scriptlibs/?.lua", 1, true) then
				path = path .. ";scriptlibs/?.lua"
			end
			return path
		end
		api.rawset(package_table, "path", forward_path(api.rawget(package_table, "path")))

		local safe_package = {}
		safe_package.loaded = safe_loaded
		safe_package.preload = safe_preload
		safe_package.loaders = safe_loaders
		safe_package.loadlib = safe_loadlib
		api.setmetatable(safe_package, {
			__index = package_table,
			__newindex = function(_, key, value)
				api.rawset(package_table, key, value)
			end,
		})

		local real_package = {
			loaded = real_loaded,
			preload = safe_preload,
			loaders = safe_loaders,
			loadlib = safe_loadlib,
		}
		api.setmetatable(real_package, { __index = safe_package })

		manager.safe_package = safe_package
		manager.real_package = real_package
		-- GLOBAL keeps the stock package identity (its loaded/preload/loadlib are already the
		-- scrubbed-safe ones); ordinary mod envs get the separate safe_package view.
		api.rawset(global, "package", package_table)

		-- registry._LOADED is the table stock require consults; it must be the safe base.
		api.rawset(real_registry, "_LOADED", safe_loaded)
		api.rawset(real_registry, "_PRELOAD", safe_preload)
		for _, key in api.pairs({"_LOADED", "_PRELOAD"}) do
			local map = api.rawget(real_registry, key)
			if api.type(map) == "table" then
				for name in api.pairs(map) do
					if is_luajit_module(name) then
						api.rawset(map, name, nil)
					end
				end
			end
		end

		-- Leave the stock require object and its real package environment untouched. The real
		-- package already has the extension-free preload/loadlib and the safe registry loaded
		-- table, so `require("jit")` fails naturally while the game's path/custom loaders
		-- (which are installed after this mod) keep working. Plain envs get that same require.
		manager.real_require = real_require
		manager.safe_require = real_require

		api.rawset(global, "jit", nil)
		-- DST's own scripts use the global `bit` library (e.g. scrapbookpartitions), so the
		-- engine surface keeps it; only jit/ffi/upvalueid/table.new/string.buffer are masked.
		if api.type(global.debug) == "table" then
			api.rawset(global.debug, "upvalueid", nil)
			api.rawset(global.debug, "upvaluejoin", nil)
		end
		if api.type(global.table) == "table" then
			api.rawset(global.table, "new", nil)
			api.rawset(global.table, "clear", nil)
		end
		if api.type(global.string) == "table" then
			api.rawset(global.string, "buffer", nil)
		end
	end

	-- One InitializeModMain hook: every mod env is registered (attribution) and, before the
	-- engine runs it, either authorised or scrubbed.
	local old_initialize = modmanager.InitializeModMain
	local function initialize_hook(self, register_modname, register_env, ...)
		manager:register_env(register_modname, register_env)
		return old_initialize(self, register_modname, register_env, ...)
	end
	manager.own_functions[initialize_hook] = true
	modmanager.InitializeModMain = initialize_hook

	manager:register_env(modname, modenv)
	return manager
end

return { install = M.install }
