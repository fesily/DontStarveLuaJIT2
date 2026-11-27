-- The LuaJIT surface of one VM state: the hide and inject halves.
--
-- hide: before the first game mod runs, the shared surface loses what only LuaJIT has:
--   GLOBAL.jit, debug.upvalueid/upvaluejoin, table.new/table.clear, string.buffer, the
--   extension entries in package.loaded/preload and the loadlib openers that would put them
--   back. GLOBAL keeps its own package table identity and DST's `bit` (the engine uses it);
--   every ordinary mod env gets private stock copies of debug/table/string plus the safe
--   package and the stock require. Nothing on that side can reach the captured modules.
-- inject: a mod that declares `modinfo.luajit_compatible` (and this mod's own faces) gets a
--   per-env grant: private containers pointing at the same function objects, the real
--   package overlay, and the private jit.* loader. The installing mod also sees the real
--   registry; our own faces (grant_plugin_view) see a view whose writes land in the real
--   GLOBAL. `GLOBAL` is the one granted surface; `_G` is not written into any env (a stock mod
--   env does not define it, and relying on it would be guessing the engine's semantics).
--
-- No module above this one owns a per-mod dump policy: `declares_compat` is the only grant
-- rule and `register_env` is the one place that decides grant vs scrub.
--
-- Chunk env: the mod env (loaded through modrequire), so privileged APIs come from the api
-- table the caller built; only `type` and the string/table methods are read from the chunk env.

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
local Surface = {}
Surface.__index = Surface

-- api: the privileged-API table the caller built from the real GLOBAL.
-- opts: global, modname, modenv (the installing mod env), private_root, real_registry.
function Surface.new(api, opts)
	local self = api.setmetatable({
		api = api,
		global = opts.global,
		root = opts.private_root,
		registry = opts.real_registry,
		installer_env = opts.modenv,
		installing_modname = opts.modname,
		modules = {},
		loaders = {},
		envs = {},
		roots = {},
		env_owner = api.setmetatable({}, { __mode = "k" }),
		compat = api.setmetatable({}, { __mode = "k" }),
		own_functions = api.setmetatable({}, { __mode = "k" }),
		real_require = opts.global.require,
		kleiloadlua = opts.global.kleiloadlua,
		-- rawget: under a stock (PUC) VM there is no `jit` in GLOBAL, and a dev-branch client
		-- installs scripts/strict.lua as GLOBAL's __index, which turns that probe into
		-- "variable 'jit' is not declared" and aborts the whole mod load.
		has_luajit = api.type(api.rawget(opts.global, "jit")) == "table",
	}, Surface)
	-- Frames of this module and of the blacklist module are never attribution candidates.
	for _, value in api.pairs(Surface) do
		if api.type(value) == "function" then
			self.own_functions[value] = true
		end
	end
	-- The installing mod's scripts/jit/*.lua directory is the first place a compatible mod's
	-- private jit.* loader looks (this module ships them); a caller's own MODROOT is second.
	local ok_root, installer_root = api.pcall(function()
		return self.installer_env.MODROOT
	end)
	if ok_root and api.type(installer_root) == "string" and installer_root ~= "" then
		self.installer_modroot = installer_root
	end
	return self
end

function Surface:mark_own(func)
	if self.api.type(func) == "function" then
		self.own_functions[func] = true
	end
end

function Surface:is_own(func)
	return self.own_functions[func] == true
end

function Surface:owner_of(env)
	local owner = self.env_owner[env]
	if self.api.type(owner) == "string" then
		return owner
	end
	return nil
end

-- Shallow copy of a family table (jit/bit/ffi/debug/table/string and the jit submodules).
-- Functions and the VM state behind them stay shared by reference; the metatable stays the
-- original one, so a copy is interchangeable with stock.
function Surface:copy_family(source)
	local api = self.api
	local copy = {}
	for key, value in api.pairs(source) do
		copy[key] = value
	end
	return api.setmetatable(copy, api.getmetatable(source))
end

-- The env's own copy for an extension module name, or nil when this build does not ship it.
function Surface:extension_value(name, state)
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
function Surface:grant(env, is_installer)
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
-- tables: plain names resolve to the granted surface (jit/ffi/.../GameInjector), `GLOBAL` is the
-- proxy whose reads and writes reach the real GLOBAL, and `_G` is not defined here (it resolves
-- to the real GLOBAL through the fallthrough, exactly like every other engine name). Built once
-- per state.
function Surface:grant_plugin_view()
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
function Surface:scrub_env(env)
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

function Surface:require_extension(name, state)
	return self:extension_value(name, state)
end

-- LuaJIT's own jit/*.lua modules (jit.bc, jit.v, jit.dis_*) do not exist as C modules. They
-- load through this env's private cache: this mod's scripts/jit first, then the loaders saved
-- at install, always into the calling mod's authorised env. Nothing is written to the shared
-- package.loaded/preload.
function Surface:require_lua_extension(name, env, state)
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

function Surface:load_lua_extension(name, env)
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

function Surface:remember_root(modname, env)
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
function Surface:declares_compat(env)
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

-- Registers a mod env. Attribution (frames + MODROOT prefix) is recorded for every mod;
-- then the env either gets the LuaJIT access environment (a mod that declared
-- `modinfo.luajit_compatible`) or the stock surface scrub (everyone else). This runs from the
-- one InitializeModMain hook, before the engine executes the mod's own modmain.
function Surface:register_env(modname, env)
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
		-- This mod's own env is where the installer lives: it gets the same local
		-- capability containers, plus the private registry and the two injector tables.
		return self:grant(env, true)
	end
	if self:declares_compat(env) then
		return self:grant(env, false)
	end
	return self:scrub_env(env)
end

-- The authorised local env of a registered mod (discovery hands it to that mod's external
-- packages as their parent; it never goes through a plugin context).
function Surface:mod_env(modname)
	if not is_valid_modname(modname) then
		return nil
	end
	return self.envs[modname]
end

-- Maps a game path (or a debug source) to a mod folder name. Only the exact
-- "../mods/<name>/..." layout and registered MODROOT prefixes count, so a path
-- that merely mentions "mods" is not guessed at. Returns name, remainder.
function Surface:locate(path)
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

-- Capture the extension surface before the first scrub. C submodules load only when this
-- build already exposes them (loaded or preload): a missing module means this VM does not
-- ship it, and an existing one that fails to load is an initialization error. Lua jit.*
-- modules are loaded lazily per compatible env (require_lua_extension).
function Surface:capture()
	local api = self.api
	if self.has_luajit then
		self.modules.jit = self.global.jit
		self.modules.bit = self.global.bit
		-- require's C implementation uses the package table in its own environment, which is
		-- not necessarily the current GLOBAL.package (the engine may have replaced the field).
		local package_table = self.global.package
		local injector = self.installer_env and api.rawget(self.installer_env, "GameInjector")
		if api.type(injector) ~= "table" then
			injector = self.global.GameInjector
		end
		local get_env = api.type(injector) == "table"
			and api.rawget(injector, "GetFunctionEnvironment") or nil
		if api.type(get_env) == "function" then
			local ok_env, require_env = api.pcall(get_env, self.real_require)
			if ok_env and api.type(require_env) == "table" then
				package_table = require_env
			end
		end
		self.source_package = package_table
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
			if api.type(self.real_require) == "function" and available(name) then
				local ok, module = api.pcall(self.real_require, name)
				if not ok then
					self.api.error("[luajit] Cannot initialize the surface: cannot load " .. name
						.. ": " .. api.tostring(module))
				end
				if module ~= nil then
					self.modules[name] = module
				end
			end
		end
		local debug_table = api.rawget(self.global, "debug")
		if api.type(debug_table) == "table" then
			self.modules.debug = debug_table
			self.modules.upvalueid = api.rawget(debug_table, "upvalueid")
			self.modules.upvaluejoin = api.rawget(debug_table, "upvaluejoin")
		end
		local table_table = api.rawget(self.global, "table")
		if api.type(table_table) == "table" then
			self.modules.table = table_table
		end
		local string_table = api.rawget(self.global, "string")
		if api.type(string_table) == "table" then
			self.modules.string = string_table
		end
		local loaders = {}
		if api.type(package_table) == "table" and api.type(package_table.loaders) == "table" then
			for index = 1, #package_table.loaders do
				loaders[index] = package_table.loaders[index]
			end
		end
		self.loaders = loaders
		api.rawset(self.root, "modules", self.modules)
	end
end

-- Build the two package views and scrub the shared surface. Runs once, after capture and
-- after the VM policy is published. `safe_package` is what ordinary mod envs see;
-- `real_package` is the overlay a declared mod sees. The stock package table keeps its
-- loaded=registry._LOADED identity and its loader array (the game appends its own loader
-- later), so only the extension entries and loadlib are replaced there.
function Surface:prepare_shared()
	-- Build the two package views:
	--   safe_package: a separate table for ordinary mod envs. Its loaded/preload are the
	--     scrubbed shared tables, and path/cpath/loaders forward to the stock package that
	--     require actually uses (so game loaders inserted later stay visible).
	--   real_package: a separate view for declared mods. Its loaded is an overlay
	--     (extension entries on top of the safe base); preload/loaders/loadlib match safe.
	-- The stock package table itself keeps its loaded=registry._LOADED identity, its real
	-- loader array and its path; only extension entries and loadlib are replaced.
	local api = self.api
	if self.has_luajit then
		local package_table = self.source_package or self.global.package
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
		for name, value in api.pairs(self.modules) do
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

		self.safe_package = safe_package
		self.real_package = real_package
		-- GLOBAL keeps the stock package identity (its loaded/preload/loadlib are already the
		-- scrubbed-safe ones); ordinary mod envs get the separate safe_package view.
		api.rawset(self.global, "package", package_table)

		-- registry._LOADED is the table stock require consults; it must be the safe base.
		api.rawset(self.registry, "_LOADED", safe_loaded)
		api.rawset(self.registry, "_PRELOAD", safe_preload)
		for _, key in api.pairs({"_LOADED", "_PRELOAD"}) do
			local map = api.rawget(self.registry, key)
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
		self.safe_require = self.real_require

		api.rawset(self.global, "jit", nil)
		-- DST's own scripts use the global `bit` library (e.g. scrapbookpartitions), so the
		-- engine surface keeps it; only jit/ffi/upvalueid/table.new/string.buffer are masked.
		if api.type(self.global.debug) == "table" then
			api.rawset(self.global.debug, "upvalueid", nil)
			api.rawset(self.global.debug, "upvaluejoin", nil)
		end
		if api.type(self.global.table) == "table" then
			api.rawset(self.global.table, "new", nil)
			api.rawset(self.global.table, "clear", nil)
		end
		if api.type(self.global.string) == "table" then
			api.rawset(self.global.string, "buffer", nil)
		end
	end
end


return {
	new = Surface.new,
	Surface = Surface,
	is_valid_modname = is_valid_modname,
}

