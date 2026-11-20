-- tests/plugin/mod_blacklist_spec.lua
-- Consumer-level tests for Mod/scripts/luajit_mod_blacklist.lua.
--
-- These run inside the real game VM (tests/plugin/puc_dump_host loads the built
-- LuaJIT library and installs the production PUC 5.1 dump service), so the
-- assertions are about the product contract, not a mock:
--   * a mod calling string.dump gets genuine PUC Lua 5.1 bytecode and is recorded
--     in unsafedata/luajit_mod_blacklist.json as a compatibility hit,
--   * a recorded mod still loads and runs (fresh process): the record never
--     refuses a chunk,
--   * attribution follows the caller (env front end, GLOBAL entry, engine wrapper
--     frames, loading-time tail calls, loaded mod name/path, cross-mod aliases),
--   * persistence failures are reported and never silently lose the record,
--   * idempotent install / registry policy ownership, and the real
--     Mod/modworldgenmain.lua + modimport entry points.
-- Runner: tests/plugin/run_mod_blacklist.py (modes: cases, record, reload).
--
-- All file I/O goes through a sandbox "game io" that only accepts "r"/"w" (Klei's
-- VFS treats "a"/"w+" as reads) and maps relative paths under
-- <MOD_BLACKLIST_ROOT>/data, with mod fixtures under <MOD_BLACKLIST_ROOT>/mods.

local function repo_root()
	local from_env = os.getenv("REPO_ROOT")
	if from_env and from_env ~= "" then
		return from_env:gsub("\\", "/")
	end
	local src = debug.getinfo(1, "S").source
	if src:sub(1, 1) == "@" then
		src = src:sub(2)
	end
	src = src:gsub("\\", "/")
	local dir = src:match("^(.*)/[^/]+$") or "."
	return dir:match("^(.*)/tests/plugin$") or (dir .. "/../..")
end

local ROOT = repo_root()
local MODULE_PATH = ROOT .. "/Mod/scripts/luajit_mod_blacklist.lua"
local WORLDGEN_PATH = ROOT .. "/Mod/modworldgenmain.lua"

local real_io = io
local mode = (arg and arg[1]) or "cases"

local SB_ROOT_ENV = os.getenv("MOD_BLACKLIST_ROOT")
if not SB_ROOT_ENV or SB_ROOT_ENV == "" then
	error("MOD_BLACKLIST_ROOT is required; run tests/plugin/run_mod_blacklist.py", 0)
end
local SB_ROOT = SB_ROOT_ENV:gsub("\\", "/")
local DATA = SB_ROOT .. "/data"
local MODS = SB_ROOT .. "/mods"

local MOD_A = "workshop-900000001"
local MOD_B = "workshop-900000002"
local MOD_C = "workshop-900000003"
local TOOL = "luajit_blacklist_tool"
local LOCAL_UNICODE = "blacklist local_日本語"
local UGC_MOD = "workshop-900000004"
local UGC_ROOT = "C:/ugc/" .. UGC_MOD .. "/"

local POLICY_KEY = "LJ_DS_PUC51_DUMP_POLICY"
local PUC_HEADER = "\27Lua\81\0"
local NATIVE_HEADER = "\27LJ"

---------------------------------------------------------------------------
-- assertions

local function assert_true(cond, message)
	if not cond then
		error(message or "expected true", 2)
	end
end

local function assert_eq(actual, expected, message)
	if actual ~= expected then
		error(string.format("%s: expected %s, got %s", message or "assert_eq",
			tostring(expected), tostring(actual)), 2)
	end
end

local function assert_contains(haystack, needle, message)
	if type(haystack) ~= "string" or not haystack:find(needle, 1, true) then
		error(string.format("%s: %q does not contain %q", message or "assert_contains",
			tostring(haystack), tostring(needle)), 2)
	end
end

local function assert_func(value, message)
	if type(value) ~= "function" then
		error(string.format("%s: expected a chunk, got %s (%s)", message or "assert_func",
			type(value), tostring(value)), 2)
	end
	return value
end

local function assert_puc(bytes, message)
	local label = message or "string.dump"
	assert_eq(type(bytes), "string", label .. ": expected bytes")
	assert_eq(bytes:sub(1, #PUC_HEADER), PUC_HEADER, label .. ": expected PUC 5.1 header")
end

local function assert_native(bytes, message)
	local label = message or "string.dump"
	assert_eq(type(bytes), "string", label .. ": expected bytes")
	assert_eq(bytes:sub(1, #NATIVE_HEADER), NATIVE_HEADER, label .. ": expected LuaJIT header")
end

---------------------------------------------------------------------------
-- files

local function ensure_dir(dir)
	dir = dir:gsub("\\", "/")
	if package.config:sub(1, 1) == "\\" then
		os.execute('mkdir "' .. dir:gsub("/", "\\") .. '" 2>nul')
	else
		os.execute('mkdir -p "' .. dir .. '" 2>/dev/null')
	end
end

---------------------------------------------------------------------------
-- JSON (test-only). Bare LuaJIT has no json module, and the blacklist stores one
-- shape: an array of strings. Encoding/decoding here is deliberately strict, so a
-- non-JSON file fails instead of passing silently.

local JSON_ESCAPE = {
	['"'] = '\\"',
	["\\"] = "\\\\",
	["\n"] = "\\n",
	["\r"] = "\\r",
	["\t"] = "\\t",
}

local function json_encode(names)
	local parts = {}
	for index = 1, #names do
		local escaped = names[index]:gsub('[%c\\"]', function(char)
			return JSON_ESCAPE[char] or string.format("\\u%04x", string.byte(char))
		end)
		parts[index] = '"' .. escaped .. '"'
	end
	return "[" .. table.concat(parts, ",") .. "]"
end

local function json_decode(text)
	local position = 1

	local function fail(reason)
		error(reason .. " at byte " .. position, 0)
	end

	local function skip_space()
		position = text:find("[^ \t\r\n]", position) or (#text + 1)
	end

	local function parse_string()
		position = position + 1 -- opening quote
		local parts = {}
		while true do
			local char = text:sub(position, position)
			if char == "" then
				fail("unterminated string")
			elseif char == '"' then
				position = position + 1
				return table.concat(parts)
			elseif char == "\\" then
				local escape = text:sub(position + 1, position + 1)
				if escape == "n" then
					parts[#parts + 1] = "\n"
				elseif escape == "r" then
					parts[#parts + 1] = "\r"
				elseif escape == "t" then
					parts[#parts + 1] = "\t"
				elseif escape == "u" then
					local hex = text:sub(position + 2, position + 5)
					local code = tonumber(hex, 16)
					if not code then
						fail("bad \\u escape")
					end
					parts[#parts + 1] = string.char(code)
					position = position + 4
				elseif escape == "\\" or escape == '"' or escape == "/" or escape == "'" then
					parts[#parts + 1] = escape
				else
					fail("bad escape")
				end
				position = position + 2
			else
				parts[#parts + 1] = char
				position = position + 1
			end
		end
	end

	local parse_value
	parse_value = function()
		skip_space()
		if text:sub(position, position) ~= "[" then
			fail("expected a JSON array")
		end
		position = position + 1
		local list = {}
		skip_space()
		if text:sub(position, position) == "]" then
			position = position + 1
			return list
		end
		while true do
			skip_space()
			if text:sub(position, position) ~= '"' then
				fail("expected a string element")
			end
			list[#list + 1] = parse_string()
			skip_space()
			local next_char = text:sub(position, position)
			if next_char == "," then
				position = position + 1
			elseif next_char == "]" then
				position = position + 1
				return list
			else
				fail("expected , or ]")
			end
		end
	end

	local ok, result = pcall(parse_value)
	if not ok then
		return nil, result
	end
	skip_space()
	if position <= #text then
		return nil, "trailing data at byte " .. position
	end
	return result, nil
end

local function blacklist_path()
	return DATA .. "/unsafedata/luajit_mod_blacklist.json"
end

local function read_blacklist()
	local fp = real_io.open(blacklist_path(), "r")
	if not fp then
		return nil
	end
	local text = fp:read("*a")
	fp:close()
	return text
end

local function write_blacklist(text)
	ensure_dir(DATA .. "/unsafedata")
	local fp = assert(real_io.open(blacklist_path(), "w"))
	fp:write(text)
	fp:close()
end

local function remove_blacklist()
	os.remove(blacklist_path())
end

local function file_exists(dir, rel)
	local fp = real_io.open(dir .. "/" .. rel, "r")
	if not fp then
		return false
	end
	fp:close()
	return true
end

local function data_file_exists(rel)
	return file_exists(DATA, rel)
end

local function write_fixture(modname, rel, body)
	local dir = MODS .. "/" .. modname
	ensure_dir(dir)
	local sub = rel:match("^(.*)/[^/]*$")
	if sub then
		ensure_dir(dir .. "/" .. sub)
	end
	local fp = assert(real_io.open(dir .. "/" .. rel, "w"))
	fp:write(body)
	fp:close()
end

---------------------------------------------------------------------------
-- sandbox game surface

local function copy_table(src)
	local copy = {}
	for key, value in pairs(src) do
		copy[key] = value
	end
	return copy
end

-- Game io: relative paths live under <root>/data, only r/w are accepted, and
-- open/write/close failures can be injected per case.
local function make_game_io(opts)
	opts = opts or {}
	local api = {}
	api.open = function(path, io_mode)
		if io_mode ~= "r" and io_mode ~= "w" then
			error("sandbox game io only accepts r/w, got " .. tostring(io_mode), 0)
		end
		if opts.fail_open == io_mode then
			return nil, "simulated open failure"
		end
		local real = real_io.open(DATA .. "/" .. path:gsub("\\", "/"), io_mode)
		if not real then
			return nil, "cannot open " .. tostring(path)
		end
		local handle = {}
		handle.read = function(_, fmt)
			if opts.fail_read then
				return nil, "simulated read failure"
			end
			return real:read(fmt)
		end
		handle.write = function(_, text)
			if opts.fail_write then
				return nil, "simulated write failure"
			end
			return real:write(text)
		end
		handle.close = function(_)
			local ok, err = real:close()
			if opts.fail_close then
				return nil, "simulated close failure"
			end
			return ok, err
		end
		return handle
	end
	return api
end

local function new_fake_global(opts)
	opts = opts or {}
	local printed = {}
	-- A real GLOBAL mirrors the process globals; only the pieces the manager
	-- touches are replaced with sandboxed versions. `string.dump` stays the real
	-- VM function: that is what makes these tests exercise the product path.
	local global = {}
	for key, value in pairs(_G) do
		global[key] = value
	end
	global.io = opts.io or make_game_io(opts.io_opts)
	-- Per-sandbox copies of every table the manager may scrub: the process's own debug/table/
	-- jit/preload must survive a case.
	global.string = copy_table(string)
	global.table = copy_table(table)
	global.debug = copy_table(debug)
	global.jit = copy_table(_G.jit)
	if type(_G.bit) == "table" then
		global.bit = copy_table(_G.bit)
	end
	global.kleiloadlua = function(path)
		return loadfile(path)
	end
	global.print = function(...)
		local parts = {}
		for index = 1, select("#", ...) do
			parts[#parts + 1] = tostring(select(index, ...))
		end
		local line = table.concat(parts, " ")
		printed[#printed + 1] = line
		print("[mod-blacklist-spec] " .. line)
	end
	global.__printed = printed
	-- Private package table: scrubbing it must never poison this process's real
	-- package.loaded/preload for later cases.
	global.package = {
		loaded = {},
		preload = copy_table(package.preload or {}),
		loaders = package.loaders,
		path = package.path,
		cpath = package.cpath,
		config = package.config,
	}
	local host_require = global.require
	global.require = function(name, ...)
		local from_manager = false
		for level = 2, 8 do
			local info = debug.getinfo(level, "S")
			if info and type(info.source) == "string"
				and info.source:find("luajit_mod_blacklist", 1, true) then
				from_manager = true
				break
			end
		end
		if not from_manager
			and (name == "ffi" or name == "bit" or name == "jit"
				or tostring(name):sub(1, 4) == "jit."
				or name == "table.new" or name == "table.clear"
				or name == "string.buffer" or name == "memprof") then
			error("module '" .. tostring(name) .. "' not found:", 2)
		end
		return host_require(name, ...)
	end
	global.json = { encode = json_encode, decode = json_decode }
	global.GLOBAL = global
	global.GetModConfigData = nil
	global.WORLDGEN_MAIN = nil

	local modmanager = {}
	modmanager.currentlyloadingmod = nil
	function modmanager:InitializeModMain(modname, env, mainfile, safe, ...)
		self.initialized = (self.initialized or 0) + 1
		return modname, env, mainfile, safe, ...
	end
	global.ModManager = modmanager
	return global
end

-- The VM's own private root: the same table the native string.dump policy reads. The VM no
-- longer exposes a Lua accessor; the test host publishes it as __ds_test_private_root in
-- script mode. A case must never leak a manager or policy into the next one, so every known
-- injected field is dropped here.
local ROOT_FIELDS = {
	"LJ_DS_PUC51_DUMP_POLICY", "GameLuaInjector", "GameInjector",
	"modules", "controller", "compat53",
}

local function vm_private_root()
	local root = rawget(_G, "__ds_test_private_root")
	if type(root) == "table" then
		return root
	end
	return {}
end

local function clear_policy()
	local root = vm_private_root()
	for _, key in ipairs(ROOT_FIELDS) do
		rawset(root, key, nil)
	end
end

local function new_sandbox(opts)
	opts = opts or {}
	if not opts.keep_blacklist then
		remove_blacklist()
	end
	clear_policy()
	local global = new_fake_global(opts)
	local chunk, load_err = loadfile(MODULE_PATH)
	assert_func(chunk, "load " .. MODULE_PATH .. ": " .. tostring(load_err))
	setfenv(chunk, global)
	-- The native entry returns the VM's real private root and the real registry. The root is the
	-- table the VM's dump policy reads (clear_policy above resets it per sandbox); the registry
	-- is a sandbox table so scrubbing _LOADED/_PRELOAD cannot poison the process's own module
	-- caches for later cases.
	local root = vm_private_root()
	local registry = {
		_LOADED = global.package.loaded,
		_PRELOAD = global.package.preload,
	}
	return {
		global = global,
		module = chunk(),
		io = global.io,
		root = root,
		registry = registry,
	}
end

local install_fake_native

local function install(sb, modname, modenv)
	if type(sb.global.GameInjector) ~= "table" then
		install_fake_native(sb)
	end
	return sb.module.install(sb.global, modname or TOOL, modenv, sb.root, sb.registry)
end

-- The native GameInjector.InitializeModEnvironment, as the production plugin exposes it:
-- binds both injector tables into the mod env and returns (private root, real registry).
function install_fake_native(sb)
	local native
	native = {
		InitializeModEnvironment = function(env)
			env.GameInjector = native
			env.GameLuaInjector = sb.global.GameLuaInjector
			return sb.root, sb.registry
		end,
		-- Test stand-in for the native lua_getfenv helper.
		GetFunctionEnvironment = function()
			return sb.global.package
		end,
	}
	sb.global.GameInjector = native
	sb.global.GameLuaInjector = { marker = true }
	return native
end

local function make_mod_env(sb, modname, opts)
	opts = opts or {}
	local env = {
		modname = modname,
		GLOBAL = sb.global,
		MODROOT = opts.modroot or ("../mods/" .. modname .. "/"),
		string = copy_table(sb.global.string),
		io = sb.io,
		modinfo = opts.modinfo,
	}
	env.env = env
	return setmetatable(env, { __index = sb.global })
end

local function run_in_env(chunk, env)
	setfenv(chunk, env)
	return xpcall(chunk, function(err)
		return tostring(err)
	end)
end

-- Calls string.dump from a function whose env is `env`, keeping that frame on the
-- stack: a tail call leaves only a "tail" pseudo frame (no func, no source), so
-- the record can only come from the caller's env or its source path.
local function dump_from_env(env, fn)
	local caller = function()
		local bytes = env.string.dump(fn or function() end)
		return bytes
	end
	setfenv(caller, env)
	return xpcall(caller, function(e)
		return tostring(e)
	end)
end

local function mod_path(modname, rel)
	return "../mods/" .. modname .. "/" .. rel
end

local function sorted_names(...)
	local names = { ... }
	table.sort(names)
	return names
end

local function assert_blacklist(expected_names, message)
	local where = message or "blacklist contents"
	local text = read_blacklist()
	if #expected_names == 0 then
		assert_eq(text, nil, where)
		return
	end
	assert_true(text ~= nil, where .. ": file missing")
	local decoded, err = json_decode(text)
	assert_true(decoded ~= nil, where .. ": not JSON (" .. tostring(err) .. "): " .. tostring(text))
	assert_eq(#decoded, #expected_names, where .. ": element count")
	for index = 1, #expected_names do
		assert_eq(decoded[index], expected_names[index], where .. ": element " .. index)
	end
end

---------------------------------------------------------------------------
-- 1. a mod dump returns PUC bytecode and is recorded, without stopping the chunk

local function case_dump_returns_puc_and_records()
	local sb = new_sandbox()
	install(sb, TOOL, make_mod_env(sb, TOOL))
	local env_a = make_mod_env(sb, MOD_A)
	local env_b = make_mod_env(sb, MOD_B)
	sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
	sb.global.ModManager:InitializeModMain(MOD_B, env_b, "main.lua")

	write_fixture(MOD_A, "modmain.lua", [[
local bytes = string.dump(function() end)
assert(type(bytes) == "string" and #bytes > 6, "dump must return bytes")
assert(bytes:sub(1, 6) == "\27Lua\81\0", "dump must return PUC 5.1 bytecode")
io.open("unsafedata/side_effect_a.txt", "w"):write("ran")
]])
	write_fixture(MOD_B, "modmain.lua", [[
io.open("unsafedata/marker_b.txt", "w"):write("ran")
]])

	local path_a = mod_path(MOD_A, "modmain.lua")
	local ok, err = run_in_env(assert_func(loadfile(path_a)), env_a)
	assert_eq(ok, true, "a dump must not abort the mod: " .. tostring(err))
	assert_true(data_file_exists("unsafedata/side_effect_a.txt"),
		"statements after the dump must still run")
	assert_blacklist(sorted_names(MOD_A), "only mod A is recorded, immediately and synchronously")

	local path_b = mod_path(MOD_B, "modmain.lua")
	local ok_b = run_in_env(assert_func(loadfile(path_b)), env_b)
	assert_eq(ok_b, true, "a mod that never calls string.dump still loads")
	assert_true(data_file_exists("unsafedata/marker_b.txt"), "mod B's chunk ran")
	assert_blacklist(sorted_names(MOD_A), "mod B must not be recorded")
end

---------------------------------------------------------------------------
-- 2. record process: the first hit persists to the real file

local function run_record()
	local sb = new_sandbox()
	install(sb, TOOL, make_mod_env(sb, TOOL))
	local env_a = make_mod_env(sb, MOD_A)
	sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
	write_fixture(MOD_A, "modmain.lua", "string.dump(function() end)\n")
	local path = mod_path(MOD_A, "modmain.lua")
	local ok, err = run_in_env(assert_func(loadfile(path)), env_a)
	assert_eq(ok, true, "the dump must succeed: " .. tostring(err))
	assert_blacklist(sorted_names(MOD_A), "record process must persist " .. MOD_A)
	print("ok record " .. MOD_A)
end

-- 3. reload process: a fresh VM state restores the list from the file and still
-- loads and runs every chunk of the recorded mod.

local function run_reload()
	assert_blacklist(sorted_names(MOD_A), "reload must start from the recorded file")
	local sb = new_sandbox({ keep_blacklist = true })
	install(sb, TOOL, make_mod_env(sb, TOOL))
	local env_a = make_mod_env(sb, MOD_A)
	sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")

	write_fixture(MOD_A, "modmain.lua", [[io.open("unsafedata/marker_a_modmain.txt", "w"):write("ran")]])
	write_fixture(MOD_A, "modworldgenmain.lua", [[io.open("unsafedata/marker_a_worldgen.txt", "w"):write("ran")]])
	write_fixture(MOD_A, "scripts/sub.lua", [[io.open("unsafedata/marker_a_sub.txt", "w"):write("ran")]])
	write_fixture(MOD_A, "modinfo.lua", [[name = "A"]])
	write_fixture(MOD_B, "modmain.lua", [[io.open("unsafedata/marker_b_reload.txt", "w"):write("ran")]])

	for _, rel in ipairs({ "modmain.lua", "modworldgenmain.lua", "scripts/sub.lua" }) do
		local path = mod_path(MOD_A, rel)
		local chunk = assert_func(loadfile(path), "load " .. rel)
		local ok, err = run_in_env(chunk, env_a)
		assert_eq(ok, true, "a recorded mod must still load " .. rel .. ": " .. tostring(err))
	end
	assert_true(data_file_exists("unsafedata/marker_a_modmain.txt"),
		"a recorded modmain still runs")
	assert_true(data_file_exists("unsafedata/marker_a_worldgen.txt"),
		"a recorded modworldgenmain still runs")
	assert_true(data_file_exists("unsafedata/marker_a_sub.txt"),
		"a recorded sub-script still runs")
	assert_blacklist(sorted_names(MOD_A), "loading a recorded mod must not change the record")

	-- The record is a compatibility log: a second dump keeps working and stays.
	local again = loadstring("return string.dump(function() end)", "@" .. mod_path(MOD_A, "modmain.lua"))
	setfenv(assert_func(again), env_a)
	local ok_dump, bytes = run_in_env(again, env_a)
	assert_eq(ok_dump, true, "a recorded mod's dump must still succeed")
	assert_puc(bytes, "reload process dump")
	assert_blacklist(sorted_names(MOD_A), "the record survives a repeat dump")

	-- modinfo stays loadable, other mods are untouched.
	local info_path = mod_path(MOD_A, "modinfo.lua")
	assert_eq(type(loadfile(info_path)), "function", "modinfo.lua must still load")
	local path_b = mod_path(MOD_B, "modmain.lua")
	local ok_b = run_in_env(assert_func(loadfile(path_b)), make_mod_env(sb, MOD_B))
	assert_eq(ok_b, true, "an unrecorded mod still loads in the reload process")
	assert_true(data_file_exists("unsafedata/marker_b_reload.txt"), "mod B ran")
	assert_blacklist(sorted_names(MOD_A), "mod B must not be recorded")
	print("ok reload " .. MOD_A)
end

---------------------------------------------------------------------------
-- 4. attribution

local function case_attribution()
	-- (a) tail call from mod code while the engine is loading that mod. The Lua
	-- caller frame is elided (a tail call leaves only a "tail" pseudo frame, which
	-- carries neither func nor source), so attribution has to come from the load
	-- window the engine opens for every mod (`currentlyloadingmod`). Per-env
	-- string.dump proxies are gone: the VM policy owns the record and the format.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_a = make_mod_env(sb, MOD_A)
		sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
		local chunk = assert_func(loadstring("return string.dump(function() end)",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		setfenv(chunk, env_a)
		local manager = sb.global.ModManager
		local previous_loading = manager.currentlyloadingmod
		manager.currentlyloadingmod = MOD_A
		local ok, bytes = xpcall(chunk, function(e)
			return tostring(e)
		end)
		manager.currentlyloadingmod = previous_loading
		assert_eq(ok, true, "env tail call must succeed: " .. tostring(bytes))
		assert_puc(bytes, "env tail call")
		assert_blacklist(sorted_names(MOD_A), "env tail call during load attributes to the mod")
	end

	-- (b) saved alias: local dump = string.dump, called normally from mod code.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_a = make_mod_env(sb, MOD_A)
		sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
		-- Keep the call non-tail: a `return dump(f)` would elide this frame, and the
		-- alias cases exist to prove attribution through the *saved reference*, not
		-- through the load window.
		local chunk = assert_func(loadstring(
			"local dump = string.dump\nlocal f = function() return 1 end\nlocal bytes = dump(f)\nreturn bytes",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		local ok, bytes = run_in_env(chunk, env_a)
		assert_eq(ok, true, "saved alias must succeed: " .. tostring(bytes))
		assert_puc(bytes, "saved alias")
		assert_blacklist(sorted_names(MOD_A), "saved alias attributes to the calling mod")
	end

	-- (c) explicit GLOBAL.string.dump from a mod frame.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_a = make_mod_env(sb, MOD_A)
		sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
		-- A normal call, not a tail call: the mod frame must stay visible, which is
		-- the priority the manager documents (visible frame before any fallback).
		local chunk = assert_func(loadstring(
			"local bytes = GLOBAL.string.dump(function() end)\nreturn bytes",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		local ok, bytes = run_in_env(chunk, env_a)
		assert_eq(ok, true, "GLOBAL dump must succeed: " .. tostring(bytes))
		assert_puc(bytes, "GLOBAL dump")
		assert_blacklist(sorted_names(MOD_A), "GLOBAL dump from a mod frame attributes to the mod")
	end

	-- (d) an engine Lua wrapper frame (env = GLOBAL) sits between mod and dump.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_a = make_mod_env(sb, MOD_A)
		sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
		local global_ref = sb.global
		local engine_dump = function(fn)
			local bytes = global_ref.string.dump(fn)
			return bytes
		end
		setfenv(engine_dump, sb.global)
		env_a.engine_dump = engine_dump
		-- Normal call: the mod frame must survive the unowned engine frame between
		-- it and the VM entry point.
		local chunk = assert_func(loadstring(
			"local bytes = engine_dump(function() end)\nreturn bytes",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		local ok, bytes = run_in_env(chunk, env_a)
		assert_eq(ok, true, "engine wrapper must succeed: " .. tostring(bytes))
		assert_puc(bytes, "engine wrapper")
		assert_blacklist(sorted_names(MOD_A), "an unowned engine frame must not stop the walk")
	end

	-- (e) loading-time tail call through GLOBAL (no mod frame on the stack).
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		sb.global.ModManager.currentlyloadingmod = MOD_B
		local chunk = assert_func(loadstring("return GLOBAL.string.dump(function() end)", "=engine_loader"))
		setfenv(chunk, sb.global)
		local ok, bytes = xpcall(chunk, function(e)
			return tostring(e)
		end)
		assert_eq(ok, true, "loading-time tail call must succeed: " .. tostring(bytes))
		assert_puc(bytes, "loading-time tail call")
		assert_blacklist(sorted_names(MOD_B), "a loading-time GLOBAL tail call uses currentlyloadingmod")
	end

	-- (f) mod B dumping mod A's function records B only; (g) an unowned engine
	-- dump returns native bytecode and records nobody.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_a = make_mod_env(sb, MOD_A)
		local env_b = make_mod_env(sb, MOD_B)
		sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
		sb.global.ModManager:InitializeModMain(MOD_B, env_b, "main.lua")
		local a_chunk = assert_func(loadstring("return function() return 'a' end",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		setfenv(a_chunk, env_a)
		local a_fn = a_chunk()
		env_b.a_fn = a_fn

		local b_chunk = assert_func(loadstring(
			"local bytes = string.dump(a_fn)\nreturn bytes",
			"@" .. mod_path(MOD_B, "modmain.lua")))
		local ok, bytes = run_in_env(b_chunk, env_b)
		assert_eq(ok, true, "cross-mod dump must succeed: " .. tostring(bytes))
		assert_puc(bytes, "cross-mod dump")
		assert_blacklist(sorted_names(MOD_B), "only the calling mod is recorded, never the dumped function's mod")

		local before = read_blacklist()
		sb.global.ModManager.currentlyloadingmod = nil
		local unowned = sb.global.string.dump(a_fn)
		-- The return format is not a policy decision: an unowned caller still gets
		-- PUC 5.1 bytes (stock behaviour); only the record is skipped.
		assert_puc(unowned, "unowned engine dump")
		assert_eq(read_blacklist(), before, "an unowned engine dump must not record anything")
	end

	-- (h) mod B calling mod A's saved env dump alias is attributed to B.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_a = make_mod_env(sb, MOD_A)
		local env_b = make_mod_env(sb, MOD_B)
		sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
		sb.global.ModManager:InitializeModMain(MOD_B, env_b, "main.lua")
		-- A saves its env front end for later use.
		local a_chunk = assert_func(loadstring("a_saved = string.dump return a_saved",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		setfenv(a_chunk, env_a)
		local saved = a_chunk()
		assert_eq(type(saved), "function", "mod A saved its env dump")
		env_b.a_saved = saved
		-- Normal call: B's own frame is what decides, not A's wrapper owner.
		local b_chunk = assert_func(loadstring(
			"local bytes = a_saved(function() return 1 end)\nreturn bytes",
			"@" .. mod_path(MOD_B, "modmain.lua")))
		local ok, bytes = run_in_env(b_chunk, env_b)
		assert_eq(ok, true, "cross-mod alias must succeed: " .. tostring(bytes))
		assert_puc(bytes, "cross-mod alias")
		assert_blacklist(sorted_names(MOD_B), "A's dump alias called from B records B, not A")
	end

	-- (i) an alias tail-called while the engine loads the mod keeps the same answer:
	-- the elided frame leaves only the load window to name the caller.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_c = make_mod_env(sb, MOD_C)
		sb.global.ModManager:InitializeModMain(MOD_C, env_c, "main.lua")
		local chunk = assert_func(loadstring("local d = string.dump return d(function() end)",
			"@" .. mod_path(MOD_C, "modmain.lua")))
		setfenv(chunk, env_c)
		local manager = sb.global.ModManager
		local previous_loading = manager.currentlyloadingmod
		manager.currentlyloadingmod = MOD_C
		local ok, bytes = xpcall(chunk, function(e)
			return tostring(e)
		end)
		manager.currentlyloadingmod = previous_loading
		assert_eq(ok, true, "env alias tail call must succeed: " .. tostring(bytes))
		assert_puc(bytes, "env alias tail call")
		assert_blacklist(sorted_names(MOD_C), "an env alias tail call during load keeps the mod's attribution")
	end
end

---------------------------------------------------------------------------
-- 5. no exemption: config / luajit_compatible / EnabledJIT are never consulted

local function case_no_exemption()
	local sb = new_sandbox()
	sb.global.GetModConfigData = function(key)
		error("the mod blacklist must not read mod config (" .. tostring(key) .. ")", 0)
	end
	install(sb, TOOL, make_mod_env(sb, TOOL))

	local compat_env = make_mod_env(sb, MOD_A, { modinfo = { luajit_compatible = true } })
	local table_compat_env = make_mod_env(sb, MOD_B, { modinfo = { luajit_compatible = {} } })
	sb.global.ModManager:InitializeModMain(MOD_A, compat_env, "main.lua")
	sb.global.ModManager:InitializeModMain(MOD_B, table_compat_env, "main.lua")
	assert_true(type(rawget(compat_env, "luajit")) == "table",
		"a declared-compatible mod receives the local capability container")
	assert_true(rawget(compat_env, "jit") == rawget(compat_env, "luajit").jit,
		"env.jit and env.luajit.jit point at the same copy")
	assert_true(type(rawget(table_compat_env, "luajit")) == "table",
		"a table declaration grants the same capability")

	-- Mod code runs in its own env and calls the dump without a tail call; the
	-- caller's env is what names the record (compatibility flags never exempt).
	local ok, bytes = dump_from_env(compat_env)
	assert_eq(ok, true, "compatible mod dump must succeed: " .. tostring(bytes))
	assert_puc(bytes, "luajit_compatible mod dump")

	ok, bytes = dump_from_env(table_compat_env)
	assert_eq(ok, true, "table-compatible mod dump must succeed: " .. tostring(bytes))
	assert_puc(bytes, "luajit_compatible table mod dump")
	assert_blacklist(sorted_names(MOD_A, MOD_B), "luajit_compatible (true or table) is not an exemption")
end

---------------------------------------------------------------------------
-- 6. names and paths

local function case_names_and_paths()
	-- local (non workshop-) Unicode folder name through a registered env.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_l = make_mod_env(sb, LOCAL_UNICODE)
		sb.global.ModManager:InitializeModMain(LOCAL_UNICODE, env_l, "main.lua")
		local ok, bytes = dump_from_env(env_l)
		assert_eq(ok, true, "unicode mod dump must succeed: " .. tostring(bytes))
		assert_puc(bytes, "unicode mod dump")
		assert_blacklist(sorted_names(LOCAL_UNICODE), "UTF-8 names are stored verbatim")
	end

	-- source attribution: backslashes, leading @, unregistered env.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local source = "@..\\mods\\" .. LOCAL_UNICODE .. "\\scripts\\sub.lua"
		-- Normal call: this case is about path attribution, so the frame must exist.
		local chunk = assert_func(loadstring(
			"local bytes = GLOBAL.string.dump(function() end)\nreturn bytes", source))
		setfenv(chunk, { GLOBAL = sb.global })
		local ok, bytes = xpcall(chunk, function(e)
			return tostring(e)
		end)
		assert_eq(ok, true, "backslash source dump must succeed: " .. tostring(bytes))
		assert_puc(bytes, "backslash source dump")
		assert_blacklist(sorted_names(LOCAL_UNICODE), "backslash paths and the leading @ are normalized")
	end

	-- registered MODROOT outside ../mods (custom UGC root).
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_ugc = make_mod_env(sb, UGC_MOD, { modroot = UGC_ROOT })
		sb.global.ModManager:InitializeModMain(UGC_MOD, env_ugc, "main.lua")
		local source = "@" .. UGC_ROOT .. "sub/init.lua"
		-- Normal call: this case is about path attribution, so the frame must exist.
		local chunk = assert_func(loadstring(
			"local bytes = GLOBAL.string.dump(function() end)\nreturn bytes", source))
		setfenv(chunk, { GLOBAL = sb.global })
		local ok, bytes = xpcall(chunk, function(e)
			return tostring(e)
		end)
		assert_eq(ok, true, "UGC root dump must succeed: " .. tostring(bytes))
		assert_puc(bytes, "UGC root dump")
		assert_blacklist(sorted_names(UGC_MOD), "a registered non-../mods MODROOT is honored")
	end

	-- similar prefix, different directory: no attribution, still PUC bytecode.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_ugc = make_mod_env(sb, UGC_MOD, { modroot = UGC_ROOT })
		sb.global.ModManager:InitializeModMain(UGC_MOD, env_ugc, "main.lua")
		local source = "@C:/ugc/" .. UGC_MOD .. "0/sub.lua"
		local chunk = assert_func(loadstring(
			"local bytes = GLOBAL.string.dump(function() end)\nreturn bytes", source))
		setfenv(chunk, { GLOBAL = sb.global })
		local ok, bytes = xpcall(chunk, function(e)
			return tostring(e)
		end)
		assert_eq(ok, true, "a similar-prefix path must not be attributed: " .. tostring(bytes))
		assert_puc(bytes, "similar-prefix dump")
		assert_eq(read_blacklist(), nil, "a similar-prefix path must not be recorded")
	end

	-- file parsing: missing file, empty file, duplicates, invalid entries.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		assert_eq(read_blacklist(), nil, "install must not create an empty file")
	end
	do
		local sb = new_sandbox()
		write_blacklist("")
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_b = make_mod_env(sb, MOD_B)
		sb.global.ModManager:InitializeModMain(MOD_B, env_b, "main.lua")
		local ok, bytes = dump_from_env(env_b)
		assert_eq(ok, true, "dump over an empty list must succeed: " .. tostring(bytes))
		assert_blacklist(sorted_names(MOD_B), "a whitespace-only file decodes as an empty list")
	end
	do
		local sb = new_sandbox()
		write_blacklist(" \r\n"
			.. json_encode({ "workshop-900000005", "bad/name", "workshop-900000006", "workshop-900000005" })
			.. "\r\n ")
		install(sb, TOOL, make_mod_env(sb, TOOL))
		assert_contains(table.concat(sb.global.__printed, "\n"),
			"[luajit] Invalid mod blacklist entry ignored", "invalid lines are reported")
		local env_5 = make_mod_env(sb, "workshop-900000005")
		sb.global.ModManager:InitializeModMain("workshop-900000005", env_5, "main.lua")
		local ok, bytes = dump_from_env(env_5)
		assert_eq(ok, true, "dump with existing records must succeed: " .. tostring(bytes))
		assert_blacklist(sorted_names("workshop-900000005", "workshop-900000006"),
			"duplicates collapse, invalid names drop, existing records stay")
	end
	do
		local sb = new_sandbox()
		write_blacklist('["workshop-900000001"')
		local ok, err = pcall(install, sb, TOOL, make_mod_env(sb, TOOL))
		assert_eq(ok, false, "a damaged file must be an initialization error, not an empty list")
		assert_contains(tostring(err), "[luajit] Cannot initialize mod blacklist: ")
		assert_contains(tostring(err), "luajit_mod_blacklist.json")
		assert_eq(sb.root.controller, nil, "no manager after a failed read")
		assert_eq(sb.root[POLICY_KEY], nil, "no policy after a failed read")
	end
	do
		-- Valid JSON, wrong shape: an object must be rejected instead of silently
		-- reading as "no records". The sandbox decoder is overridden here because a
		-- strict array-only decoder would reject the document before the module's own
		-- schema check runs.
		local sb = new_sandbox()
		write_blacklist('{"mods":["workshop-900000001"]}')
		sb.global.json = {
			encode = json_encode,
			decode = function()
				return { mods = { "workshop-900000001" } }
			end,
		}
		local ok, err = pcall(install, sb, TOOL, make_mod_env(sb, TOOL))
		assert_eq(ok, false, "a non-array JSON document must be an initialization error")
		assert_contains(tostring(err), "expected a JSON array")
		assert_eq(sb.root.controller, nil)
	end
	do
		-- Array with a non-string element: that element is reported and ignored while
		-- the rest of the list stays usable.
		local sb = new_sandbox()
		write_blacklist("[1]")
		sb.global.json = {
			encode = json_encode,
			decode = function()
				return { 1, "workshop-900000005" }
			end,
		}
		install(sb, TOOL, make_mod_env(sb, TOOL))
		assert_contains(table.concat(sb.global.__printed, "\n"),
			"[luajit] Invalid mod blacklist entry ignored", "non-string elements are reported")
		local env_5 = make_mod_env(sb, "workshop-900000005")
		sb.global.ModManager:InitializeModMain("workshop-900000005", env_5, "main.lua")
		local ok, bytes = dump_from_env(env_5)
		assert_eq(ok, true, "dump with a repaired list must succeed: " .. tostring(bytes))
		assert_blacklist(sorted_names("workshop-900000005"), "the valid entry is kept")
	end
	do
		-- Recorded in descending order; the file must still be ascending.
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		for _, name in ipairs({ "workshop-900000009", "workshop-900000004" }) do
			local env = make_mod_env(sb, name)
			sb.global.ModManager:InitializeModMain(name, env, "main.lua")
			local ok = dump_from_env(env)
			assert_eq(ok, true, "dump must succeed for " .. name)
		end
		assert_blacklist(sorted_names("workshop-900000004", "workshop-900000009"),
			"records are stored in ascending order")
	end
end

---------------------------------------------------------------------------
-- 6b. precompiled chunks: the VM owns the stock text and the stock chunk name

local function case_loadstring_message()
	local sb = new_sandbox()
	install(sb, TOOL, make_mod_env(sb, TOOL))
	local puc = "\27Lua\81\0\1\4\4\4\8\0"
	local lj = "\27LJ\2junk"
	local function message(bytes, name)
		local fn, err = loadstring(bytes, name)
		assert_eq(fn, nil, "a precompiled chunk must not load")
		return tostring(err)
	end
	-- PUC 5.1 luaU_undump names the chunk: '@'/'=' stripped, the chunk itself as
	-- the name (loadstring without a chunk name) becomes "binary string".
	assert_eq(message(puc, nil),
		"binary string: Disallowed functionality in precompiled chunk",
		"a nameless dump is reported as 'binary string'")
	assert_eq(message(puc, "=chunk"),
		"chunk: Disallowed functionality in precompiled chunk",
		"the '=' prefix is stripped")
	assert_eq(message(puc, "@../mods/x/modmain.lua"),
		"../mods/x/modmain.lua: Disallowed functionality in precompiled chunk",
		"the '@' prefix is stripped")
	assert_eq(message(puc, "plainname"),
		"plainname: Disallowed functionality in precompiled chunk",
		"a plain chunk name is kept")
	assert_eq(message(lj, "=chunk"),
		"chunk: Disallowed functionality in precompiled chunk",
		"LuaJIT bytecode gets the same text and name")
	assert_eq(message("\27LJ\2junk", nil),
		"binary string: Disallowed functionality in precompiled chunk",
		"a nameless LuaJIT dump is 'binary string' too")
	-- The manager must not patch loadstring: no policy registry entry for it (the VM
	-- answers, and the object keeps its identity).
	assert_eq(type(loadstring), "function", "loadstring stays a function")
	assert_eq(debug.getinfo(loadstring).what, "C", "loadstring stays a C function")
	for _, v in pairs(debug.getregistry()) do
		if type(v) == "table" and rawget(v, loadstring) ~= nil then
			error("loadstring carries a policy registry entry", 0)
		end
	end
end

---------------------------------------------------------------------------
-- 7. persistence failures are reported per dump

local function case_persistence_failure(label, io_opts, reason)
	local sb = new_sandbox({ io_opts = io_opts })
	install(sb, TOOL, make_mod_env(sb, TOOL))
	local env_a = make_mod_env(sb, MOD_A)
	sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
	write_fixture(MOD_A, "modmain.lua",
		"string.dump(function() end)\nio.open(\"unsafedata/side_effect_" .. label .. ".txt\", \"w\"):write(\"x\")\n")
	local path = mod_path(MOD_A, "modmain.lua")
	local ok, err = run_in_env(assert_func(loadfile(path)), env_a)
	assert_eq(ok, false, "a failing record must raise (" .. label .. ")")
	assert_contains(err, "[luajit] Mod '" .. MOD_A .. "': PUC 5.1 string.dump failed: ")
	assert_contains(err, "blacklist persistence failed: ")
	assert_contains(err, reason, "the underlying io failure must be reported (" .. label .. ")")
	assert_true(not data_file_exists("unsafedata/side_effect_" .. label .. ".txt"),
		"the chunk must not continue after a failed record")

	-- The in-memory hit survives, so a retry reports the same failure again.
	local again = loadstring("local bytes = string.dump(function() end)\nreturn bytes", "@" .. path)
	setfenv(assert_func(again), env_a)
	local ok_again, err_again = run_in_env(again, env_a)
	assert_eq(ok_again, false, "the retry must report the same failure")
	assert_contains(tostring(err_again), "blacklist persistence failed: ")
end

local function case_persistence_failures()
	case_persistence_failure("open", { fail_open = "w" }, "simulated open failure")
	case_persistence_failure("write", { fail_write = true }, "simulated write failure")
	case_persistence_failure("close", { fail_close = true }, "simulated close failure")

	-- A failing read is an initialization error with the path, never an empty list.
	local sb = new_sandbox({ io_opts = { fail_read = true } })
	write_blacklist("[]")
	local ok, err = pcall(install, sb, TOOL, make_mod_env(sb, TOOL))
	assert_eq(ok, false, "a failing read must be an initialization error")
	assert_contains(tostring(err), "[luajit] Cannot initialize mod blacklist: ")
	assert_contains(tostring(err), "simulated read failure")
	assert_contains(tostring(err), "luajit_mod_blacklist.json")
end

---------------------------------------------------------------------------
-- 8. install idempotency and registry policy ownership

local function case_install_and_policy()
	local sb = new_sandbox()
	local tool_env = make_mod_env(sb, TOOL)
	local manager = install(sb, TOOL, tool_env)
	local tool_string_first = rawget(tool_env, "string")
	local policy_first = sb.root[POLICY_KEY]
	assert_eq(type(policy_first), "function", "install publishes the VM policy")
	assert_eq(sb.root[POLICY_KEY], policy_first, "the policy is written once")

	local manager_again = install(sb, TOOL, tool_env)
	assert_eq(manager_again, manager, "repeat install returns the same manager")
	assert_eq(rawget(tool_env, "string"), tool_string_first, "repeat install must not re-copy env.string")
	assert_eq(sb.root[POLICY_KEY], policy_first, "repeat install must not replace the policy")

	-- main and worldgen entry points in the same VM share one manager.
	local worldgen_env = make_mod_env(sb, MOD_A)
	assert_eq(install(sb, MOD_A, worldgen_env), manager, "worldgen/main installs share the manager")
	assert_true(rawget(worldgen_env, "string") ~= nil, "the worldgen env string table is registered")
	assert_eq(sb.root[POLICY_KEY], policy_first, "a later install keeps the same policy")
	write_fixture(MOD_A, "modworldgenmain.lua", "string.dump(function() end)\n")
	local worldgen_path = mod_path(MOD_A, "modworldgenmain.lua")
	local ok_worldgen, err_worldgen = run_in_env(assert_func(loadfile(worldgen_path)),
		make_mod_env(sb, MOD_A))
	assert_eq(ok_worldgen, true, "worldgen dump must succeed: " .. tostring(err_worldgen))
	assert_blacklist(sorted_names(MOD_A), "the worldgen env's dump is recorded")

	-- A registry key owned by somebody else is an initialization error, never
	-- silently displaced.
	local other = new_sandbox()
	other.root[POLICY_KEY] = function()
		return nil
	end
	local ok_damaged, err_damaged = pcall(install, other, TOOL, make_mod_env(other, TOOL))
	assert_eq(ok_damaged, false, "another live policy must not be overwritten")
	assert_contains(tostring(err_damaged), "already in use")
	assert_eq(other.root.controller, nil, "no manager after a refused install")
	clear_policy()

	-- The manager never replaces GLOBAL.string.dump: an alias saved before the
	-- install still reaches the VM decision point.
	local before = new_sandbox()
	local native_dump = before.global.string.dump
	install(before, TOOL, make_mod_env(before, TOOL))
	assert_eq(before.global.string.dump, native_dump, "GLOBAL.string.dump keeps its identity")
end

---------------------------------------------------------------------------
-- 9. the real Mod/modworldgenmain.lua entry point

-- DST's CreateEnvironment whitelist: no metatable, no getfenv/pcall/rawget, and
-- the string table is the same object GLOBAL holds. modimport runs the chunk in
-- env.env (env here) and drops the chunk's return value, like scripts/mods.lua.
local function make_worldgen_env(global, modname, modroot)
	local worldgen_env = {
		pairs = pairs,
		ipairs = ipairs,
		print = print,
		math = math,
		table = table,
		type = type,
		string = global.string,
		tostring = tostring,
		require = require,
		Class = global.Class,
		TUNING = global.TUNING,
		GLOBAL = global,
		modname = modname,
		MODROOT = modroot,
	}
	worldgen_env.env = worldgen_env
	worldgen_env.modimport = function(modulename)
		if string.sub(modulename, #modulename - 3, #modulename) ~= ".lua" then
			modulename = modulename .. ".lua"
		end
		local path = modroot .. modulename
		local result = loadfile(path)
		if result == nil then
			error("Error in modimport: " .. modulename .. " not found!", 0)
		end
		setfenv(result, worldgen_env.env)
		result()
	end
	return worldgen_env
end

-- The worldgen entry point only probes require("jit"); on a host without LuaJIT
-- stand in for the module so the install path is still exercised.
local function ensure_jit_probe(sb)
	if pcall(require, "jit") then
		return
	end
	local real_require = require
	sb.global.require = function(name)
		if name == "jit" then
			return { version = "stub" }
		end
		return real_require(name)
	end
	print("note: host has no jit module; using a stub require for the worldgen case")
end

local function run_worldgen(global, modname, modroot)
	local worldgen_env = make_worldgen_env(global, modname, modroot)
	local chunk, err = loadfile(WORLDGEN_PATH)
	assert_func(chunk, "load " .. WORLDGEN_PATH .. ": " .. tostring(err))
	setfenv(chunk, worldgen_env)
	local ok, run_err = pcall(chunk)
	return ok, run_err, worldgen_env
end

local function run_worldgen(global, modname, modroot)
	local worldgen_env = make_worldgen_env(global, modname, modroot)
	local chunk, err = loadfile(WORLDGEN_PATH)
	assert_func(chunk, "load " .. WORLDGEN_PATH .. ": " .. tostring(err))
	setfenv(chunk, worldgen_env)
	local ok, run_err = pcall(chunk)
	return ok, run_err, worldgen_env
end

local function case_worldgen_entry()
	-- WORLDGEN_MAIN + the native entry: the hand-off installs the manager, publishes the
	-- private policy and clears the real injector globals.
	do
		local sb = new_sandbox()
		sb.global.WORLDGEN_MAIN = 1
		install_fake_native(sb)
		local ok, err, worldgen_env = run_worldgen(sb.global, MOD_A, ROOT .. "/Mod/")
		assert_eq(ok, true, "worldgen main must install the manager: " .. tostring(err))
		local manager = sb.root.controller
		assert_true(manager ~= nil, "the worldgen entry point publishes the manager in the root")
		assert_eq(type(sb.root[POLICY_KEY]), "function",
			"the worldgen entry point publishes the VM policy")
		assert_eq(sb.global.GameInjector, nil, "the real GLOBAL.GameInjector is cleared")
		assert_eq(sb.global.GameLuaInjector, nil, "the real GLOBAL.GameLuaInjector is cleared")
		assert_true(rawget(worldgen_env, "GameInjector") ~= nil,
			"the mod env keeps its bound injector table")
		local chunk = assert_func(loadstring(
			"local bytes = string.dump(function() end)\nreturn bytes",
			"@" .. mod_path(MOD_A, "modworldgenmain.lua")))
		local ok_dump, bytes = run_in_env(chunk, worldgen_env)
		assert_eq(ok_dump, true, "worldgen dump must succeed: " .. tostring(bytes))
		assert_puc(bytes, "worldgen dump")
		assert_blacklist(sorted_names(MOD_A), "the worldgen path persists the hit")
	end

	-- Not a worldgen load: nothing is installed, nothing is read or written.
	do
		local sb = new_sandbox()
		install_fake_native(sb)
		local ok, err = run_worldgen(sb.global, MOD_A, ROOT .. "/Mod/")
		assert_eq(ok, true, "a non-worldgen load must be a no-op: " .. tostring(err))
		assert_eq(sb.root.controller, nil, "no manager outside worldgen")
		assert_eq(sb.root[POLICY_KEY], nil, "no policy outside worldgen")
		assert_eq(read_blacklist(), nil, "no file access outside worldgen")
	end

	-- A classic VM (no jit/bit) still takes over both injector tables, without inventing
	-- LuaJIT capabilities or a dump policy.
	do
		local sb = new_sandbox()
		sb.global.WORLDGEN_MAIN = 1
		sb.global.jit = nil
		sb.global.bit = nil
		install_fake_native(sb)
		local ok, err, worldgen_env = run_worldgen(sb.global, MOD_A, ROOT .. "/Mod/")
		assert_eq(ok, true, "a non-LuaJIT worldgen load still localises the injectors: "
			.. tostring(err))
		assert_true(sb.root.controller ~= nil, "the manager is installed on the classic VM too")
		assert_eq(sb.root[POLICY_KEY], nil, "no dump policy without LuaJIT")
		assert_eq(rawget(worldgen_env, "luajit"), nil, "no luajit container without LuaJIT")
		assert_true(rawget(worldgen_env, "GameInjector") ~= nil,
			"the classic VM keeps the local injector table")
		assert_eq(sb.global.GameInjector, nil, "the classic VM clears the real global too")
		assert_eq(read_blacklist(), nil, "no file access without LuaJIT")
	end

	-- Missing game io is an initialization error, not a silent pass.
	do
		local sb = new_sandbox()
		sb.global.WORLDGEN_MAIN = 1
		sb.global.io = nil
		install_fake_native(sb)
		local ok, err = run_worldgen(sb.global, MOD_A, ROOT .. "/Mod/")
		assert_eq(ok, false, "missing io must fail the worldgen install")
		assert_contains(tostring(err), "[luajit] Cannot initialize mod blacklist: io.open")
	end
end

---------------------------------------------------------------------------
-- 10. bootstrap entry: the hand-off loads the manager explicitly (kleiloadlua + setfenv),
-- binds the mod env and clears the real injector globals.

local function case_bootstrap_entry()
	local sb = new_sandbox()
	install_fake_native(sb)
	local tool_env = make_mod_env(sb, TOOL, { modroot = ROOT .. "/Mod/" })
	local bootstrap = assert_func(loadfile(ROOT .. "/Mod/scripts/luajit_env_bootstrap.lua"))
	setfenv(bootstrap, tool_env)
	local runtime = bootstrap()
	assert_eq(type(runtime.manager), "table", "the bootstrap returns the manager")
	assert_eq(runtime.root, sb.root, "the bootstrap returns the state's private root")
	assert_eq(sb.root.controller, runtime.manager, "the root owns the manager")
	assert_eq(sb.global.GameInjector, nil, "the real GLOBAL.GameInjector is cleared")
	assert_eq(sb.global.GameLuaInjector, nil, "the real GLOBAL.GameLuaInjector is cleared")
	assert_true(rawget(tool_env, "GameInjector") ~= nil, "the mod env keeps its injector table")
	assert_true(type(rawget(tool_env, "luajit")) == "table", "the mod env gets the capability container")
	assert_eq(rawget(tool_env, "luajit").registry, sb.registry,
		"only this mod's env sees the real registry")

	-- An ordinary mod gets the stock surface: masked libraries and no capability.
	local env_probe = make_mod_env(sb, MOD_B)
	sb.global.ModManager:InitializeModMain(MOD_B, env_probe, "main.lua")
	assert_eq(rawget(env_probe, "luajit"), nil, "an undeclared mod gets no luajit container")
	local masked_debug = rawget(env_probe, "debug")
	assert_eq(type(masked_debug), "table", "a mod env receives a masked debug copy")
	assert_eq(rawget(masked_debug, "upvalueid"), nil, "debug.upvalueid is masked")
	local masked_table = rawget(env_probe, "table")
	assert_eq(type(masked_table), "table", "a mod env receives a masked table copy")
	assert_eq(rawget(masked_table, "new"), nil, "table.new is masked")
	local ok_require, err_require = pcall(rawget(env_probe, "require"), "jit")
	assert_eq(ok_require, false, "an undeclared mod cannot require jit")
	assert_contains(tostring(err_require), "module 'jit' not found", "the stock error text")

	-- The tool mod is not exempt: its own env records itself.
	local tool_chunk = assert_func(loadstring(
		"local bytes = string.dump(function() end)\nreturn bytes",
		"@" .. mod_path(TOOL, "modmain.lua")))
	local ok_tool, bytes = run_in_env(tool_chunk, tool_env)
	assert_eq(ok_tool, true, "tool mod dump must succeed: " .. tostring(bytes))
	assert_puc(bytes, "tool mod dump")
	assert_blacklist(sorted_names(TOOL), "the installing mod is recorded like any other")

	-- Another mod's dump must not be blamed on the tool mod whose env the manager
	-- itself runs in (the manager's own frames carry that env).
	local env_a = make_mod_env(sb, MOD_A)
	sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
	local a_chunk = assert_func(loadstring(
		"local bytes = string.dump(function() end)\nreturn bytes",
		"@" .. mod_path(MOD_A, "modmain.lua")))
	local ok_a, bytes_a = run_in_env(a_chunk, env_a)
	assert_eq(ok_a, true, "mod A dump must succeed: " .. tostring(bytes_a))
	assert_puc(bytes_a, "mod A dump")
	assert_blacklist(sorted_names(TOOL, MOD_A), "only the calling mod is recorded")
end

---------------------------------------------------------------------------
-- 11. access matrix: declarations, per-env isolation, live GLOBAL forwarding

local function case_access_matrix()
	local sb = new_sandbox()
	install_fake_native(sb)
	local tool_env = make_mod_env(sb, TOOL, { modroot = ROOT .. "/Mod/" })
	local bootstrap = assert_func(loadfile(ROOT .. "/Mod/scripts/luajit_env_bootstrap.lua"))
	setfenv(bootstrap, tool_env)
	bootstrap()

	local plain_env = make_mod_env(sb, MOD_C)  -- no modinfo at all
	local false_env = make_mod_env(sb, "workshop-900000010", { modinfo = { luajit_compatible = false } })
	local true_env = make_mod_env(sb, MOD_A, { modinfo = { luajit_compatible = true } })
	local table_env = make_mod_env(sb, MOD_B, { modinfo = { luajit_compatible = { api = 1 } } })
	sb.global.ModManager:InitializeModMain(MOD_C, plain_env, "main.lua")
	sb.global.ModManager:InitializeModMain("workshop-900000010", false_env, "main.lua")
	sb.global.ModManager:InitializeModMain(MOD_A, true_env, "main.lua")
	sb.global.ModManager:InitializeModMain(MOD_B, table_env, "main.lua")

	-- Undeclared / false: no capability, no loader back to the private modules.
	for _, env in ipairs({ plain_env, false_env }) do
		assert_eq(rawget(env, "luajit"), nil, "no luajit container without a declaration")
		local ok = pcall(function()
			return env.GLOBAL.jit
		end)
		assert_eq(ok, true, "GLOBAL is always readable")
		assert_eq(env.GLOBAL.jit, nil, "the real GLOBAL no longer carries jit")
		for _, name in ipairs({ "jit", "bit", "ffi", "memprof", "jit.bc", "table.new", "string.buffer" }) do
			local ok_req, err_req = pcall(env.require, name)
			assert_eq(ok_req, false, "an undeclared mod cannot require " .. name)
			assert_contains(tostring(err_req), "module '" .. name .. "' not found",
				"stock not-found text for " .. name)
		end
	end

	-- Declared: same function family through every entry point, distinct containers per env.
	for _, env in ipairs({ true_env, table_env }) do
		local luajit = rawget(env, "luajit")
		assert_eq(type(luajit), "table", "declared mod gets luajit")
		assert_true(env.jit == env.GLOBAL.jit, "env.jit and GLOBAL.jit are one object")
		assert_true(env.jit == luajit.jit, "env.jit and luajit.jit are one object")
		assert_true(env.debug == luajit.debug, "env.debug and luajit.debug are one object")
		assert_true(env.table == luajit.table, "env.table and luajit.table are one object")
		assert_true(env.string == luajit.string, "env.string and luajit.string are one object")
		assert_true(env.GLOBAL.debug.upvalueid == luajit.debug.upvalueid,
			"GLOBAL.debug.upvalueid is the same function")
		assert_eq(type(luajit.registry), "nil", "an external mod never gets the real registry")
		assert_eq(type(env.require("jit")), "table", "require('jit') works")
		assert_true(env.require("jit") == luajit.jit, "require('jit') == luajit.jit")
		assert_true(env.require("bit") == env.GLOBAL.bit, "bit is shared through the env")
		assert_eq(type(env.require("table.new")), "function", "require('table.new') is the function")
		assert_true(env.require("table.new") == env.table.new, "the family field is the same function")
		assert_eq(type(env.require("table.clear")), "function", "require('table.clear') is the function")
		assert_eq(type(env.require("string.buffer")), "table", "require('string.buffer') is its module")
		assert_true(env.require("string.buffer") == env.string.buffer,
			"the family field is the same module")
		-- actual calls: the functions are the real ones, not stubs
		assert_eq(env.table.new(2, 2).x, nil, "table.new returns a table")
		assert_eq(type(env.string.buffer.new), "function", "string.buffer is usable")
		if env.require("ffi") ~= nil then
			assert_eq(type(env.require("ffi").cdef), "function", "ffi is usable")
		end
		-- jit.bc pulls jit.util + jit.vmdef through the private loader. The shipped vmdef.lua
		-- guards its own LuaJIT build id, so a locally built VM may stop there; reaching that
		-- guard still proves the private loader ran file → loader → env, never shared state.
		if sb.root.controller.modules["jit.util"] ~= nil then
			assert_true(env.require("jit.util") == luajit.jit.util,
				"jit.util is the env's copy")
			local ok_bc, bc = pcall(env.require, "jit.bc")
			assert_true(ok_bc or tostring(bc):find("version mismatch", 1, true) ~= nil,
				"jit.bc resolves through the private loader: " .. tostring(bc))
		end
	end

	assert_true(rawget(true_env, "jit") ~= rawget(table_env, "jit"),
		"each compatible env has its own jit copy")
	assert_true(rawget(true_env, "luajit").jit ~= rawget(table_env, "luajit").jit,
		"containers are per env")
	assert_eq(type(true_env.jit.off), "function", "the copy keeps the shared functions")

	-- Two package surfaces: GLOBAL and ordinary envs get the safe base; declared mods get the
	-- real package with the extension-loaded overlay. The safe side never sees those keys.
	local real_package = sb.root.controller.real_package
	assert_true(type(real_package) == "table", "the manager keeps the real package")
	assert_true(rawget(true_env, "package") == real_package,
		"declared env.package is the real package")
	assert_true(rawget(true_env.GLOBAL, "package") == real_package,
		"declared GLOBAL.package is the real package")
	assert_true(sb.global.package ~= real_package, "GLOBAL.package is the safe base")
	assert_eq(rawget(sb.global.package.loaded, "jit"), nil, "safe loaded has no jit")
	assert_eq(rawget(sb.global.package.loaded, "bit"), nil, "safe loaded has no bit")
	assert_eq(rawget(real_package.loaded, "jit"), sb.root.controller.modules.jit,
		"real loaded carries the captured jit table")
	assert_eq(rawget(real_package.loaded, "ffi"), sb.root.controller.modules.ffi,
		"real loaded carries the captured ffi table")
	assert_eq(type(rawget(sb.global, "bit")), "table",
		"the engine's global bit library remains available")
	local ok_ld, err_ld = sb.global.package.loadlib("", "luaopen_ffi")
	assert_eq(ok_ld, nil, "safe loadlib refuses extension openers")
	assert_contains(tostring(err_ld), "disabled", "safe loadlib explains the refusal")
	assert_eq(rawget(sb.global.package.loaded, "ffi"), nil,
		"refused loadlib does not populate the safe loaded table")

	-- Local edits stay local; real library tables are untouched.
	true_env.GLOBAL.debug.private_probe = true
	assert_eq(rawget(rawget(table_env, "debug"), "private_probe"), nil,
		"one env's debug copy does not leak into another")
	assert_eq(rawget(sb.global.debug, "private_probe"), nil,
		"the real debug table is not modified")
	true_env.jit.private_probe = true
	assert_eq(rawget(rawget(table_env, "jit"), "private_probe"), nil,
		"one env's jit copy does not leak into another")

	-- Ordinary GLOBAL fields forward live, both read and write.
	sb.global.TheWorld = nil
	assert_eq(true_env.GLOBAL.TheWorld, nil, "absent game fields are nil")
	local world = { marker = "world" }
	sb.global.TheWorld = world
	assert_true(true_env.GLOBAL.TheWorld == world, "a later real GLOBAL field is visible immediately")
	true_env.GLOBAL.shared_probe = "shared"
	assert_eq(sb.global.shared_probe, "shared", "an ordinary GLOBAL write reaches the real GLOBAL")
	assert_eq(true_env.GLOBAL.shared_probe, "shared", "and reads back")
	-- A false value must not fall through to another field.
	sb.global.flag_probe = false
	assert_eq(true_env.GLOBAL.flag_probe, false, "false is forwarded, not treated as missing")
	-- rawget sees only the local raw fields (`jit` is explicit; a forwarded game field is not).
	assert_true(rawget(true_env.GLOBAL, "jit") == true_env.jit, "rawget sees the explicit field")
	assert_eq(rawget(true_env.GLOBAL, "TheWorld"), nil, "rawget does not fake the whole GLOBAL")
	-- The shared _LOADED/_PRELOAD never contains the extensions again.
	assert_eq(sb.global.package.loaded.jit, nil, "shared package.loaded has no jit")
	assert_eq(sb.global.package.preload.ffi, nil, "shared package.preload has no ffi")
	assert_eq(sb.global.package.loaded["jit.bc"], nil, "the private loader does not fill shared loaded")
	assert_eq(sb.global.package.preload["jit.bc"], nil, "nor shared preload")

	-- The real GLOBAL.require refuses every extension name for every caller.
	for _, name in ipairs({ "jit", "bit", "ffi", "string.buffer" }) do
		local ok, err = pcall(sb.global.require, name)
		assert_eq(ok, false, "GLOBAL.require refuses " .. name)
		assert_contains(tostring(err), "module '" .. name .. "' not found", "canonical refusal text")
	end
end

-- 11. the authorised plugin view: the same grant the installer gets, plus the injector
-- tables, with `_G` pointing at the view so normal names resolve and engine globals still
-- fall through to the real (scrubbed) GLOBAL.
local function case_plugin_view()
	local sb = new_sandbox()
	-- The host publishes the native table before the manager installs (one table per state).
	local native = { marker = 7 }
	rawset(sb.root, "GameInjector", native)
	rawset(sb.root, "GameLuaInjector", { framework = true })
	local manager = install(sb, TOOL, make_mod_env(sb, TOOL))
	local view = manager:grant_plugin_view()

	assert_eq(type(view), "table", "grant_plugin_view returns a table")
	assert_true(view == manager:grant_plugin_view(), "the view is built once per state")
	assert_true(view._G == view, "_G is the view itself")
	assert_true(view.GameInjector == native, "the view carries the native table")
	assert_true(view.GameLuaInjector == sb.root.GameLuaInjector, "the view carries the framework")
	assert_eq(type(view.jit), "table", "the view has the granted jit")
	assert_true(view.jit.off ~= nil, "the granted jit is the real table")
	assert_true(view.jit == rawget(view, "jit"), "the granted jit is a raw field of the view")
	assert_true(view.luajit ~= nil and view.luajit.jit == view.jit, "luajit container matches")
	assert_true(view.GLOBAL.jit == view.jit, "GLOBAL proxy exposes the same jit object")
	assert_eq(view.require("jit"), view.jit, "require('jit') resolves to the granted copy")
	-- Engine globals still resolve through the view; the real GLOBAL stays scrubbed.
	assert_eq(sb.global.jit, nil, "the engine GLOBAL has no jit")
	assert_true(view.ModManager == sb.global.ModManager, "engine globals fall through the view")
end

---------------------------------------------------------------------------
-- driver

local function run_cases()
	local cases = {
		{ "dump_returns_puc_and_records", case_dump_returns_puc_and_records },
		{ "attribution", case_attribution },
		{ "no_exemption", case_no_exemption },
		{ "names_and_paths", case_names_and_paths },
		{ "loadstring_message", case_loadstring_message },
		{ "persistence_failures", case_persistence_failures },
		{ "install_and_policy", case_install_and_policy },
		{ "worldgen_entry", case_worldgen_entry },
		{ "bootstrap_entry", case_bootstrap_entry },
		{ "access_matrix", case_access_matrix },
		{ "plugin_view", case_plugin_view },
	}
	for _, case in ipairs(cases) do
		clear_policy()
		local ok, err = xpcall(case[2], function(e)
			return tostring(e) .. "\n" .. debug.traceback()
		end)
		if not ok then
			error(string.format("case %s failed: %s", case[1], tostring(err)), 0)
		end
		print("ok case " .. case[1])
	end
	clear_policy()
end

if mode == "cases" then
	run_cases()
	print("ok mod_blacklist cases")
elseif mode == "record" then
	run_record()
	clear_policy()
elseif mode == "reload" then
	run_reload()
	clear_policy()
else
	error("unknown mode " .. tostring(mode), 0)
end
