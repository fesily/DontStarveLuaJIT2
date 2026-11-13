-- tests/plugin/mod_blacklist_spec.lua
-- Consumer-level tests for Mod/scripts/luajit_mod_blacklist.lua:
--   * a mod calling string.dump is reported + recorded synchronously,
--   * a recorded mod is refused before its chunks run (fresh process),
--   * attribution follows the caller (env front end, GLOBAL front end, engine
--     wrapper frames, loading-time tail calls, loaded mod name/path),
--   * persistence failures still refuse and keep the in-process hit,
--   * idempotent install / loader re-wrapping order, and the real
--     Mod/modworldgenmain.lua entry point.
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
local TOOL = "luajit_blacklist_tool"
local LOCAL_UNICODE = "blacklist local_日本語"
local UGC_MOD = "workshop-900000003"
local UGC_ROOT = "C:/ugc/" .. UGC_MOD .. "/"

local INCOMPATIBLE = "is incompatible with LuaJIT (此模组不兼容): string.dump is not supported for mods."

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

local function expect_refusal(ok, err, modname, extra)
	if ok ~= false then
		error(string.format("string.dump for %s must raise (xpcall returned %s)",
			modname, tostring(ok)), 2)
	end
	assert_contains(err, "[luajit] Mod '" .. modname .. "' " .. INCOMPATIBLE)
	if extra then
		assert_contains(err, extra, "error text")
	end
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
-- non-JSON file (e.g. the old line format) fails instead of passing silently.

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

-- "../mods/<name>/x.lua" (the engine's mod path shape) -> <root>/mods/<name>/x.lua
local function fixture_path(filename)
	local norm = tostring(filename):gsub("\\", "/")
	if norm:sub(1, 1) == "/" or norm:match("^%a:[/\\]") then
		return norm
	end
	if norm:sub(1, 3) == "../" then
		norm = norm:sub(4)
	end
	if norm:sub(1, 5) == "mods/" then
		norm = norm:sub(6)
	end
	return MODS .. "/" .. norm
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

local function new_engine()
	local engine = { calls = {} }
	function engine.load(filename, ...)
		engine.calls[filename] = (engine.calls[filename] or 0) + 1
		local chunk, err = loadfile(fixture_path(filename))
		if chunk == nil then
			return err
		end
		return chunk
	end
	return engine
end

local function new_fake_global(opts, loader)
	opts = opts or {}
	local printed = {}
	-- A real GLOBAL mirrors the process globals; only the pieces the blacklist
	-- touches are replaced with sandboxed versions.
	local global = {}
	for key, value in pairs(_G) do
		global[key] = value
	end
	global.io = opts.io or make_game_io(opts.io_opts)
	global.string = copy_table(string)
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
	-- Private package table: the worldgen hide path drops package.loaded.jit, which
	-- must not poison this process's require("jit") for later cases.
	global.package = { loaded = {}, preload = package.preload }
	global.json = { encode = json_encode, decode = json_decode }
	global.kleiloadlua = loader
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

local function new_sandbox(opts)
	opts = opts or {}
	if not opts.keep_blacklist then
		remove_blacklist()
	end
	local engine = new_engine()
	local global = new_fake_global(opts, engine.load)
	local chunk, load_err = loadfile(MODULE_PATH)
	assert_func(chunk, "load " .. MODULE_PATH .. ": " .. tostring(load_err))
	setfenv(chunk, global)
	return {
		global = global,
		engine = engine,
		module = chunk(),
		io = global.io,
	}
end

local function install(sb, modname, modenv)
	return sb.module.install(sb.global, modname or TOOL, modenv)
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
-- 1. dump is refused at once and recorded (same process)

local function case_dump_rejects_and_persists()
	local sb = new_sandbox()
	-- The manager captures global.string.dump at install time; count invocations so
	-- "the original dump never runs" is actually observable.
	local original_dump_calls = 0
	local real_dump = sb.global.string.dump
	sb.global.string.dump = function(...)
		original_dump_calls = original_dump_calls + 1
		return real_dump(...)
	end
	install(sb, TOOL, make_mod_env(sb, TOOL))
	local env_a = make_mod_env(sb, MOD_A)
	local env_b = make_mod_env(sb, MOD_B)
	sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
	sb.global.ModManager:InitializeModMain(MOD_B, env_b, "main.lua")

	write_fixture(MOD_A, "modmain.lua", [[
string.dump(function() end)
io.open("unsafedata/side_effect_a.txt", "w"):write("ran")
]])
	write_fixture(MOD_B, "modmain.lua", [[
io.open("unsafedata/marker_b.txt", "w"):write("ran")
]])

	local path_a = mod_path(MOD_A, "modmain.lua")
	local ok, err = run_in_env(assert_func(sb.global.kleiloadlua(path_a)), env_a)
	expect_refusal(ok, err, MOD_A)
	assert_eq(sb.engine.calls[path_a], 1, "mod A's own chunk must be loaded (the error happens inside it)")
	assert_true(not data_file_exists("unsafedata/side_effect_a.txt"),
		"statements after the dump call must not run")
	assert_eq(original_dump_calls, 0, "the original string.dump must never run for a mod")
	assert_contains(table.concat(sb.global.__printed, "\n"), "[luajit] Mod '" .. MOD_A .. "' " .. INCOMPATIBLE,
		"the mod must be reported")
	assert_blacklist(sorted_names(MOD_A), "only mod A is recorded, immediately and synchronously")

	local path_b = mod_path(MOD_B, "modmain.lua")
	local ok_b = run_in_env(assert_func(sb.global.kleiloadlua(path_b)), env_b)
	assert_eq(ok_b, true, "a mod that never calls string.dump still loads")
	assert_true(data_file_exists("unsafedata/marker_b.txt"), "mod B's chunk ran")
	assert_blacklist(sorted_names(MOD_A), "mod B must not be recorded")
end

---------------------------------------------------------------------------
-- 2. record process: first hit persists to the real file

local function run_record()
	local sb = new_sandbox()
	install(sb, TOOL, make_mod_env(sb, TOOL))
	local env_a = make_mod_env(sb, MOD_A)
	sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
	write_fixture(MOD_A, "modmain.lua", "string.dump(function() end)\n")
	local path = mod_path(MOD_A, "modmain.lua")
	local ok, err = run_in_env(assert_func(sb.global.kleiloadlua(path)), env_a)
	expect_refusal(ok, err, MOD_A)
	assert_blacklist(sorted_names(MOD_A), "record process must persist " .. MOD_A)
	print("ok record " .. MOD_A)
end

-- 3. reload process: a fresh Lua state restores the list from the file and
-- refuses the mod before any of its chunks run.

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

	-- Entry files carry the incompatibility error, which disables the mod.
	for _, rel in ipairs({ "modmain.lua", "modworldgenmain.lua" }) do
		local path = mod_path(MOD_A, rel)
		local chunk = assert_func(sb.global.kleiloadlua(path), "refusal chunk for " .. rel)
		local ok, err = run_in_env(chunk, env_a)
		expect_refusal(ok, err, MOD_A)
		assert_eq(sb.engine.calls[path], nil, "the underlying loader must not run for " .. rel)
	end
	-- Other scripts of a recorded mod are replaced by an empty chunk: their code
	-- never runs, but a late engine require must not abort on our error either.
	do
		local path = mod_path(MOD_A, "scripts/sub.lua")
		local chunk = assert_func(sb.global.kleiloadlua(path), "blocked chunk for the sub-file")
		local ok = run_in_env(chunk, env_a)
		assert_eq(ok, true, "a non-entry script is blocked silently, not refused")
		assert_eq(sb.engine.calls[path], nil, "the underlying loader must not run for the sub-file")
	end
	assert_true(not data_file_exists("unsafedata/marker_a_modmain.txt"), "refused modmain must not run")
	assert_true(not data_file_exists("unsafedata/marker_a_worldgen.txt"), "refused modworldgenmain must not run")
	assert_true(not data_file_exists("unsafedata/marker_a_sub.txt"), "blocked sub-file must not run")

	-- The refusal chunk closes over its report/error functions: a bare env (no
	-- print/error/string) must still report and raise.
	do
		local bare_chunk = assert_func(sb.global.kleiloadlua(mod_path(MOD_A, "modmain.lua")))
		local ok_bare, err_bare = run_in_env(bare_chunk, {})
		expect_refusal(ok_bare, err_bare, MOD_A)
	end

	-- modinfo stays loadable so the game can still list/manage the mod.
	local info_path = mod_path(MOD_A, "modinfo.lua")
	assert_eq(type(sb.global.kleiloadlua(info_path)), "function", "modinfo.lua must still load")
	assert_eq(sb.engine.calls[info_path], 1, "modinfo.lua goes through the original loader")
	assert_blacklist(sorted_names(MOD_A), "loading modinfo must not clear the list")

	-- Other mods are untouched.
	local path_b = mod_path(MOD_B, "modmain.lua")
	local ok_b = run_in_env(assert_func(sb.global.kleiloadlua(path_b)), make_mod_env(sb, MOD_B))
	assert_eq(ok_b, true, "an unrecorded mod still loads in the reload process")
	assert_true(data_file_exists("unsafedata/marker_b_reload.txt"), "mod B ran")
	assert_blacklist(sorted_names(MOD_A), "mod B must not be recorded")
	print("ok reload " .. MOD_A)
end

---------------------------------------------------------------------------
-- 4. attribution

local function case_attribution()
	-- (a) tail call through the mod env front end (the Lua caller frame is elided).
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_a = make_mod_env(sb, MOD_A)
		sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
		local chunk = assert_func(loadstring("return string.dump(function() end)",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		setfenv(chunk, env_a)
		local ok, err = xpcall(chunk, function(e)
			return tostring(e)
		end)
		expect_refusal(ok, err, MOD_A)
		assert_blacklist(sorted_names(MOD_A), "env tail call attributes to the env's mod")
	end

	-- (b) saved alias: local dump = string.dump, called normally from mod code.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_a = make_mod_env(sb, MOD_A)
		sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
		local chunk = assert_func(loadstring(
			"local dump = string.dump\nlocal f = function() return 1 end\ndump(f)",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		local ok, err = run_in_env(chunk, env_a)
		expect_refusal(ok, err, MOD_A)
		assert_blacklist(sorted_names(MOD_A), "saved alias attributes to the calling mod")
	end

	-- (c) explicit GLOBAL.string.dump from a mod frame.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_a = make_mod_env(sb, MOD_A)
		sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
		local chunk = assert_func(loadstring("GLOBAL.string.dump(function() end)",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		local ok, err = run_in_env(chunk, env_a)
		expect_refusal(ok, err, MOD_A)
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
		local chunk = assert_func(loadstring("engine_dump(function() end)",
			"@" .. mod_path(MOD_A, "modmain.lua")))
		local ok, err = run_in_env(chunk, env_a)
		expect_refusal(ok, err, MOD_A)
		assert_blacklist(sorted_names(MOD_A), "an unowned engine frame must not stop the walk")
	end

	-- (e) loading-time tail call through GLOBAL (no mod frame on the stack).
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		sb.global.ModManager.currentlyloadingmod = MOD_B
		local chunk = assert_func(loadstring("return GLOBAL.string.dump(function() end)", "=engine_loader"))
		setfenv(chunk, sb.global)
		local ok, err = xpcall(chunk, function(e)
			return tostring(e)
		end)
		expect_refusal(ok, err, MOD_B)
		assert_blacklist(sorted_names(MOD_B), "a loading-time GLOBAL tail call uses currentlyloadingmod")
	end

	-- (f) mod B dumping mod A's function records B only; (g) the engine dumping it
	-- returns the original bytecode and records nobody.
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

		local b_chunk = assert_func(loadstring("string.dump(a_fn)", "@" .. mod_path(MOD_B, "modmain.lua")))
		local ok, err = run_in_env(b_chunk, env_b)
		expect_refusal(ok, err, MOD_B)
		assert_blacklist(sorted_names(MOD_B), "only the calling mod is recorded, never the dumped function's mod")

		local before = read_blacklist()
		local bytes = sb.global.string.dump(a_fn)
		assert_eq(type(bytes), "string", "an unowned engine dump must still return the bytecode")
		assert_eq(bytes, string.dump(a_fn), "an unowned engine dump must return the original bytes")
		assert_eq(read_blacklist(), before, "an unowned engine dump must not record anything")
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

	local jit_sentinel = { sentinel = true }
	local compat_env = make_mod_env(sb, MOD_A, { modinfo = { luajit_compatible = true } })
	compat_env.jit = jit_sentinel
	local table_compat_env = make_mod_env(sb, MOD_B, { modinfo = { luajit_compatible = {} } })
	sb.global.ModManager:InitializeModMain(MOD_A, compat_env, "main.lua")
	sb.global.ModManager:InitializeModMain(MOD_B, table_compat_env, "main.lua")
	assert_eq(rawget(compat_env, "jit"), jit_sentinel, "a compatible mod keeps the env.jit it was given")
	assert_eq(rawget(table_compat_env, "jit"), nil, "a plain mod env must not gain a raw jit")

	local ok, err = xpcall(function()
		compat_env.string.dump(function() end)
	end, function(e)
		return tostring(e)
	end)
	expect_refusal(ok, err, MOD_A)

	ok, err = xpcall(function()
		table_compat_env.string.dump(function() end)
	end, function(e)
		return tostring(e)
	end)
	expect_refusal(ok, err, MOD_B)
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
		local ok, err = xpcall(function()
			env_l.string.dump(function() end)
		end, function(e)
			return tostring(e)
		end)
		expect_refusal(ok, err, LOCAL_UNICODE)
		assert_blacklist(sorted_names(LOCAL_UNICODE), "UTF-8 names are stored verbatim")
	end

	-- source attribution: backslashes, leading @, unregistered env.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local source = "@..\\mods\\" .. LOCAL_UNICODE .. "\\scripts\\sub.lua"
		local chunk = assert_func(loadstring("GLOBAL.string.dump(function() end)", source))
		setfenv(chunk, { GLOBAL = sb.global })
		local ok, err = xpcall(chunk, function(e)
			return tostring(e)
		end)
		expect_refusal(ok, err, LOCAL_UNICODE)
		assert_blacklist(sorted_names(LOCAL_UNICODE), "backslash paths and the leading @ are normalized")
	end

	-- registered MODROOT outside ../mods (custom UGC root).
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_ugc = make_mod_env(sb, UGC_MOD, { modroot = UGC_ROOT })
		sb.global.ModManager:InitializeModMain(UGC_MOD, env_ugc, "main.lua")
		local source = "@" .. UGC_ROOT .. "sub/init.lua"
		local chunk = assert_func(loadstring("GLOBAL.string.dump(function() end)", source))
		setfenv(chunk, { GLOBAL = sb.global })
		local ok, err = xpcall(chunk, function(e)
			return tostring(e)
		end)
		expect_refusal(ok, err, UGC_MOD)
		assert_blacklist(sorted_names(UGC_MOD), "a registered non-../mods MODROOT is honored")
	end

	-- similar prefix, different directory: no match.
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
		assert_eq(type(bytes), "string", "the original dump must run")
		assert_eq(read_blacklist(), nil, "a similar-prefix path must not be recorded")
	end

	-- file parsing: missing file, CRLF, duplicates, blank and invalid lines.
	do
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		assert_eq(read_blacklist(), nil, "install must not create an empty file")
	end
	do
		local sb = new_sandbox()
		write_blacklist("")
		install(sb, TOOL, make_mod_env(sb, TOOL))
		local env_empty = make_mod_env(sb, MOD_B)
		sb.global.ModManager:InitializeModMain(MOD_B, env_empty, "main.lua")
		local ok, err = xpcall(function()
			env_empty.string.dump(function() end)
		end, function(e)
			return tostring(e)
		end)
		expect_refusal(ok, err, MOD_B)
		assert_blacklist(sorted_names(MOD_B), "a whitespace-only file decodes as an empty list")
	end
	do
		local sb = new_sandbox()
		write_blacklist(" \r\n"
			.. json_encode({ "workshop-900000004", "bad/name", "workshop-900000005", "workshop-900000004" })
			.. "\r\n ")
		install(sb, TOOL, make_mod_env(sb, TOOL))
		assert_contains(table.concat(sb.global.__printed, "\n"),
			"[luajit] Invalid mod blacklist entry ignored", "invalid lines are reported")
		local env_4 = make_mod_env(sb, "workshop-900000004")
		sb.global.ModManager:InitializeModMain("workshop-900000004", env_4, "main.lua")
		local ok, err = xpcall(function()
			env_4.string.dump(function() end)
		end, function(e)
			return tostring(e)
		end)
		expect_refusal(ok, err, "workshop-900000004")
		assert_blacklist(sorted_names("workshop-900000004", "workshop-900000005"),
			"duplicates collapse, invalid names drop, existing records stay")
	end
	do
		local sb = new_sandbox()
		local loader_before = sb.global.kleiloadlua
		write_blacklist('["workshop-900000001"')
		local ok, err = pcall(install, sb, TOOL, make_mod_env(sb, TOOL))
		assert_eq(ok, false, "a damaged file must be an initialization error, not an empty list")
		assert_contains(tostring(err), "[luajit] Cannot initialize mod blacklist: ")
		assert_contains(tostring(err), "luajit_mod_blacklist.json")
		assert_eq(sb.global.kleiloadlua, loader_before, "no hook is installed after a failed read")
		assert_eq(sb.global.ModManager._ds_luajit_mod_blacklist_installed, nil, "no manager after a failed read")
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
		assert_eq(sb.global.ModManager._ds_luajit_mod_blacklist_installed, nil)
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
		local ok, err = xpcall(function()
			env_5.string.dump(function() end)
		end, function(e)
			return tostring(e)
		end)
		expect_refusal(ok, err, "workshop-900000005")
	end
	do
		-- Recorded in descending order; the file must still be ascending.
		local sb = new_sandbox()
		install(sb, TOOL, make_mod_env(sb, TOOL))
		for _, name in ipairs({ "workshop-900000009", "workshop-900000004" }) do
			local env = make_mod_env(sb, name)
			sb.global.ModManager:InitializeModMain(name, env, "main.lua")
			local ok = xpcall(function()
				env.string.dump(function() end)
			end, function(e)
				return tostring(e)
			end)
			assert_eq(ok, false, "dump must be refused for " .. name)
		end
		assert_blacklist(sorted_names("workshop-900000004", "workshop-900000009"),
			"records are stored in ascending order")
	end
end

---------------------------------------------------------------------------
-- 7. persistence failures still refuse

local function case_persistence_failure(label, io_opts, reason)
	local sb = new_sandbox({ io_opts = io_opts })
	install(sb, TOOL, make_mod_env(sb, TOOL))
	local env_a = make_mod_env(sb, MOD_A)
	sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
	write_fixture(MOD_A, "modmain.lua",
		"string.dump(function() end)\nio.open(\"unsafedata/side_effect_" .. label .. ".txt\", \"w\"):write(\"x\")\n")
	local path = mod_path(MOD_A, "modmain.lua")
	local ok, err = run_in_env(assert_func(sb.global.kleiloadlua(path)), env_a)
	expect_refusal(ok, err, MOD_A, "blacklist persistence failed: ")
	assert_contains(err, reason, "the underlying io failure must be reported (" .. label .. ")")
	assert_true(not data_file_exists("unsafedata/side_effect_" .. label .. ".txt"),
		"the original dump and the rest of the chunk must not run")

	-- The in-process hit survives the failed write.
	local again = assert_func(sb.global.kleiloadlua(path), "in-memory hit must refuse the reload")
	local ok_again, err_again = run_in_env(again, env_a)
	expect_refusal(ok_again, err_again, MOD_A)
	assert_eq(sb.engine.calls[path], 1, "the refused reload must not reach the loader")
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
-- 8. install idempotency and loader re-wrap order

local function case_install_and_loader_order()
	local sb = new_sandbox()
	local tool_env = make_mod_env(sb, TOOL)
	local manager = install(sb, TOOL, tool_env)
	local loader_first = sb.global.kleiloadlua
	local tool_string_first = rawget(tool_env, "string")
	local manager_again = install(sb, TOOL, tool_env)
	assert_eq(manager_again, manager, "repeat install returns the same manager")
	assert_eq(sb.global.kleiloadlua, loader_first, "repeat install must not stack loader wrappers")
	assert_eq(rawget(tool_env, "string"), tool_string_first, "repeat install must not re-copy env.string")

	-- main and worldgen entry points in the same VM share one manager.
	local worldgen_env = make_mod_env(sb, MOD_A)
	assert_eq(install(sb, MOD_A, worldgen_env), manager, "worldgen/main installs share the manager")
	assert_true(rawget(worldgen_env, "string") ~= nil, "the worldgen env string table is registered")
	write_fixture(MOD_A, "modworldgenmain.lua", "string.dump(function() end)\n")
	local worldgen_path = mod_path(MOD_A, "modworldgenmain.lua")
	local ok_worldgen, err_worldgen = run_in_env(assert_func(sb.global.kleiloadlua(worldgen_path)), worldgen_env)
	expect_refusal(ok_worldgen, err_worldgen, MOD_A)

	-- jit.runtime installs its frostxx/encrypted loader afterwards; the blacklist
	-- must end up on top again and refuse without calling the decrypt loader.
	local inner = sb.global.kleiloadlua
	local crypto_calls = 0
	local crypto = function(filename, ...)
		crypto_calls = crypto_calls + 1
		if crypto_calls > 5 then
			error("loader delegation loop: the re-wrap re-pointed an installed wrapper", 0)
		end
		return inner(filename, ...)
	end
	sb.global.kleiloadlua = crypto
	manager:wrap_loader()
	assert_true(sb.global.kleiloadlua ~= crypto, "wrap_loader must re-wrap an externally replaced loader")
	local refused = assert_func(sb.global.kleiloadlua(mod_path(MOD_A, "modmain.lua")))
	assert_eq(crypto_calls, 0, "the blacklist must refuse before the crypto/decrypt loader")
	assert_eq(type(refused), "function", "a refusal chunk comes back")
	local ok_refused, err_refused = run_in_env(refused, make_mod_env(sb, MOD_A))
	expect_refusal(ok_refused, err_refused, MOD_A)

	-- A re-wrap must not re-point the older wrapper's downstream: the chain is
	-- W2 -> crypto -> W1 -> engine, and it has to terminate (a shared mutable
	-- "inner" would recurse W1 -> crypto... forever).
	local rewrap_path = "../mods/unknown_after_rewrap/main.lua"
	local delegated = sb.global.kleiloadlua(rewrap_path)
	assert_eq(crypto_calls, 1, "a delegated load goes through the outer hook exactly once")
	assert_true(delegated ~= nil and type(delegated) ~= "function",
		"the engine loader's result comes back (the chain terminated)")

	-- A second external hook plus another wrap still terminates.
	local inner2 = sb.global.kleiloadlua
	local second_calls = 0
	sb.global.kleiloadlua = function(filename, ...)
		second_calls = second_calls + 1
		if second_calls > 5 then
			error("loader delegation loop after the second wrap", 0)
		end
		return inner2(filename, ...)
	end
	manager:wrap_loader()
	assert_true(type(sb.global.kleiloadlua(rewrap_path)) ~= "function", "two re-wraps still terminate")
	assert_eq(second_calls, 1, "the second hook ran exactly once")

	-- Unmatched loads pass every argument and every result through unchanged.
	local seen
	sb.global.kleiloadlua = function(...)
		seen = { n = select("#", ...), ... }
		return 1, 2, 3
	end
	manager:wrap_loader()
	local first, second, third = sb.global.kleiloadlua("../mods/unknown/main.lua", "arg1", "arg2")
	assert_eq(first, 1, "first return")
	assert_eq(second, 2, "second return")
	assert_eq(third, 3, "third return")
	assert_eq(seen.n, 3, "arguments are forwarded")
	assert_eq(seen[2], "arg1", "first argument forwarded")
	assert_eq(seen[3], "arg2", "second argument forwarded")

	sb.global.kleiloadlua = function()
		return "syntax error"
	end
	manager:wrap_loader()
	assert_eq(sb.global.kleiloadlua("../mods/unknown/main.lua"), "syntax error", "string loader errors pass through")
	sb.global.kleiloadlua = function()
		return nil
	end
	manager:wrap_loader()
	assert_eq(sb.global.kleiloadlua("../mods/unknown/main.lua"), nil, "nil loader results pass through")
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
-- (e.g. the PUC 5.1 runner) stand in for the module so the install path is still
-- exercised, while a LuaJIT host exercises the real probe.
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

local function case_worldgen_entry()
	-- WORLDGEN_MAIN + real LuaJIT + HideGlobalJIT=false does not disable the blacklist.
	do
		local sb = new_sandbox()
		sb.global.WORLDGEN_MAIN = 1
		-- The kill switch: the entry points install the blacklist only when this is true.
		sb.global._ds_luajit_mod_blacklist_enabled = true
		sb.global.GetModConfigData = function()
			return false
		end
		ensure_jit_probe(sb)
		local ok, err, worldgen_env = run_worldgen(sb.global, MOD_A, ROOT .. "/Mod/")
		assert_eq(ok, true, "worldgen main must install the blacklist: " .. tostring(err))
		local manager = sb.global.ModManager._ds_luajit_mod_blacklist_installed
		assert_true(manager ~= nil, "the worldgen entry point publishes the manager")
		local chunk = assert_func(loadstring("string.dump(function() end)",
			"@" .. mod_path(MOD_A, "modworldgenmain.lua")))
		local ok_dump, dump_err = run_in_env(chunk, worldgen_env)
		expect_refusal(ok_dump, dump_err, MOD_A)
		assert_blacklist(sorted_names(MOD_A), "the worldgen path persists the hit")
	end

	-- TEMPORARY kill switch: without GLOBAL._ds_luajit_mod_blacklist_enabled the
	-- worldgen entry point installs nothing, so no mod is refused.
	do
		local sb = new_sandbox()
		sb.global.WORLDGEN_MAIN = 1
		sb.global.GetModConfigData = function()
			return false
		end
		ensure_jit_probe(sb)
		local loader_before = sb.global.kleiloadlua
		local ok, err = run_worldgen(sb.global, MOD_A, ROOT .. "/Mod/")
		assert_eq(ok, true, "the disabled worldgen entry must not error: " .. tostring(err))
		assert_eq(sb.global.ModManager._ds_luajit_mod_blacklist_installed, nil,
			"the kill switch leaves the blacklist uninstalled")
		assert_eq(sb.global.kleiloadlua, loader_before, "kleiloadlua must stay untouched")
		assert_eq(read_blacklist(), nil, "no blacklist file access while disabled")
	end

	-- Not a worldgen load: nothing is installed, nothing is read or written.
	do
		local sb = new_sandbox()
		local loader_before = sb.global.kleiloadlua
		local ok, err = run_worldgen(sb.global, MOD_A, ROOT .. "/Mod/")
		assert_eq(ok, true, "a non-worldgen load must be a no-op: " .. tostring(err))
		assert_eq(sb.global.ModManager._ds_luajit_mod_blacklist_installed, nil, "no manager outside worldgen")
		assert_eq(sb.global.kleiloadlua, loader_before, "kleiloadlua must stay untouched")
		assert_eq(read_blacklist(), nil, "no file access outside worldgen")
	end

	-- Not LuaJIT: nothing is installed.
	do
		local sb = new_sandbox()
		sb.global.WORLDGEN_MAIN = 1
		sb.global.require = function(name)
			error("module '" .. tostring(name) .. "' not found", 0)
		end
		local ok, err = run_worldgen(sb.global, MOD_A, ROOT .. "/Mod/")
		assert_eq(ok, true, "a non-LuaJIT worldgen load must be a no-op: " .. tostring(err))
		assert_eq(sb.global.ModManager._ds_luajit_mod_blacklist_installed, nil, "no manager without LuaJIT")
		assert_eq(read_blacklist(), nil, "no file access without LuaJIT")
	end

	-- Missing game io is an initialization error, not a silent pass.
	do
		local sb = new_sandbox()
		sb.global.WORLDGEN_MAIN = 1
		sb.global._ds_luajit_mod_blacklist_enabled = true
		sb.global.io = nil
		ensure_jit_probe(sb)
		local ok, err = run_worldgen(sb.global, MOD_A, ROOT .. "/Mod/")
		assert_eq(ok, false, "missing io must fail the worldgen install")
		assert_contains(tostring(err), "[luajit] Cannot initialize mod blacklist: io.open")
	end
end

---------------------------------------------------------------------------
-- 10. modmain entry: modimport runs the script in the mod env proxy, the module
-- installs itself, and its own frames are never attributed to the tool mod.

local function case_modimport_entry()
	local sb = new_sandbox()
	local tool_env = {
		modname = TOOL,
		GLOBAL = sb.global,
		MODROOT = "../mods/" .. TOOL .. "/",
		string = sb.global.string,
	}
	tool_env.env = tool_env
	-- Mirror Mod/modmain.lua: main() runs with a proxy env over the mod env, which
	-- is what the local modimport wrapper hands to the chunk (env.env = main_fenv).
	local proxy = setmetatable({}, {
		__index = function(_, key)
			return tool_env[key] or sb.global[key]
		end,
		__newindex = tool_env,
	})
	local chunk = assert_func(loadfile(MODULE_PATH))
	setfenv(chunk, proxy)
	local module = chunk()
	assert_eq(type(module), "table", "the script still returns its table")
	assert_eq(type(sb.global.ModManager._ds_luajit_mod_blacklist_installed), "table",
		"modimport must self-install")
	assert_eq(type(rawget(proxy, "string")), "table", "the proxy env receives its string copy")

	-- The tool mod is not exempt: its own env string front end blames itself.
	local tool_chunk = assert_func(loadstring("string.dump(function() end)",
		"@" .. mod_path(TOOL, "modmain.lua")))
	setfenv(tool_chunk, proxy)
	local ok_tool, err_tool = xpcall(tool_chunk, function(e)
		return tostring(e)
	end)
	expect_refusal(ok_tool, err_tool, TOOL)
	assert_blacklist(sorted_names(TOOL), "the installing mod is recorded like any other")

	-- Another mod's dump must not be blamed on the tool mod whose env the manager
	-- itself runs in (the manager's own frames carry that proxy env).
	local env_a = make_mod_env(sb, MOD_A)
	sb.global.ModManager:InitializeModMain(MOD_A, env_a, "main.lua")
	local a_chunk = assert_func(loadstring("string.dump(function() end)",
		"@" .. mod_path(MOD_A, "modmain.lua")))
	local ok_a, err_a = run_in_env(a_chunk, env_a)
	expect_refusal(ok_a, err_a, MOD_A)
	assert_blacklist(sorted_names(TOOL, MOD_A), "only the calling mod is recorded")
end

---------------------------------------------------------------------------
-- driver

local function run_cases()
	local cases = {
		{ "dump_rejects_and_persists", case_dump_rejects_and_persists },
		{ "attribution", case_attribution },
		{ "no_exemption", case_no_exemption },
		{ "names_and_paths", case_names_and_paths },
		{ "persistence_failures", case_persistence_failures },
		{ "install_and_loader_order", case_install_and_loader_order },
		{ "worldgen_entry", case_worldgen_entry },
		{ "modimport_entry", case_modimport_entry },
	}
	for _, case in ipairs(cases) do
		local ok, err = pcall(case[2])
		if not ok then
			error(string.format("case %s failed: %s", case[1], tostring(err)), 0)
		end
		print("ok case " .. case[1])
	end
end

if mode == "cases" then
	run_cases()
	print("ok mod_blacklist cases")
elseif mode == "record" then
	run_record()
elseif mode == "reload" then
	run_reload()
else
	error("unknown mode " .. tostring(mode), 0)
end
