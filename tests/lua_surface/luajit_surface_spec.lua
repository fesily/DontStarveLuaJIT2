-- Bare-VM spec for Mod/scripts/luajit_surface.lua.
--
-- Pins the granted env's GLOBAL proxy against DST's scripts/strict.lua: a main chunk may
-- declare a new global through the proxy, a function may not, and a declaration made through
-- the proxy must stay visible to strict's later reads. The proxy's __newindex is a Lua
-- function, so the write reaches the real table from this module's frame -- exactly the frame
-- strict would blame; the proxy therefore repeats strict's caller rule itself and keeps
-- __declared in step.
--
-- Runner: tests/plugin/run_lua_host.py <this file> (bare LuaJIT or PUC 5.1).

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
    return dir:match("^(.*)/tests/lua_surface$") or (dir .. "/../..")
end

local ROOT = repo_root()

local function load_surface_module()
    local chunk, err = loadfile(ROOT .. "/Mod/scripts/luajit_surface.lua")
    assert(chunk, err)
    -- The module reads `type` from its chunk environment (the mod env inside the game).
    setfenv(chunk, { type = type })
    return chunk()
end

local surface_lib = load_surface_module()

-- The api table scripts/luajit_env_runtime.lua:build_api hands the surface.
local api = {
    type = type,
    tostring = tostring,
    pairs = pairs,
    pcall = pcall,
    error = error,
    print = print,
    format = string.format,
    sort = table.sort,
    concat = table.concat,
    encode = function() end,
    decode = function() end,
    getinfo = debug.getinfo,
    getfenv = getfenv,
    setfenv = setfenv,
    getmetatable = getmetatable,
    setmetatable = setmetatable,
    rawget = rawget,
    rawset = rawset,
    open = io.open,
}

-- scripts/strict.lua reduced to a target table: __declared bookkeeping, the main/C-only
-- declaration rule, and the same two error messages. The names in `declared_names` stand for
-- the engine globals scripts/strict.lua itself declared (libs/require/... resolved at boot).
local function install_strict(global, declared_names, strict_enabled)
    rawset(global, "__STRICT", strict_enabled ~= false)
    local mt = { __declared = {} }
    for _, name in ipairs(declared_names or {}) do
        mt.__declared[name] = true
    end
    mt.__newindex = function(t, n, v)
        if rawget(t, "__STRICT") and not mt.__declared[n] then
            local info = debug.getinfo(2, "S")
            local what = info and info.what or "C"
            if what ~= "main" and what ~= "C" then
                error("assign to undeclared variable '" .. tostring(n) .. "'", 2)
            end
            mt.__declared[n] = true
        end
        rawset(t, n, v)
    end
    mt.__index = function(t, n)
        if not mt.__declared[n] then
            local info = debug.getinfo(2, "S")
            if not info or info.what ~= "C" then
                error("variable '" .. tostring(n) .. "' is not declared", 2)
            end
        end
        return rawget(t, n)
    end
    setmetatable(global, mt)
    return mt
end

-- Engine-shaped real GLOBAL: the fields scripts/luajit_surface.lua itself reads, plus the
-- `jit` table a LuaJIT state carries. `opts.jit = false` models a stock PUC state;
-- `opts.declare_jit = false` models a raw `jit` that strict never recorded.
local ENGINE_FIELDS = {"require", "kleiloadlua", "package", "bit", "debug", "table", "string",
    "rawget", "rawset", "GameInjector"}

local function make_global(opts)
    opts = opts or {}
    local global = {
        bit = { band = function() end },
        debug = debug,
        table = table,
        string = string,
        package = { loaded = {}, preload = {}, loaders = {} },
        rawget = rawget,
        rawset = rawset,
        require = function(name)
            return nil, "module '" .. name .. "' not found"
        end,
        kleiloadlua = function()
            return nil
        end,
    }
    local declared = {}
    for _, name in ipairs(ENGINE_FIELDS) do
        declared[#declared + 1] = name
    end
    if opts.jit ~= false then
        global.jit = { version = "LuaJIT spec" }
        if opts.declare_jit ~= false then
            declared[#declared + 1] = "jit"
        end
    end
    if opts.strict == false then
        return global, nil
    end
    return global, install_strict(global, declared)
end

local function new_surface(global, modname)
    local surface = surface_lib.new(api, {
        global = global,
        modname = modname or "spec_installer",
        modenv = {},
        private_root = {},
        real_registry = {},
    })
    surface:capture()
    surface:prepare_shared()
    return surface
end

local function grant_env(surface, modname)
    local env = { modinfo = { luajit_compatible = true } }
    assert(surface:register_env(modname, env), "register_env refused the declaring mod")
    return env
end

local function run(env, source)
    local chunk, err = loadstring(source, "=surface-spec")
    assert(chunk, err)
    setfenv(chunk, env)
    return pcall(chunk)
end

local function assert_eq(actual, expected, message)
    if actual ~= expected then
        error(string.format("%s: expected %s, got %s", message, tostring(expected),
            tostring(actual)), 2)
    end
end

local function assert_contains(text, needle, message)
    if type(text) ~= "string" or not text:find(needle, 1, true) then
        error(string.format("%s: %q does not contain %q", message, tostring(text), needle), 2)
    end
end

-- A main chunk declares a new global through GLOBAL; the write reaches the real table and
-- strict records it, so a later function read passes __index.
local function test_main_chunk_declares_through_proxy()
    local global, mt = make_global()
    local env = grant_env(new_surface(global), "spec_grant")
    local ok, err = run(env, "GLOBAL.spec_declared = 41")
    assert_eq(ok, true, "main chunk declaration through GLOBAL failed: " .. tostring(err))
    assert_eq(rawget(global, "spec_declared"), 41, "declaration did not reach the real GLOBAL")
    assert_eq(mt.__declared.spec_declared, true, "declaration was not recorded for strict")
    local read_ok, value = run(env,
        "local function f() return GLOBAL.spec_declared end return f()")
    assert_eq(read_ok, true, "read after declaration failed: " .. tostring(value))
    assert_eq(value, 41, "read after declaration returned the wrong value")
end

-- Same assignment from a function is a strict violation, and nothing is written or declared.
local function test_function_cannot_declare_through_proxy()
    local global, mt = make_global()
    local env = grant_env(new_surface(global), "spec_func")
    local ok, err = run(env, "local function f() GLOBAL.spec_undeclared = 1 end f()")
    assert_eq(ok, false, "a function declared a new global through GLOBAL")
    assert_contains(err, "assign to undeclared variable 'spec_undeclared'",
        "wrong refusal message")
    assert_eq(rawget(global, "spec_undeclared"), nil, "refused write reached the real GLOBAL")
    assert_eq(mt.__declared.spec_undeclared, nil, "refused write was recorded as declared")
end

-- Once declared, functions may write the global again (strict only gates declarations).
local function test_declared_global_accepts_function_writes()
    local global = make_global()
    local env = grant_env(new_surface(global), "spec_redeclare")
    assert_eq((run(env, "GLOBAL.spec_shared = 1")), true, "declaration failed")
    local ok, err = run(env, "local function f() GLOBAL.spec_shared = 2 end f()")
    assert_eq(ok, true, "a declared global refused a function write: " .. tostring(err))
    assert_eq(rawget(global, "spec_shared"), 2, "function write did not reach the real GLOBAL")
end

-- strict keys the rule off __declared, not off raw presence: an undeclared raw field is still
-- a declaration only a main chunk may make.
local function test_raw_field_without_declaration_is_still_undeclared()
    local global, mt = make_global()
    rawset(global, "spec_engine_owned", 7)
    local env = grant_env(new_surface(global), "spec_raw")
    local ok, err = run(env, "local function f() GLOBAL.spec_engine_owned = 8 end f()")
    assert_eq(ok, false, "a function overwrote an undeclared raw global")
    assert_contains(err, "assign to undeclared variable 'spec_engine_owned'",
        "wrong refusal message")
    assert_eq(rawget(global, "spec_engine_owned"), 7, "refused write changed the raw field")
    ok, err = run(env, "GLOBAL.spec_engine_owned = 9")
    assert_eq(ok, true, "main chunk declaration of a raw field failed: " .. tostring(err))
    assert_eq(rawget(global, "spec_engine_owned"), 9, "declaration did not reach the real GLOBAL")
    assert_eq(mt.__declared.spec_engine_owned, true, "declaration was not recorded for strict")
end

-- A state without strict's metatable: the proxy stays transparent, from any frame.
local function test_state_without_strict_accepts_function_writes()
    local global = make_global({ strict = false })
    local env = grant_env(new_surface(global), "spec_plain")
    local ok, err = run(env, "local function f() GLOBAL.spec_plain = 5 end f()")
    assert_eq(ok, true, "a stock state refused a function write: " .. tostring(err))
    assert_eq(rawget(global, "spec_plain"), 5, "write did not reach the real GLOBAL")
end

-- The plugin view forwards plain-name writes with `__newindex = real GLOBAL` (table form), so
-- the caller frame survives untouched: a function still fails, a main chunk still declares.
local function test_plugin_view_keeps_caller_attribution()
    local global = make_global()
    local surface = new_surface(global)
    local view = surface:grant_plugin_view()
    assert_eq(type(view), "table", "no plugin view")
    local ok, err = run(view, "local function f() spec_view_key = 1 end f()")
    assert_eq(ok, false, "a function declared a global through the plugin view")
    assert_contains(err, "assign to undeclared variable 'spec_view_key'",
        "wrong refusal message")
    ok, err = run(view, "spec_view_key = 2")
    assert_eq(ok, true, "main chunk declaration through the plugin view failed: "
        .. tostring(err))
    assert_eq(rawget(global, "spec_view_key"), 2, "view write did not reach the real GLOBAL")
    -- The view's own GLOBAL proxy must penetrate raw reads too.
    rawset(global, "spec_view_engine", 11)
    local read_ok, value = run(view, [[
        local function f() return rawget(GLOBAL, "spec_view_engine") end
        return f()
    ]])
    assert_eq(read_ok, true, "view rawget(GLOBAL, ...) failed: " .. tostring(value))
    assert_eq(value, 11, "view rawget(GLOBAL, ...) did not reach the real GLOBAL")
end

-- rawget has no metamethods: without the env wrapper it reads only the proxy's raw table, so
-- an engine field comes back nil. Keys the proxy owns raw (the granted copies) stay local.
local function test_rawget_penetrates_to_real_global()
    local global = make_global()
    rawset(global, "spec_engine_only", "engine")
    local env = grant_env(new_surface(global), "spec_rawget")
    local ok, value = run(env, [[
        local function f() return rawget(GLOBAL, "spec_engine_only") end
        return f()
    ]])
    assert_eq(ok, true, "rawget(GLOBAL, engine field) failed: " .. tostring(value))
    assert_eq(value, "engine", "rawget(GLOBAL, ...) did not reach the real GLOBAL")
    local copy_ok, same = run(env, [[
        local function f() return rawget(GLOBAL, "jit") == jit end
        return f()
    ]])
    assert_eq(copy_ok, true, "rawget(GLOBAL, 'jit') failed: " .. tostring(same))
    assert_eq(same, true, "rawget(GLOBAL, 'jit') did not return the granted copy")
end

-- rawset must reach the real GLOBAL (raw access is not gated by strict), while keys the proxy
-- owns raw stay local -- the engine package table must keep its identity.
local function test_rawset_penetrates_to_real_global()
    local global = make_global()
    local env = grant_env(new_surface(global), "spec_rawset")
    local proxy = rawget(env, "GLOBAL")
    local ok, identity, via_field = run(env, [[
        local function f()
            local same = rawset(GLOBAL, "spec_raw_written", 7) == GLOBAL
            local field = GLOBAL.rawset(GLOBAL, "spec_raw_via_field", 8) == GLOBAL
            return same, field
        end
        return f()
    ]])
    assert_eq(ok, true, "rawset(GLOBAL, ...) in a function failed: " .. tostring(identity))
    assert_eq(identity, true, "rawset(GLOBAL, ...) did not return the proxy it was given")
    assert_eq(via_field, true, "GLOBAL.rawset(...) did not return the proxy")
    assert_eq(rawget(global, "spec_raw_written"), 7, "rawset did not reach the real GLOBAL")
    assert_eq(rawget(global, "spec_raw_via_field"), 8,
        "GLOBAL.rawset did not reach the real GLOBAL")
    assert_eq(rawget(proxy, "spec_raw_written"), nil, "rawset stayed on the proxy")
    local real_package = rawget(global, "package")
    ok, err = run(env, [[rawset(GLOBAL, "package", "spec_marker")]])
    assert_eq(ok, true, "rawset on a local key failed: " .. tostring(err))
    assert_eq(rawget(proxy, "package"), "spec_marker", "local rawset did not reach the proxy")
    assert_eq(rawget(global, "package"), real_package,
        "rawset replaced the engine package table")
end

-- GLOBAL.rawget / GLOBAL.rawset resolve to this env's wrappers through __index, but the proxy
-- stores no such field: its raw contents stay the view's own extensions, so a raw read of
-- GLOBAL still shows the engine functions.
local function test_global_raw_functions_resolve_to_wrappers()
    local global = make_global()
    local env = grant_env(new_surface(global), "spec_raw_field")
    local proxy = rawget(env, "GLOBAL")
    rawset(global, "spec_engine_only", "engine")
    assert_eq(rawget(proxy, "rawget"), nil,
        "the wrapper polluted the proxy's raw contents (rawget)")
    assert_eq(rawget(proxy, "rawset"), nil,
        "the wrapper polluted the proxy's raw contents (rawset)")
    local ok, value, same_get, same_set, raw_get, raw_set = run(env, [[
        local function f()
            return GLOBAL.rawget(GLOBAL, "spec_engine_only"), GLOBAL.rawget == rawget,
                GLOBAL.rawset == rawset, rawget(GLOBAL, "rawget"), rawget(GLOBAL, "rawset")
        end
        return f()
    ]])
    assert_eq(ok, true, "GLOBAL.rawget(GLOBAL, ...) failed: " .. tostring(value))
    assert_eq(value, "engine", "GLOBAL.rawget(GLOBAL, ...) did not penetrate")
    assert_eq(same_get, true, "GLOBAL.rawget is not this env's wrapper")
    assert_eq(same_set, true, "GLOBAL.rawset is not this env's wrapper")
    -- A raw read of the accessor names must see the view wrapper, never the engine function.
    assert_eq(raw_get, rawget(env, "rawget"),
        "rawget(GLOBAL, 'rawget') did not return the view wrapper")
    assert_eq(raw_set, rawget(env, "rawset"),
        "rawget(GLOBAL, 'rawset') did not return the view wrapper")
    assert_eq(raw_get ~= rawget(global, "rawget"), true,
        "rawget(GLOBAL, 'rawget') returned the engine function")
    -- Replacing an accessor through the view stays on the view; the engine function is shared
    -- and must keep its identity.
    local engine_rawget = rawget(global, "rawget")
    local override_ok, identity = run(env, [[
        local function f()
            return rawset(GLOBAL, "rawget", function() return "override" end) == GLOBAL
        end
        return f()
    ]])
    assert_eq(override_ok, true, "rawset(GLOBAL, 'rawget', ...) failed: " .. tostring(identity))
    assert_eq(identity, true, "rawset(GLOBAL, 'rawget', ...) did not return the proxy")
    assert_eq(rawget(global, "rawget"), engine_rawget,
        "the view's accessor override clobbered the engine rawget")
    local call_ok, called, raw_called = run(env, [[
        local function f()
            return GLOBAL.rawget(), rawget(GLOBAL, "rawget")()
        end
        return f()
    ]])
    assert_eq(call_ok, true, "the accessor override is not callable: " .. tostring(called))
    assert_eq(called, "override", "GLOBAL.rawget kept the old wrapper after the override")
    assert_eq(raw_called, "override",
        "rawget(GLOBAL, 'rawget') kept the old wrapper after the override")
end

-- Any other table keeps the stock semantics: no metamethod, rawset returns its table.
local function test_raw_access_on_other_tables_is_stock()
    local env = grant_env(new_surface(make_global()), "spec_raw_other")
    local shadow = setmetatable({}, { __index = function() return "ghost" end })
    rawset(env, "spec_shadow", shadow)
    local ok, value, returned = run(env, [[
        local v = rawget(spec_shadow, "missing")
        rawset(spec_shadow, "written", 3)
        return v, rawset(spec_shadow, "again", 4) == spec_shadow
    ]])
    assert_eq(ok, true, "raw access on another table failed: " .. tostring(value))
    assert_eq(value, nil, "rawget consulted the metatable of another table")
    assert_eq(rawget(shadow, "written"), 3, "rawset missed another table")
    assert_eq(returned, true, "rawset did not return its table")
end

-- A stock PUC state has no `jit` global at all; strict must not turn that probe into an error.
local function test_strict_state_without_jit_constructs()
    local global = make_global({ jit = false })
    local surface = surface_lib.new(api, {
        global = global,
        modname = "spec_installer",
        modenv = {},
        private_root = {},
        real_registry = {},
    })
    assert_eq(surface.has_luajit, false, "a stock PUC state was detected as LuaJIT")
    local env = {}
    assert_eq(surface:register_env("spec_puc", env), true, "register_env failed on a stock state")
    assert_eq(rawget(env, "GLOBAL"), nil, "a stock state's env was granted a surface")
end

-- A raw `jit` that strict never declared still means LuaJIT: the probe must not go through
-- strict's __index (that read raises "variable 'jit' is not declared").
local function test_undeclared_jit_is_not_read_through_strict()
    local global = make_global({ declare_jit = false })
    local surface = surface_lib.new(api, {
        global = global,
        modname = "spec_installer",
        modenv = {},
        private_root = {},
        real_registry = {},
    })
    assert_eq(surface.has_luajit, true,
        "a raw `jit` outside strict's __declared set was not detected")
end

test_main_chunk_declares_through_proxy()
test_function_cannot_declare_through_proxy()
test_declared_global_accepts_function_writes()
test_raw_field_without_declaration_is_still_undeclared()
test_state_without_strict_accepts_function_writes()
test_plugin_view_keeps_caller_attribution()
test_rawget_penetrates_to_real_global()
test_rawset_penetrates_to_real_global()
test_global_raw_functions_resolve_to_wrappers()
test_raw_access_on_other_tables_is_stock()
test_strict_state_without_jit_constructs()
test_undeclared_jit_is_not_read_through_strict()

print("ALL PASS luajit_surface_spec")
