-- shell_harness.lua -- engine-equivalent sandbox for self-checking "shell"-protected DST mods.
-- Usage:
--   luajit shell_harness.lua <out.log> <mod-root-dir> [hidejit:0|1] [modname] [original-modmain.lua]
-- Mirrors the stock engine env (data/scripts/mods.lua CreateEnvironment):
--   * plain env table; env.env = env; env.GLOBAL = game globals; env.modname / env.MODROOT
--   * NO env._G  -- the shell's anti-debug gate trips when a harness aliases _G into env
--   * real `debug` (debug.load must stay a C function for the fingerprint checks)
--   * io/os/loadfile/kleiloadlua served through GLOBAL; modimport loads ROOT/<name>
--   * pass [original-modmain.lua] to serve pristine bytes to the self-check read
--     (bypass A) while ROOT/modmain.lua itself stays modified
local OUT = arg[1] or "shell_trace.txt"
local ROOT = arg[2] or "."
local HIDEJIT = arg[3] == "1"
local MODNAME = arg[4] or "workshop-2130351510"
local ORIG = arg[5]
local FAKE = "../mods/" .. MODNAME .. "/"
if HIDEJIT then
    _G.jit = nil
    if package and package.loaded then package.loaded["jit"] = nil end
    local reg = debug.getregistry()
    if reg and reg["_LOADED"] then reg["_LOADED"]["jit"] = nil end
end
local TARGET = "modmain.lua"
local LOG = assert(io.open(OUT, "w"))
local real_char, real_concat, real_loadstring, real_gsub
local n = 0
local function log(...)
    local parts = {}
    for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
    LOG:write(real_concat(parts, "\t"), "\n")
    if n % 200 == 0 then LOG:flush() end
    n = n + 1
end
local function cat(v, lim)
    if type(v) ~= "string" then return tostring(v) end
    v = real_gsub(v, "[^\32-\126]", ".")
    if #v > lim then v = v:sub(1, lim) .. "..." end
    return v
end
local realG = _G
real_char, real_concat, real_loadstring = string.char, table.concat, loadstring
real_gsub = string.gsub

-- anti-clear sethook + call tracer
local tracing = true
local in_hook = false
local function hook(ev)
    if in_hook then return end
    in_hook = true
    if ev ~= "call" then in_hook = false return end
    local i2 = debug.getinfo(2, "S")
    if not (i2 and tostring(i2.source):find(TARGET, 1, true)) then return end
    local i3 = debug.getinfo(3, "S")
    local from = i3 and tostring(i3.source):gsub("^.*/", "") or "?"
    local fn = debug.getinfo(2, "f")
    local nparams = fn and fn.nparams or 0
    local args = {}
    for i = 1, math.min(nparams, 4) do
        local ok, v = pcall(debug.getlocal, 2, i)
        args[#args + 1] = ok and cat(v, 20) or "?"
    end
    log("CALL", from, "line" .. tostring(i2.linedefined), real_concat(args, " | "))
    in_hook = false
end
local real_sethook = debug.sethook
debug.sethook = function(f, mask, count)
    if f == nil then
        log("sethook-CLEAR-BLOCKED")
        return
    end
    return real_sethook(f, mask, count)
end
real_sethook(hook, "c")

-- logging wrappers (allowed here)
string.char = function(...)
    local r = real_char(...)
    log("char", real_concat({ ... }, ","), "->", cat(r, 60))
    return r
end
table.concat = function(t, sep, i, j)
    local r = real_concat(t, sep, i, j)
    log("concat", type(t) == "table" and ("n=" .. #t) or type(t), "->", cat(r, 4000))
    return r
end
loadstring = function(s, name, ...)
    log("loadstring", tostring(name), type(s) == "string" and #s or -1, cat(s, 200))
    local f, e = real_loadstring(s, name, ...)
    return f, e
end

local GAME = {}
do
    local g = GAME
    g.print = function(...) log("print", ...) end
    g.type, g.tostring, g.pairs, g.ipairs = type, tostring, pairs, ipairs
    g.string, g.table, g.math = string, table, math
    g.select, g.unpack, g.pcall, g.error, g.assert = select, unpack, pcall, error, assert
    g.setmetatable, g.getmetatable, g.rawget, g.rawset = setmetatable, getmetatable, rawget, rawset
    g.require, g.loadstring, g.loadfile, g.setfenv, g.getfenv = require, loadstring, loadfile, setfenv, getfenv
    local dbg_proxy = {}
    setmetatable(dbg_proxy, {
        __index = function(_, k)
            local v = debug[k]
            if type(v) ~= "function" then return v end
            return function(...)
                local a = { ... }
                local ok, r = pcall(v, ...)
                if not in_hook then
                    local parts = {}
                    for i = 1, math.min(#a, 3) do
                        local x = a[i]
                        if type(x) == "string" then parts[#parts + 1] = x:gsub("\n", " "):sub(1, 40)
                        else parts[#parts + 1] = tostring(x) end
                    end
                    log("debug." .. tostring(k), real_concat(parts, " | "), "->", type(r))
                end
                if not ok then error(r, 0) end
                return r
            end
        end,
    })
    g.debug = debug  -- h13: pass real debug so debug.load.what=="C"
    g.coroutine, g.newproxy, g.next, g.tonumber = coroutine, newproxy, next, tonumber
    g.io = setmetatable({
        open = function(path, mode, ...)
            local p = tostring(path)
            if ORIGINAL_SRC and ORIGINAL_SRC.data and p:find("modmain%.lua$") and tostring(mode):find("r") then
                log("io.open-SERVE-ORIGINAL", p, tostring(mode))
                local f = realG.io.open(ROOT .. "/.orig_modmain.lua", "wb"); f:write(ORIGINAL_SRC.data); f:close()
                return realG.io.open(ROOT .. "/.orig_modmain.lua", mode, ...)
            end
            local mapped = p:gsub("^" .. FAKE:gsub("%p", "%%%0"), ROOT .. "/")
            log("io.open", p, "->", mapped, tostring(mode))
            return realG.io.open(mapped, mode, ...)
        end,
        lines = function(path, ...) log("io.lines", tostring(path)) return realG.io.lines(path, ...) end,
    }, { __index = function(_, k) return realG.io[k] end })
    g.os = { time = os.time, clock = os.clock, date = os.date, getenv = os.getenv, execute = function(c) log("os.execute BLOCKED", tostring(c)) return 0 end,
             remove = function(p) log("os.remove BLOCKED", tostring(p)) return true end, exit = function() log("os.exit BLOCKED") end }
    g.kleiloadlua = function(filename, ...)
        local f = realG.io.open(filename, "rb")
        local data = f and f:read("*a")
        if f then f:close() end
        log("kleiloadlua", tostring(filename), data and (#data .. "B") or "nil")
        if not data then return nil end
        local fn, err = real_loadstring(data, "@" .. tostring(filename))
        if fn then return fn end
        log("kleiloadlua-compile-fail", tostring(err))
        return tostring(err)
    end
    g.GetModConfigData = function(k, ...) log("GetModConfigData", tostring(k)) return 30 end
    g.TheSim = { GetPersistentString = function(_, n2) log("GetPersistentString", tostring(n2)) return false end }
    g.MODS_ROOT = "../mods/"
    g.jit = jit  -- h14: LuaJIT-backed engine
    g.modname = MODNAME
end
-- log every GLOBAL read (this is how we learn what the protector checks)
setmetatable(GAME, {
    __index = function(t, k)
        if not in_hook then
            local v = rawget(t, k)
            log("GLOBAL-read", tostring(k), type(v))
            return v
        end
        return rawget(t, k)
    end,
})
local env = {}
env.env, env.GLOBAL = env, GAME  -- h14: engine-like (no env._G)
setmetatable(env, { __index = function(_, k)
    if k == "_G" then return nil end  -- h14
    local v = GAME[k]                       -- goes through GAME's logging metatable
    if v == nil then v = realG[k] end
    if not in_hook then log("ENV-read", tostring(k), type(v)) end
    return v
end })
for k, v in pairs({ pairs = pairs, ipairs = ipairs, print = GAME.print, math = math, table = table, type = type,
    string = string, tostring = tostring, require = require, modname = MODNAME,
    MODROOT = FAKE }) do rawset(env, k, v) end
env.modimport = function(modulename)
    log("modimport", tostring(modulename))
    if string.sub(modulename, -4) ~= ".lua" then modulename = modulename .. ".lua" end
    local f = realG.io.open(ROOT .. "/" .. modulename, "rb")
    local data = f and f:read("*a")
    if f then f:close() end
    log("modimport-read", tostring(modulename), data and (#data .. "B") or "nil")
    if not data then error("modimport not found " .. tostring(modulename)) end
    local fn, err = real_loadstring(data, "@" .. tostring(modulename))
    if type(fn) ~= "function" then log("modimport-compile-fail", tostring(modulename), tostring(err)) error("compile failed") end
    setfenv(fn, env)
    local ok, e = pcall(fn)
    log("modimport-result", tostring(modulename), ok and "ok" or "ERR", tostring(e))
end

package.path = package.path .. ";" .. ROOT .. "/scripts/?.lua;" .. ROOT .. "/?.lua"
-- deeper payload runs may also need the engine scripts, e.g.:
--   package.path = package.path .. ";<GAME>/data/scripts/?.lua"
ORIGINAL_SRC = nil
if ORIG then
    ORIGINAL_SRC = {}
    local f = assert(realG.io.open(ORIG, "rb"))
    ORIGINAL_SRC.data = f:read("*a"); f:close()
    print("[harness] serve-original: " .. ORIG .. " (" .. #ORIGINAL_SRC.data .. "B) -> self-check reads")
end
local src = assert((function()
    local f = realG.io.open(ROOT .. "/modmain.lua", "rb")
    local d = f and f:read("*a"); if f then f:close() end; return d
end)())
log("protector-size", #src)
local chunk = assert(real_loadstring(src, "@" .. FAKE .. "modmain.lua"))
setfenv(chunk, env)
local ok, res = xpcall(chunk, function(e) return tostring(e) end)
debug.sethook()
log("protector-result", ok and "ok" or "ERR", tostring(res):sub(1, 300))
log("END")
LOG:close()
print("wrote " .. OUT .. " (" .. n .. " lines)")
