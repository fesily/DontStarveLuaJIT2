-- Compatibility probe: declares `luajit_compatible = true`; checks the per-env capability.
local G = GLOBAL
local tag = "main"
local folder = modname

local function fail(message)
    G.assert(false, "[ds_luajit_env] " .. tag .. ": " .. message .. " (" .. folder .. ")")
end

local env = G.getfenv(1)
local luajit = G.rawget(env, "luajit")
if G.type(luajit) ~= "table" then fail("no luajit container") end
if G.rawget(env, "jit") ~= luajit.jit then fail("env.jit is not luajit.jit") end
if G.jit ~= luajit.jit then fail("GLOBAL.jit is not luajit.jit") end
if G.debug.upvalueid ~= luajit.debug.upvalueid then fail("GLOBAL.debug.upvalueid is not the copy") end
if G.rawget(env, "GameInjector") ~= nil then fail("injector table leaked into the env") end
if G.rawget(G, "GameInjector") ~= nil then fail("real GLOBAL.GameInjector is not cleared") end
if G.rawget(G, "GameLuaInjector") ~= nil then fail("real GLOBAL.GameLuaInjector is not cleared") end

local t = G.table.new(2, 2)
t[1] = "x"
if t[1] ~= "x" then fail("table.new is not usable") end
local ffi = env.require("ffi")
if G.type(ffi) ~= "table" or G.type(ffi.new) ~= "function" then fail("ffi is not usable") end
local arr = ffi.new("int[1]", 7)
if arr[0] ~= 7 then fail("ffi.new did not run") end
if env.require("jit") ~= luajit.jit then fail("require('jit') is not luajit.jit") end

for _, value in G.pairs(G.debug.getregistry()) do
    if G.type(value) == "table" then
        if G.rawget(value, "controller") ~= nil or G.rawget(value, "modules") ~= nil then
            fail("the private registry root is reachable")
        end
    end
end

G.print("[ds_luajit_env] " .. tag .. " ok " .. folder)
