-- Worldgen runs in its own lua_State, where the tool mod installs the manager from
-- Mod/modworldgenmain.lua before any other mod's worldgen code. Same probe, same
-- contract: real PUC Lua 5.1 bytecode for a mod's string.dump.
local G = GLOBAL
local tag = "worldgen"

local chunk = G.loadstring("return function(n) return n + 7 end", "=puc_dump_dynamic")
G.assert(type(chunk) == "function", "[ds_puc_dump] " .. tag .. ": loadstring failed")

local f = chunk()
G.assert(type(f) == "function", "[ds_puc_dump] " .. tag .. ": chunk returned no function")
G.assert(f(5) == 12, "[ds_puc_dump] " .. tag .. ": fixture does not run")

local bytes = string.dump(f)
G.assert(type(bytes) == "string", "[ds_puc_dump] " .. tag .. ": string.dump returned no bytes")
G.assert(#bytes > 6, "[ds_puc_dump] " .. tag .. ": string.dump returned an empty dump")
G.assert(string.sub(bytes, 1, 6) == "\27Lua\81\0",
    "[ds_puc_dump] " .. tag .. ": string.dump did not return PUC Lua 5.1 bytecode")

G.assert(f(5) == 12, "[ds_puc_dump] " .. tag .. ": function changed after the dump")
-- Undeclared compatibility: no capability, no injector tables, and the shared loader never
-- answers an extension name.
local env = G.getfenv(1)
G.assert(G.rawget(env, "luajit") == nil, "[ds_luajit_env] " .. tag .. ": an undeclared mod gained luajit")
G.assert(G.rawget(env, "GameInjector") == nil,
    "[ds_luajit_env] " .. tag .. ": an undeclared mod gained GameInjector")
G.assert(G.rawget(G, "GameInjector") == nil, "[ds_luajit_env] " .. tag .. ": real GLOBAL.GameInjector is not cleared")
G.assert(G.rawget(G, "GameLuaInjector") == nil,
    "[ds_luajit_env] " .. tag .. ": real GLOBAL.GameLuaInjector is not cleared")
local ok_jit = G.pcall(env.require, "jit")
G.assert(not ok_jit, "[ds_luajit_env] " .. tag .. ": an undeclared mod required jit")
G.print("[ds_luajit_env] " .. tag .. " ok " .. modname)
