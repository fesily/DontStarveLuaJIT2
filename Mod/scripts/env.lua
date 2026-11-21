-- scripts/env.lua — the mod env's module loader.
--
-- modmain.lua and modworldgenmain.lua modimport this chunk before the environment hand-off,
-- so it runs in the mod env (whose GLOBAL is still the real one; the grant happens later, in
-- scripts/luajit_env_bootstrap.lua). Unlike modimport, modrequire keeps the chunk's return
-- value and passes no module name, which is what the hand-off modules need.
local global = GLOBAL
-- The mod env is a whitelist: type is available, assert/error are reached through GLOBAL.
if type(global) ~= "table" then
    return
end
local modenv = global.getfenv(1)
local modroot = modenv.MODROOT
if type(modroot) ~= "string" or modroot == "" then
    global.error("[luajit] Cannot initialize mod environment: MODROOT", 0)
end

function modrequire(module_name)
    if type(module_name) ~= "string" or module_name == "" then
        global.error("[luajit] modrequire needs a module name", 0)
    end
    local filepath = modroot .. module_name .. ".lua"
    local chunk, load_error = global.kleiloadlua(filepath)
    if type(chunk) ~= "function" then
        global.error("[luajit] Cannot load " .. filepath .. ": " .. tostring(load_error), 0)
    end
    global.setfenv(chunk, modenv)
    return chunk()
end
