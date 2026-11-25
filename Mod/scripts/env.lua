-- scripts/env.lua — the mod env's module loader.
--
-- modmain.lua and modworldgenmain.lua modimport this chunk before the environment hand-off,
-- so it runs in the mod env (whose GLOBAL is still the real one; the grant happens later, in
-- scripts/luajit_env_bootstrap.lua). Unlike modimport, modrequire keeps the chunk's return
-- value and passes no module name, which is what the hand-off modules need.
--
-- Modules are cached per mod env: the runtime and the downstream ledger both load
-- scripts/luajit_surface.lua, and the surface class identity (the runtime's "is this root
-- ours" check) must be the same object for both. The cache is an upvalue of this chunk, and a
-- second modimport of this file in the same env returns early because modrequire already exists.
if modrequire then
    return
end
local _G = GLOBAL
local modenv = _G.getfenv(1)

-- One GLOBAL fallthrough for the whole mod env, installed with GLOBAL's own helpers: the env
-- is a whitelist before this point (no setmetatable/getfenv/assert), so anything else here is
-- nil. Reads go through rawget on purpose: GLOBAL's own metatable is DST's strict handler, and
-- routing mod-env misses through it turns a benign nil read (mods.lua's PrefabFiles) into
-- "variable is not declared". Raw fields still provide assert/type/kleiloadlua/...; undeclared
-- names stay nil, exactly like an engine mod env.
local rawget = _G.rawget
_G.setmetatable(modenv, {
    __index = function(_, key)
        return rawget(_G, key)
    end,
})

-- Everything the loader itself needs comes from GLOBAL, never from the env it is about to serve.
local error = error
local type = type
local kleiloadlua = kleiloadlua
local setfenv = setfenv
local modroot = MODROOT
if type(modroot) ~= "string" or modroot == "" then
    error("[luajit] Cannot initialize mod environment: MODROOT", 0)
end

local modules = {}

function modrequire(module_name)
    if type(module_name) ~= "string" or module_name == "" then
        error("[luajit] modrequire needs a module name", 0)
    end
    local cached = modules[module_name]
    if cached ~= nil then
        return cached
    end
    local filepath = modroot .. module_name .. ".lua"
    local chunk, load_error = kleiloadlua(filepath)
    if type(chunk) ~= "function" then
        error("[luajit] Cannot load " .. filepath .. ": " .. tostring(load_error), 0)
    end
    setfenv(chunk, modenv)
    local result = chunk()
    modules[module_name] = result
    return result
end
