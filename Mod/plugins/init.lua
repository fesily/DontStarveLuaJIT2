-- Explicit Lua plugin registry (Path A).
-- Each entry is a plugin table consumed by Mod/plugins/host.lua.
--
-- Game path: init is kleiloadlua'd with MODROOT in env; sibling plugins load the same way
-- because custom env.require only rewrites under MODROOT/scripts/.
-- Test path: package.path includes Mod/?.lua so require("plugins.*") works.
--
-- AfterModMain priority bands (§7.3; gc.policy merged into debug.profiler):
--   10 jit.tailcall | 20 debug.profiler | 40 network.*
--   50 fps.render | 60 sim/save | 70 jit.runtime
--
-- load_package is wired for Task 5+ dual-face migration; registry stays load_flat for P0.

local function get_api()
    local env = getfenv(1)
    local root = (type(env) == "table" and (rawget(env, "MODROOT") or env.MODROOT)) or rawget(_G, "MODROOT")
    local loadlua = (type(env) == "table" and (rawget(env, "kleiloadlua") or env.kleiloadlua)) or rawget(_G, "kleiloadlua")
    local modimport = (type(env) == "table" and (rawget(env, "modimport") or env.modimport)) or rawget(_G, "modimport")
    return {
        MODROOT = root,
        kleiloadlua = loadlua,
        modimport = modimport,
        parent_env = env,
        GetModConfigData = (type(env) == "table" and env.GetModConfigData) or GetModConfigData,
        AddGamePostInit = (type(env) == "table" and env.AddGamePostInit) or AddGamePostInit,
        print = print,
        package_modimport = function(package_root, rel)
            -- Prefer loading package-local file with kleiloadlua + package env.
            local path = package_root .. rel .. ".lua"
            local chunk = loadlua(path)
            if type(chunk) == "function" then
                setfenv(chunk, env)
                return chunk()
            end
            error("package modimport failed: " .. path .. " " .. tostring(chunk))
        end,
    }
end

local function load_package_load()
    local api = get_api()
    if not api.MODROOT or not api.kleiloadlua then
        -- test path (require plugins.* via package.path)
        return require("plugins.package_load")
    end
    local path = api.MODROOT .. "plugins/package_load.lua"
    local chunk = api.kleiloadlua(path)
    if type(chunk) ~= "function" then
        -- test path fallback when kleiloadlua cannot open the file
        return require("plugins.package_load")
    end
    setfenv(chunk, getfenv(1))
    return chunk()
end

local R = load_package_load()
local api = get_api()

local function load_flat(name)
    -- Keep existing kleiloadlua path behavior for flat faces during P0.
    local env = getfenv(1)
    local root = api.MODROOT
    local loadlua = api.kleiloadlua
    if root and loadlua then
        local path = root .. "plugins/" .. name .. ".lua"
        local chunk = loadlua(path)
        if type(chunk) == "function" then
            setfenv(chunk, env)
            return chunk()
        end
        error("failed to load plugin " .. path .. ": " .. tostring(chunk))
    end
    return require("plugins." .. name)
end

local function load_package(stem)
    return R.load_package(stem, api)
end

return {
    load_flat("jit_tailcall"),
    load_flat("debug_profiler"),
    load_flat("network_rpc"),
    load_flat("network_entity"),
    load_flat("fps_render"),
    load_flat("save_fork"),
    load_flat("sim_lagcomp"),
    load_flat("network_sim"),
    load_flat("jit_runtime"),
}
