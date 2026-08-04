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

local function load_plugin(name)
    -- In-game: modmain setfenv's this chunk to the mod proxy env.
    -- MODROOT usually lives only on env.__index (not a raw key), so rawget alone fails
    -- and we incorrectly fall through to require("plugins.X") → scripts/plugins/X.lua.
    local env = getfenv(1)
    local root = nil
    local loadlua = nil
    if type(env) == "table" then
        root = rawget(env, "MODROOT")
        if root == nil then
            -- metamethod / proxy lookup (not a strict global read)
            root = env.MODROOT
        end
        loadlua = rawget(env, "kleiloadlua")
        if loadlua == nil then
            loadlua = env.kleiloadlua
        end
    end
    if root == nil then
        root = rawget(_G, "MODROOT")
    end
    if loadlua == nil then
        loadlua = rawget(_G, "kleiloadlua")
    end
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

return {
    load_plugin("jit_tailcall"),
    load_plugin("debug_profiler"),
    load_plugin("network_rpc"),
    load_plugin("network_entity"),
    load_plugin("fps_render"),
    load_plugin("save_fork"),
    load_plugin("sim_lagcomp"),
    load_plugin("network_sim"),
    load_plugin("jit_runtime"),
}
