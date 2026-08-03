-- Explicit Lua plugin registry (Path A).
-- Each entry is a plugin table consumed by Mod/plugins/host.lua.
--
-- Game path: init is kleiloadlua'd with MODROOT in env; sibling plugins load the same way
-- because custom env.require only rewrites under MODROOT/scripts/.
-- Test path: package.path includes Mod/?.lua so require("plugins.*") works.
--
-- AfterModMain priority bands (§7.3):
--   10 jit.tailcall | 20 debug.profiler | 30 gc.policy | 40 network.*
--   50 fps.render | 60 sim/save | 70 jit.runtime

local function load_plugin(name)
    -- In-game: modmain setfenv's this chunk so MODROOT is a real key on the env.
    -- Under strict.lua, bare global MODROOT errors if missing — only rawget/getfenv.
    local env = getfenv(1)
    local root = (type(env) == "table" and rawget(env, "MODROOT")) or rawget(_G, "MODROOT")
    local loadlua = (type(env) == "table" and rawget(env, "kleiloadlua")) or rawget(_G, "kleiloadlua")
    if root and loadlua then
        local chunk = loadlua(root .. "plugins/" .. name .. ".lua")
        if type(chunk) == "function" then
            setfenv(chunk, env)
            return chunk()
        end
        error("failed to load plugin plugins/" .. name .. ".lua: " .. tostring(chunk))
    end
    return require("plugins." .. name)
end

return {
    load_plugin("jit_tailcall"),
    load_plugin("debug_profiler"),
    load_plugin("gc_policy"),
    load_plugin("network_rpc"),
    load_plugin("network_entity"),
    load_plugin("fps_render"),
    load_plugin("save_fork"),
    load_plugin("sim_lagcomp"),
    load_plugin("network_sim"),
    load_plugin("jit_runtime"),
}
