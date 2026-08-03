-- Explicit Lua plugin registry (Path A).
-- Each entry is a plugin table consumed by Mod/plugins/host.lua.
--
-- Game path: init is kleiloadlua'd with MODROOT in env; sibling plugins load the same way
-- because custom env.require only rewrites under MODROOT/scripts/.
-- Test path: package.path includes Mod/?.lua so require("plugins.*") works.

local function load_plugin(name)
    if MODROOT then
        local chunk = kleiloadlua(MODROOT .. "plugins/" .. name .. ".lua")
        if type(chunk) == "function" then
            return chunk()
        end
        error("failed to load plugin plugins/" .. name .. ".lua: " .. tostring(chunk))
    end
    return require("plugins." .. name)
end

return {
    load_plugin("save_fork"),
    load_plugin("sim_lagcomp"),
    load_plugin("network_sim"),
    load_plugin("network_rpc"),
    load_plugin("network_entity"),
}
