-- ConfigPatch bootstrap entrypoint.
-- Call this only after scripts/modindex.lua has created KnownModIndex.
-- This installs the base DST mod config screen patch in memory and does not touch save data or startup timing.

return function()
    local known_mod_index = rawget(_G, "KnownModIndex")
    assert(known_mod_index ~= nil, "ConfigPatchBootstrap must run after modindex.lua has initialized KnownModIndex")

    if known_mod_index.__config_patch_installed then
        print("ConfigPatch: already installed, skipping")
        return true
    end

    print("ConfigPatch: installing mod config screen patch")

    local _PATCH = {}
    _PATCH.helpers = require("config_patch_bootstrap/config_patch_helpers")
    _PATCH.screen = require("config_patch_bootstrap/config_patch_screen")

    known_mod_index.__config_patch_installed = true
    return true
end
