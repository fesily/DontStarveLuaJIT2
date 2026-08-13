-- Discover enabled external DST mods marked luajit_plugin_pack and load package faces.
-- Does not LoadLibrary (native is C EarlyNative). Built-in this mod is skipped.

local M = {}

local function is_nonempty_string(v)
    return type(v) == "string" and v ~= ""
end

local function list_enabled_mod_names(is_client)
    local names = {}
    if type(KnownModIndex) ~= "table" then
        return names
    end
    local list
    if is_client then
        if type(KnownModIndex.GetClientModNames) == "function" then
            list = KnownModIndex:GetClientModNames()
        elseif type(KnownModIndex.GetClientModNamesTable) == "function" then
            list = KnownModIndex:GetClientModNamesTable()
        end
    else
        if type(KnownModIndex.GetServerModNames) == "function" then
            list = KnownModIndex:GetServerModNames()
        elseif type(KnownModIndex.GetEnabledServerModNames) == "function" then
            list = KnownModIndex:GetEnabledServerModNames()
        elseif type(KnownModIndex.GetServerModNamesTable) == "function" then
            list = KnownModIndex:GetServerModNamesTable()
        end
    end
    if type(list) ~= "table" then
        return names
    end
    for _, v in pairs(list) do
        if type(v) == "string" then
            names[#names + 1] = v
        elseif type(v) == "table" and type(v.modname) == "string" then
            names[#names + 1] = v.modname
        end
    end
    return names
end

local function is_enabled(modname)
    if type(KnownModIndex) ~= "table" then
        return false
    end
    if type(KnownModIndex.IsModEnabled) == "function" then
        local ok, en = pcall(function()
            return KnownModIndex:IsModEnabled(modname)
        end)
        return ok and en and true or false
    end
    return false
end

local function get_modinfo(modname)
    if type(KnownModIndex) ~= "table" or type(KnownModIndex.GetModInfo) ~= "function" then
        return nil
    end
    local ok, info = pcall(function()
        return KnownModIndex:GetModInfo(modname)
    end)
    if ok then
        return info
    end
    return nil
end

local function default_mod_root(modname)
    local root = rawget(_G, "MODS_ROOT")
    if type(root) ~= "string" or root == "" then
        root = "../mods/"
    end
    if root:sub(-1) ~= "/" and root:sub(-1) ~= "\\" then
        root = root .. "/"
    end
    return (root .. modname .. "/"):gsub("\\", "/")
end

local function list_package_dirs(mod_root, api)
    local out = {}
    local plugins = mod_root .. "plugins/"
    if api and type(api.list_dir) == "function" then
        local entries = api.list_dir(plugins) or {}
        for _, name in ipairs(entries) do
            if type(name) == "string" and name:sub(1, 7) == "plugin_" then
                out[#out + 1] = plugins .. name .. "/"
            end
        end
        return out
    end
    if api and type(api.package_dirs_for_mod) == "function" then
        local dirs = api.package_dirs_for_mod(mod_root)
        if type(dirs) == "table" and #dirs > 0 then
            return dirs
        end
    end
    -- Production FS listing when available (varies by build).
    local TheSim = rawget(_G, "TheSim")
    if type(TheSim) == "table" then
        local listfn = TheSim.ListDirectory or TheSim.GetDirList or TheSim.ListFiles
        if type(listfn) == "function" then
            local ok, entries = pcall(listfn, TheSim, plugins)
            if ok and type(entries) == "table" then
                for _, name in pairs(entries) do
                    if type(name) == "string" and name:sub(1, 7) == "plugin_" then
                        out[#out + 1] = plugins .. name .. "/"
                    end
                end
            end
        end
    end
    return out
end

local function try_load_package(api, package_root, stem)
    if not api or not api.package_load or type(api.package_load.load_package_from_root) ~= "function" then
        return nil, "no_package_load"
    end
    local ok, result = pcall(function()
        return api.package_load.load_package_from_root(package_root, stem, api)
    end)
    if not ok then
        return nil, tostring(result)
    end
    return result, nil
end

--- api fields:
---   this_modname, is_client, package_load, MODROOT, kleiloadlua, parent_env,
---   config_for_mod?, GetModConfigData?,
---   mod_root_for(modname)?, list_dir(path)?, package_dirs_for_mod(mod_root)?
--- Per-pack clone sets config_modname to the enabled folder name.
function M.run(api)
    api = api or {}
    local out = {}
    local this_mod = api.this_modname
    local names = list_enabled_mod_names(api.is_client and true or false)
    for i = 1, #names do
        local modname = names[i]
        if this_mod and modname == this_mod then
            -- skip built-in
        elseif not is_enabled(modname) then
            -- skip disabled
        else
            local info = get_modinfo(modname)
            if not info or not info.luajit_plugin_pack then
                -- skip unmarked
            elseif not is_nonempty_string(info.plugin_id) then
                print("[luajit][plugin-discover] skip " .. tostring(modname) .. " reason=missing_plugin_id")
            else
                local mod_root
                if type(api.mod_root_for) == "function" then
                    mod_root = api.mod_root_for(modname)
                else
                    mod_root = default_mod_root(modname)
                end
                if type(mod_root) ~= "string" or mod_root == "" then
                    print("[luajit][plugin-discover] skip " .. tostring(modname) .. " reason=no_root")
                else
                    if mod_root:sub(-1) ~= "/" and mod_root:sub(-1) ~= "\\" then
                        mod_root = mod_root .. "/"
                    end
                    mod_root = mod_root:gsub("\\", "/")
                    local dirs = list_package_dirs(mod_root, api)
                    -- Single-pack mod: package at mod_root if plugins empty but modinfo is pack
                    if #dirs == 0 then
                        -- Try plugins/plugin_* via stem from plugin_id is not reliable; require dirs.
                        print("[luajit][plugin-discover] skip " .. tostring(modname) ..
                            " reason=no_package_dirs")
                    else
                        for _, package_root in ipairs(dirs) do
                            local stem = package_root:match("([^/]+)/?$") or "plugin_unknown"
                            local pack_api = {}
                            for k, v in pairs(api) do
                                pack_api[k] = v
                            end
                            pack_api.config_modname = modname
                            local plugin, err = try_load_package(pack_api, package_root, stem)
                            if plugin then
                                out[#out + 1] = plugin
                                print("[luajit][plugin-discover] load mod=" .. tostring(modname) ..
                                    " id=" .. tostring(info.plugin_id) .. " stem=" .. tostring(stem))
                            else
                                print("[luajit][plugin-discover] skip " .. tostring(modname) ..
                                    " stem=" .. tostring(stem) .. " reason=" .. tostring(err))
                            end
                        end
                    end
                end
            end
        end
    end
    return out
end

return M
