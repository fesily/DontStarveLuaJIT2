-- Mod/plugins/package_load.lua
-- Thin package loader: DST-like modinfo sandbox + modmain modimport rebind.
-- Not a second PluginHost.

local M = {}
M.last_modinfo_env = nil

local ENGINE_HARD = { "name", "description", "author", "version", "api_version" }
local ENGINE_COMPAT = { "dst_compatible", "dont_starve_compatible", "reign_of_giants_compatible" }
local ENGINE_ROLE = { "client_only_mod", "server_only_mod", "all_clients_require_mod" }

local function is_nil(v) return v == nil end

function M.validate_modinfo(env)
    for _, k in ipairs(ENGINE_HARD) do
        if is_nil(env[k]) then
            return false, "missing engine field: " .. k
        end
    end
    for _, k in ipairs(ENGINE_COMPAT) do
        if is_nil(env[k]) then
            return false, "missing explicit compat field: " .. k
        end
    end
    for _, k in ipairs(ENGINE_ROLE) do
        if is_nil(env[k]) then
            return false, "missing role field: " .. k
        end
    end
    if env.client_only_mod and env.all_clients_require_mod then
        return false, "client_only_mod and all_clients_require_mod are mutually exclusive"
    end
    if is_nil(env.plugin_id) or env.plugin_id == "" then
        return false, "missing plugin_id"
    end
    return true
end

local function default_choose_translation(tbl)
    if type(tbl) ~= "table" then return tbl end
    return tbl[1]
end

local function make_modinfo_env(stem, package_root, extras)
    extras = extras or {}
    local env = {
        folder_name = stem,
        locale = extras.locale or "",
        ChooseTranslationTable = extras.ChooseTranslationTable or default_choose_translation,
        ds_luajit_package_host = true,
        ds_luajit_package_root = package_root,
        ds_luajit_package_stem = stem,
    }
    -- Free globals (TheNet, TheWorld, _G, …) fall through to parent/_G for when().
    -- Host markers stay raw fields on env; assignments write into env (no __newindex).
    local parent = extras.parent_env or _G
    return setmetatable(env, { __index = parent })
end

local function load_chunk(path, env, loader)
    -- loader: function(path) -> chunk|err string  (kleiloadlua or loadfile)
    local chunk = loader(path)
    if type(chunk) == "string" then
        error(path .. ": " .. chunk, 2)
    end
    if type(chunk) ~= "function" then
        error(path .. ": expected function chunk, got " .. type(chunk), 2)
    end
    setfenv(chunk, env)
    return chunk()
end

local function normalize_modimport_name(name)
    local rel = name
    if type(rel) ~= "string" then
        error("modimport name must be string", 2)
    end
    if rel:sub(-4) == ".lua" then
        rel = rel:sub(1, -5)
    end
    return rel
end

local function build_plugin_table(env, package_root, stem, api)
    api = api or {}
    local plugin = {
        id = rawget(env, "plugin_id"),
        version = rawget(env, "version"),
        depends = rawget(env, "depends") or {},
        soft_depends = rawget(env, "soft_depends") or {},
        conflicts = rawget(env, "conflicts") or {},
        phases = rawget(env, "phases") or "AfterModMain",
        options = rawget(env, "options"),
        support_reload = rawget(env, "support_reload") and true or false,
        priority = rawget(env, "priority") or 100,
        when = rawget(env, "when"),  -- rawget: parent may be strict.lua (no bare when)
        load = function(ctx)
            local modmain_path = package_root .. "modmain.lua"
            local parent_modimport = api.modimport
            local parent_env = api.parent_env or _G
            local mod_env
            local bound_modimport
            bound_modimport = function(name)
                -- Prefer package-root relative paths (DST-style scripts/...).
                local rel = normalize_modimport_name(name)
                if api.package_modimport then
                    return api.package_modimport(package_root, rel, mod_env)
                end
                if parent_modimport then
                    -- Fallback: call parent with package-relative path string for tests.
                    return parent_modimport(rel)
                end
                error("modimport not available in package load")
            end
            -- Host gate_ctx supplies injector/config; fall back to parent globals.
            local injector = (ctx and ctx.injector) or rawget(_G, "GameInjector")
            local get_config = api.GetModConfigData
            if type(get_config) ~= "function" and ctx and type(ctx.config) == "function" then
                get_config = ctx.config
            elseif type(get_config) ~= "function" and ctx and type(ctx.config) == "table" then
                local cfg = ctx.config
                get_config = function(key)
                    return cfg[key]
                end
            end
            mod_env = setmetatable({
                modimport = bound_modimport,
                MODROOT = package_root, -- package-local for this chunk only
                print = api.print or print,
                GetModConfigData = get_config,
                GameInjector = injector,
                AddGamePostInit = api.AddGamePostInit or function(fn) fn() end,
            }, { __index = parent_env, __newindex = parent_env })
            local loader = api.kleiloadlua or function(p)
                local f, err = loadfile(p)
                if not f then return err end
                return f
            end
            load_chunk(modmain_path, mod_env, loader)
        end,
        unload = function(ctx) end,
    }
    return plugin
end

-- Production path uses MODROOT + kleiloadlua from caller env.
function M.load_package(stem, api)
    api = api or {}
    local root = api.MODROOT or error("MODROOT required")
    local package_root = root .. "plugins/" .. stem .. "/"
    return M.load_package_from_root(package_root, stem, api)
end

function M.load_package_from_root(package_root, stem, api)
    api = api or {}
    if package_root:sub(-1) ~= "/" and package_root:sub(-1) ~= "\\" then
        package_root = package_root .. "/"
    end
    package_root = package_root:gsub("\\", "/")
    local env = make_modinfo_env(stem, package_root, api)
    M.last_modinfo_env = env
    local loader = api.kleiloadlua or function(p)
        local f, err = loadfile(p)
        if not f then return err end
        return f
    end
    load_chunk(package_root .. "modinfo.lua", env, loader)
    local ok, err = M.validate_modinfo(env)
    if not ok then
        error("package " .. stem .. " modinfo: " .. err, 2)
    end
    return build_plugin_table(env, package_root, stem, api)
end

function M.load_flat(name, api)
    api = api or {}
    local root = api.MODROOT or error("MODROOT required")
    local path = root .. "plugins/" .. name .. ".lua"
    local loader = api.kleiloadlua or function(p)
        local f, err = loadfile(p)
        if not f then return err end
        return f
    end
    local parent_env = api.parent_env or _G
    local env = setmetatable({}, { __index = parent_env, __newindex = parent_env })
    local result = load_chunk(path, env, loader)
    if type(result) ~= "table" then
        error("flat plugin " .. name .. " must return table", 2)
    end
    return result
end

return M
