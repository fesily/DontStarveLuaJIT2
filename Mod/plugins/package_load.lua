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
    local locale = extras.locale or ""
    local function translate(t)
        if type(t) ~= "table" then
            return t
        end
        t.zhr = t.zh
        t.zht = t.zht or t.zh
        return t[locale] or t.en
    end
    local toggle = {
        { description = translate({ en = "On", zh = "启用" }), data = true },
        { description = translate({ en = "Off", zh = "禁用" }), data = false },
    }
    local section_counter = 0
    local function AddSection(label, hover)
        section_counter = section_counter + 1
        return {
            section_start = true,
            name = "SECTION_" .. section_counter,
            label = label,
            hover = hover,
            options = { { description = "", data = "" } },
            default = "",
        }
    end
    local disable_by_gen_gc = {
        option = "EnabledGenGC",
        value = true,
        reason = translate({ en = "Not compatible with generational GC", zh = "与分代GC不兼容" }),
    }
    local disable_by_lua51 = {
        option = "LuaVmType",
        values = { "lua51", "game" },
        reason = translate({ en = "Not compatible with Lua 5.1 VM", zh = "与Lua 5.1虚拟机不兼容" }),
    }
    local platform_info = extras.platform_info
    local disable_by_non_win = platform_info and not (platform_info.os == "Windows") or false
    local env = {
        folder_name = stem,
        locale = locale,
        ChooseTranslationTable = extras.ChooseTranslationTable or default_choose_translation,
        ds_luajit_package_host = true,
        ds_luajit_package_root = package_root,
        ds_luajit_package_stem = stem,
        translate = translate,
        toggle = toggle,
        AddSection = AddSection,
        disable_by_gen_gc = disable_by_gen_gc,
        disable_by_lua51 = disable_by_lua51,
        disable_by_non_win = disable_by_non_win,
        platform_info = platform_info,
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
    local cfg_name = api.config_modname
    local cfg_for = api.config_for_mod
    local config_lookup
    if type(cfg_for) == "function" then
        config_lookup = function(key)
            return cfg_for(cfg_name, key)
        end
    end
    local plugin = {
        id = rawget(env, "plugin_id"),
        version = rawget(env, "version"),
        depends = rawget(env, "depends") or {},
        soft_depends = rawget(env, "soft_depends") or {},
        conflicts = rawget(env, "conflicts") or {},
        phases = rawget(env, "phases") or "AfterModMain",
        options = M.derive_option_rule(rawget(env, "configuration_options")),
        configuration_options = rawget(env, "configuration_options"),
        config_modname = cfg_name,
        config_lookup = config_lookup,
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
            local get_config = config_lookup or api.GetModConfigData
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
    if rawget(env, "options") ~= nil then
        error("package " .. stem .. " modinfo: obsolete field options; use configuration_options + host_gate", 2)
    end
    if type(api.config_modname) ~= "string" or api.config_modname == "" then
        error("package " .. stem .. " load: missing api.config_modname", 2)
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

function M.derive_option_rule(configuration_options)
    if type(configuration_options) ~= "table" then
        return { always = true }
    end
    local all_of, any_of = {}, {}
    for i = 1, #configuration_options do
        local row = configuration_options[i]
        if type(row) == "table" and row.section_start ~= true then
            local name = row.name
            if type(name) == "string" and name ~= "" then
                local g = row.host_gate
                if g == true or g == "all_of" then
                    all_of[#all_of + 1] = name
                elseif g == "any_of" then
                    any_of[#any_of + 1] = name
                elseif g ~= nil and g ~= false then
                    error("unknown host_gate: " .. tostring(g), 2)
                end
            end
        end
    end
    if #all_of == 0 and #any_of == 0 then
        return { always = true }
    end
    local rule = {}
    if #all_of > 0 then
        rule.all_of = all_of
    end
    if #any_of > 0 then
        rule.any_of = any_of
    end
    return rule
end

return M
