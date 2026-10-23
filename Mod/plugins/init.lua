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
-- Dual-face packages use load_package; Lua-only faces remain load_flat.

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
        config_modname = (type(env) == "table" and (rawget(env, "modname") or env.modname))
            or rawget(_G, "modname")
            or "DontStarveLuaJit2",
        -- Late-bind so host tests can stub _G.AddGamePostInit after requiring init.
        AddGamePostInit = function(fn)
            local f = (type(env) == "table" and (rawget(env, "AddGamePostInit") or env.AddGamePostInit))
                or rawget(_G, "AddGamePostInit")
            if type(f) == "function" then
                return f(fn)
            end
            -- Immediate run only as last resort (no host deferred registry).
            return fn()
        end,
        print = print,
        package_modimport = function(package_root, rel, package_env)
            -- Prefer loading package-local file with kleiloadlua + package env.
            -- package_env keeps deferred AddGamePostInit modimport rebind alive.
            local path = package_root .. rel .. ".lua"
            if type(loadlua) == "function" then
                local chunk = loadlua(path)
                if type(chunk) == "function" then
                    setfenv(chunk, package_env or env)
                    return chunk()
                end
                error("package modimport failed: " .. path .. " " .. tostring(chunk))
            end
            -- Test path: honor parent/global modimport stub when kleiloadlua is absent.
            local mi = modimport or rawget(_G, "modimport")
            if type(mi) == "function" then
                return mi(rel)
            end
            local chunk, err = loadfile(path)
            if type(chunk) ~= "function" then
                error("package modimport failed: " .. path .. " " .. tostring(err or chunk))
            end
            setfenv(chunk, package_env or env or _G)
            return chunk()
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
    -- Test path (require plugins.*): no MODROOT; resolve package under package.path root.
    if not api.MODROOT then
        local root = (os.getenv("REPO_ROOT") or "."):gsub("\\", "/")
        if root:sub(-1) ~= "/" then
            root = root .. "/"
        end
        return R.load_package_from_root(root .. "Mod/plugins/" .. stem .. "/", stem, api)
    end
    return R.load_package(stem, api)
end

-- Package discovery. The DST Lua sandbox has no directory listing, so the
-- registry asks the injector (core.vm) which package dirs under plugins/ carry
-- modinfo.lua — the same filesystem the native loader scans. The registry is
-- therefore exactly the installed set: a package that is not installed (e.g.
-- the Windows-only plugin_render_shadow on Linux/macOS) is never referenced,
-- which used to raise inside load_package and drop every plugin.
local function injector_get(name)
    local env = getfenv(1)
    if type(env) == "table" then
        local v = rawget(env, name)
        if v == nil then
            v = env[name]
        end
        if v ~= nil then
            return v
        end
    end
    return rawget(_G, name)
end

-- No GameInjector means no Lua bridge (core.vm absent / not injected / unit-test
-- run): every Lua face would be inert, so the plugin system stays off entirely.
-- There is deliberately no static fallback list — it would be a second source of
-- truth that drifts from what is installed (the original Linux bug).
local function plugin_system_disabled(reason)
    print("[luajit][plugin] plugin system disabled: " .. reason)
    return {}
end

local packages_dir = api.MODROOT and (api.MODROOT .. "plugins/") or ""
local injector = injector_get("GameInjector")
local list_fn = injector and injector.DS_LUAJIT_list_plugin_packages
if type(list_fn) ~= "function" then
    return plugin_system_disabled("GameInjector.DS_LUAJIT_list_plugin_packages unavailable")
end
local ok_list, discovered = pcall(list_fn, packages_dir)
if not ok_list or type(discovered) ~= "table" then
    return plugin_system_disabled("package discovery failed: " .. tostring(discovered))
end

local registry = {
    load_flat("jit_tailcall"),
    load_flat("network_entity"),
    load_flat("jit_runtime"),
}

-- One bad package must not hide the rest (the native loader behaves the same).
local function add_package(stem)
    local ok, pkg = pcall(load_package, stem)
    if ok and pkg then
        if pkg.luajit_plugin_pack then
            -- Smoke/pack face shipped for another mod's external discovery
            -- (plugin_dummy); loading it here would be noise, not a feature.
            print("[luajit][plugin] package " .. tostring(stem) .. " is an external pack face; skipped")
            return false
        end
        registry[#registry + 1] = pkg
        return true
    end
    print("[luajit][plugin] package " .. tostring(stem) .. " failed to load: " .. tostring(pkg))
    return false
end

local loaded = 0
for _, stem in ipairs(discovered) do
    if add_package(stem) then
        loaded = loaded + 1
    end
end
print(string.format("[luajit][plugin] discovered %d package(s) under %s", loaded, packages_dir))

return registry
