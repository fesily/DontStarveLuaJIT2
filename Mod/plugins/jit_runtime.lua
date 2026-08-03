-- jit.runtime — ForceJitOpt + EnabledJIT + HideGlobalJIT + ModBlackList/frostxx kleiloadlua hook.
-- Priority 70: HideGlobalJIT last among jit-related (after debug.profiler prio 20).
--
-- Reads ctx.encrypted_mod_manager / ctx.frostxx_mods produced by jit.tailcall (prio 10).

local function get_config(ctx, key)
    local config = ctx and ctx.config
    if type(config) == "function" then
        return config(key)
    end
    if type(config) == "table" then
        return config[key]
    end
    if type(GetModConfigData) == "function" then
        return GetModConfigData(key)
    end
    return nil
end

local function table_hmask(tab)
    if type(tab) ~= "table" then
        return 0
    end
    local count = 0
    for k, v in pairs(tab) do
        if k ~= nil and v ~= nil then
            count = count + 1
        end
    end
    return count
end

local function startWith(str, prefix)
    return str:find(prefix, 1, true) == 1
end

local function filename2modname(filename)
    local prefix = "../mods/"
    local modname_prefix_pos = #prefix + 1
    if startWith(filename, prefix) then
        local pos = filename:find("/", #prefix + 1, true)
        if pos then
            return filename:sub(modname_prefix_pos, pos - 1)
        end
    end
end

local function ForceJitOpt(has_luajit)
    if not has_luajit then
        return
    end
    local jit_opt = require("jit.opt")
    jit_opt.start(
        "maxtrace=4000",
        "minstitch=2",
        "maxrecord=8000",
        "sizemcode=64",
        "maxmcode=4000",
        "maxirconst=1000"
    )
end

local function skip_jit()
    _G.jit = nil
    if _G.package and _G.package.loaded then
        _G.package.loaded["jit"] = nil
    end
    local reg = _G.debug and _G.debug.getregistry and _G.debug.getregistry()
    if reg and reg["_LOADED"] then
        reg["_LOADED"]["jit"] = nil
    end
end

local function mod_wants_jit(modinfo)
    if type(modinfo) ~= "table" then
        return false
    end
    local compatible = modinfo.luajit_compatible
    return compatible == true or type(compatible) == "table"
end

local function inject_jit_into_mod_env(modenv, jit_table)
    if not jit_table or type(modenv) ~= "table" then
        return false
    end
    if not mod_wants_jit(modenv.modinfo) then
        return false
    end
    modenv.jit = jit_table
    return true
end

local function HookInitializeModMainForJit(jit_table)
    local ModManager = _G.ModManager
    if not ModManager or not ModManager.InitializeModMain then
        return
    end
    if ModManager._ds_luajit_initmodmain_hooked then
        return
    end
    ModManager._ds_luajit_initmodmain_hooked = true

    local old_InitializeModMain = ModManager.InitializeModMain
    function ModManager:InitializeModMain(modname, env, mainfile, safe, ...)
        if inject_jit_into_mod_env(env, jit_table) then
            print("inject jit to mod env:", modname or (env and env.modname) or "?", mainfile or "")
        end
        return old_InitializeModMain(self, modname, env, mainfile, safe, ...)
    end
end

local function HideGlobalJIT(ctx)
    if not (ctx and ctx.has_luajit) then
        return
    end
    local hide = get_config(ctx, "HideGlobalJIT")
    if hide == nil then
        hide = true
    end
    if not hide then
        return
    end

    local jit_table = ctx.jit
    if not jit_table then
        local mod_env = ctx.mod_env
        jit_table = (mod_env and mod_env.jit) or jit
    end

    HookInitializeModMainForJit(jit_table)
    if ctx.mod_env then
        inject_jit_into_mod_env(ctx.mod_env, jit_table)
    end
    skip_jit()
end

local function HookKleiloadlua(frostxxMods, injector, ctx)
    local enbaleBlackList = get_config(ctx, "ModBlackList")
    local blacklists = {
        --- format
        --- 'workshop-<modid>'
    }
    local function decrypt_file(filename)
        local str = injector.DS_LUAJIT_Fengxun_Decrypt(filename)
        if str ~= nil then
            assert(type(str) == "string")
            return loadstring(str, filename)
        end
    end

    if enbaleBlackList then
        enbaleBlackList = #blacklists > 0
    end
    local hmask = table_hmask(frostxxMods)
    if enbaleBlackList or hmask > 0 then
        local _kleiloadlua = kleiloadlua

        rawset(_G, "kleiloadlua", function(filename, ...)
            local modname = filename2modname(filename)
            if modname and hmask > 0 then
                if frostxxMods[modname] and not filename:find("modinfo.lua", 1, true) then
                    if filename:find("modmain.lua", 1, true) then
                        filename = filename:gsub("modmain.lua", "modmain0.lua")
                    elseif filename:find("modworldgenmain.lua", 1, true) then
                        filename = filename:gsub("modworldgenmain.lua", "modworldgenmain0.lua")
                    end

                    local fn = decrypt_file(filename)
                    if fn then
                        return fn
                    end
                end
            end

            local m = _kleiloadlua(filename, ...)
            if enbaleBlackList and modname and type(m) == "function" then
                if blacklists[modname] then
                    jit.off(m, true)
                end
            end
            return m
        end)
    end
end

return {
    id = "jit.runtime",
    version = "1.0.0",
    depends = {},
    soft_depends = { "jit.tailcall", "debug.profiler" },
    conflicts = {},
    phases = "AfterModMain",
    -- AlwaysOn when has_luajit: ForceJitOpt + EnabledJIT + HideGlobalJIT always apply from config.
    options = { always = true },
    support_reload = false,
    priority = 70,
    when = function(ctx)
        if not ctx or not ctx.has_luajit then
            return false
        end
        return true
    end,
    load = function(ctx)
        local has_luajit = ctx and ctx.has_luajit
        ForceJitOpt(has_luajit)

        -- EnabledJIT uses GetModConfigData / ctx.config
        if has_luajit then
            local jit_mod = ctx.jit or jit
            if jit_mod and jit_mod.off then
                jit_mod.off()
            elseif jit then
                jit.off()
            end
            local enabled_jit = get_config(ctx, "EnabledJIT")
            if enabled_jit then
                AddSimPostInit(function()
                    local j = (ctx and ctx.jit) or jit
                    if j and j.on then
                        j.on()
                    end
                end)
            end
        end

        local injector = ctx and ctx.injector
        if injector then
            local frostxx = (ctx and ctx.frostxx_mods) or {}
            HookKleiloadlua(frostxx, injector, ctx)
        end

        -- Hide global jit AFTER profiler / other jit.* requires in this phase.
        HideGlobalJIT(ctx)
    end,
    unload = function(ctx)
        -- Sticky by default.
    end,
}
