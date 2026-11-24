-- jit.runtime — ForceJitOpt + EnabledJIT + frostxx/encrypted kleiloadlua hook.
-- Priority 70: last among jit-related (after debug.profiler prio 20).
--
-- Reads ctx.encrypted_mod_manager / ctx.frostxx_mods produced by jit.tailcall (prio 10).
-- GLOBAL/package scrubbing is no longer done here: scripts/luajit_surface.lua takes the
-- surface once per state and hands LuaJIT only to mods that declare `luajit_compatible`.
-- The string.dump attribution manager installs no loader hook, so this file's
-- frostxx/encrypted kleiloadlua wrapper stays the only loader chain.

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

-- The only place GLOBAL.jit/package.loaded.jit are removed is the state's surface
-- (scripts/luajit_surface.lua), which also owns the per-mod grant. This plugin keeps just
-- the execution knobs and the encrypted-mod loader.

local function HookKleiloadlua(encryptedMods, frostxxMods, injector, ctx)
    local function decrypt_file(filename)
        if not injector then
            return
        end
        local str = injector.DS_LUAJIT_Fengxun_Decrypt(filename)
        if str ~= nil then
            assert(type(str) == "string")
            return loadstring(str, filename)
        end
    end

    local hmask = table_hmask(frostxxMods)
    -- Heuristically detected encrypted mods get PROTO_NOJIT so the encrypted
    -- loader never runs under the JIT. This is not a string.dump record: no
    -- per-mod dump policy exists.
    local emask = table_hmask(encryptedMods)
    if hmask > 0 or emask > 0 then
        local _kleiloadlua = kleiloadlua
        local jit_table = ctx and ctx.jit or nil
        -- `_G` is the plugin's authorised view; the engine keeps its own table. Write the
        -- loader the engine will call into the real one (GLOBAL forwards to it).
        local engine = rawget(_G, "GLOBAL") or _G

        engine.kleiloadlua = function(filename, ...)
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
            if modname and type(m) == "function" and jit_table and jit_table.off then
                if emask > 0 and encryptedMods[modname] then
                    jit_table.off(m, true)
                end
            end
            return m
        end
    end
end

return {
    id = "jit.runtime",
    version = "1.0.0",
    depends = {},
    soft_depends = { "jit.tailcall", "debug.profiler" },
    conflicts = {},
    phases = "AfterModMain",
    -- AlwaysOn when has_luajit: ForceJitOpt + EnabledJIT always apply from config.
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
            local jit_mod = ctx.jit
            if jit_mod and jit_mod.off then
                jit_mod.off()
            end
            local enabled_jit = get_config(ctx, "EnabledJIT")
            if enabled_jit then
                AddSimPostInit(function()
                    local j = ctx and ctx.jit
                    if j and j.on then
                        j.on()
                    end
                end)
            end
        end

        local injector = ctx and ctx.injector
        local manager = ctx and ctx.encrypted_mod_manager
        local encrypted = (manager and manager.EncryptedMods) or {}
        local frostxx = (ctx and ctx.frostxx_mods) or {}
        HookKleiloadlua(encrypted, frostxx, injector, ctx)
    end,
    unload = function(ctx)
        -- Sticky by default.
    end,
}
