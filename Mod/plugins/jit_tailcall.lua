-- jit.tailcall — SlowTailCall + ForceDisableTailCall + AutoDetectEncryptedMod.
-- compat.frostxx encrypt detect is folded here (thin merge per §7.3 / inventory).
-- Priority 10: runs before debug.profiler (20) and jit.runtime (70).
--
-- Stores EncryptedModManager on ctx for jit.runtime HookKleiloadlua (ModBlackList + frostxx).

local function make_file_io()
    local ModManagerFile = { filepath = nil, json_mode = true }
    function ModManagerFile:read_file()
        if not self.filepath then
            return
        end
        local fp = io.open(self.filepath, "r")
        if not fp then
            return
        end
        local str = fp:read("*a")
        fp:close()
        if self.json_mode then
            local ok, result = pcall(json.decode, str)
            return ok and result or nil
        end
        return str
    end
    function ModManagerFile:write_file(data)
        if not self.filepath then
            return
        end
        local fp = io.open(self.filepath, "w")
        if not fp then
            return
        end
        if data and self.json_mode then
            data = json.encode(data)
        end
        if data then
            fp:write(data)
        end
        fp:close()
    end
    return ModManagerFile
end

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

local function GetEncryptedModManager(ctx)
    local ModManagerFile = make_file_io()
    local luajit_encryptmods = setmetatable(
        { filepath = "unsafedata/luajit_encryptmods.json" },
        { __index = ModManagerFile }
    )

    local AutoDetectEncryptedMod = get_config(ctx, "AutoDetectEncryptedMod")

    local EncryptedModManager = AutoDetectEncryptedMod and luajit_encryptmods:read_file() or nil
    local EncryptedModManager_version = APP_VERSION .. "/1.0.0"
    if EncryptedModManager == nil or EncryptedModManager.version ~= EncryptedModManager_version then
        EncryptedModManager = {
            EncryptedMods = {},
            frostxxMods = {},
            version = EncryptedModManager_version,
            hash = 0,
        }
    end

    local function HashString(str)
        local hash = 0
        for i = 1, #str do
            hash = bit.bxor(hash, str:byte(i))
        end
        return hash
    end

    local function HashModDirectoryNames(ModDirectoryNames)
        local hash = 0
        for i, v in ipairs(ModDirectoryNames) do
            hash = bit.bxor(hash, HashString(v))
        end
        return hash
    end

    local function InitEncryptedModManager()
        local self = EncryptedModManager
        local ModDirectoryNames = TheSim:GetModDirectoryNames()
        if not ModDirectoryNames then
            return
        end

        local hash = HashModDirectoryNames(ModDirectoryNames)
        if hash == self.hash then
            return
        end
        self.hash = hash

        local function is_visible_byte(b)
            return (b >= 32 and b <= 126)
        end

        local function all_invisible_chars_are_utf8(str)
            local i = 1
            local len = #str
            while i <= len do
                local b = str:byte(i)
                if not is_visible_byte(b) then
                    if b >= 0 and b <= 127 then
                        if not (b == 9 or b == 10 or b == 13 or b == 27) then
                            return false
                        end
                        i = i + 1
                    elseif b >= 194 and b <= 223 then
                        if i + 1 > len then
                            return false
                        end
                        local b2 = str:byte(i + 1)
                        if not (b2 >= 128 and b2 <= 191) then
                            return false
                        end
                        i = i + 2
                    elseif b >= 224 and b <= 239 then
                        if i + 2 > len then
                            return false
                        end
                        local b2, b3 = str:byte(i + 1), str:byte(i + 2)
                        if not (b2 >= 128 and b2 <= 191 and b3 >= 128 and b3 <= 191) then
                            return false
                        end
                        i = i + 3
                    elseif b >= 240 and b <= 244 then
                        if i + 3 > len then
                            return false
                        end
                        local b2, b3, b4 = str:byte(i + 1), str:byte(i + 2), str:byte(i + 3)
                        if not (b2 >= 128 and b2 <= 191 and b3 >= 128 and b3 <= 191 and b4 >= 128 and b4 <= 191) then
                            return false
                        end
                        i = i + 4
                    else
                        return false
                    end
                else
                    i = i + 1
                end
            end
            return true
        end

        local function check_encrypted(filename, modname)
            local fp = io.open(filename, "r")
            if not fp then
                return
            end

            local limit = 64
            local result
            for line in fp:lines() do
                if limit <= 12 then
                    if line:find("frostxx@qq.com", 1, true) then
                        self.frostxxMods[modname] = true
                        print(filename, modname, " is frostxx mod!")
                    end
                end
                if #line > 1024 then
                    self.EncryptedMods[modname] = true
                    print(filename, modname, " is encrypted! by line length")
                    result = true
                    break
                end
                if not all_invisible_chars_are_utf8(line) then
                    self.EncryptedMods[modname] = true
                    print(filename, modname, " is encrypted! by invalid utf8", line)
                    result = true
                    break
                end

                limit = limit - 1
                if limit <= 0 then
                    break
                end
            end
            fp:close()
            return result
        end

        local MODS_ROOT = "../mods/"
        for i, modname in ipairs(ModDirectoryNames) do
            local ok, isencrypted = pcall(check_encrypted, MODS_ROOT .. modname .. "/modmain.lua", modname)
            if ok and not isencrypted then
                pcall(check_encrypted, MODS_ROOT .. modname .. "/modworldgenmain.lua", modname)
            end
            local modinfo = KnownModIndex:GetModInfo(modname)
            if modinfo and modinfo.luajit_compatible then
                local luajit_compatible = modinfo.luajit_compatible
                if luajit_compatible == true then
                    self.EncryptedMods[modname] = nil
                elseif type(luajit_compatible) == "table" then
                    self.EncryptedMods[modname] = luajit_compatible.dep_tailcall
                end
            end
        end
        luajit_encryptmods:write_file(EncryptedModManager)
    end

    if AutoDetectEncryptedMod then
        InitEncryptedModManager()
    end
    return EncryptedModManager
end

local function ApplySlowTailCall(ctx, encrypted_mods)
    local AnyModDisableTailCall = get_config(ctx, "AnyModDisableTailCall")
    if not get_config(ctx, "SlowTailCall") then
        return
    end
    local mods_table = {}
    if AnyModDisableTailCall then
        mods_table["__any__"] = true
    else
        for modname, _ in pairs(encrypted_mods or {}) do
            mods_table[modname] = true
        end
    end
    debug.getregistry()["LJ_DS_slowtailcall_mods"] = mods_table
end

local function ForceDisableTailCall(ctx)
    if not (ctx and ctx.has_luajit) then
        return
    end
    if get_config(ctx, "ForceDisableTailCall") then
        local jit_table = ctx.jit
        if jit_table and jit_table.disabletailcall then
            jit_table.disabletailcall(true)
        elseif jit and jit.disabletailcall then
            jit.disabletailcall(true)
        end
    end
end

-- EnableFrostxxMods is a compile-time switch in former modmain (default false).
local EnableFrostxxMods = false

return {
    id = "jit.tailcall",
    version = "1.0.0",
    depends = {},
    soft_depends = {},
    conflicts = {},
    phases = "AfterModMain",
    options = {
        any_of = {
            "SlowTailCall",
            "ForceDisableTailCall",
            "AutoDetectEncryptedMod",
        },
    },
    support_reload = false,
    priority = 10,
    when = function(ctx)
        if not ctx or not ctx.has_luajit then
            return false
        end
        return true
    end,
    load = function(ctx)
        ForceDisableTailCall(ctx)

        local EncryptedModManager = GetEncryptedModManager(ctx)
        if ctx then
            ctx.encrypted_mod_manager = EncryptedModManager
            -- frostxx decrypt path only when compile-time flag is on
            if EnableFrostxxMods then
                ctx.frostxx_mods = EncryptedModManager.frostxxMods or {}
            else
                ctx.frostxx_mods = {}
            end
        end

        ApplySlowTailCall(ctx, EncryptedModManager.EncryptedMods)
    end,
    unload = function(ctx)
        -- Sticky by default.
    end,
}
