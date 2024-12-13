_G = GLOBAL

if not _G.TheNet:IsDedicated() then
    local fp = _G.io.open("luajit_config.json", "w");
    if fp then
        local config = {
            modmain_path = _G.debug.getinfo(1).source,
            server_disable_luajit = GetModConfigData("DisableJITWhenServer");
        }
        fp:write(_G.json.encode(config))
    end
end



if GetModConfigData("EnabledJIT") then
    local hasluajit, jit = _G.pcall(require, 'jit')
    if not hasluajit then
        return
    end
    local TEMPLATES = require "widgets/redux/templates"
    local old_getbuildstring = TEMPLATES.GetBuildString
    TEMPLATES.GetBuildString = function()
        return (old_getbuildstring() or "") .. "(LuaJIT)"
    end

    if GetModConfigData("JitOpt") then
        require("jit.opt").start("minstitch=2", "maxtrace=4000",
            "maxrecord=8000", "sizemcode=64",
            "maxmcode=4000", "maxirconst=1000")
    end

    local enbaleBlackList = GetModConfigData("ModBlackList")

    AddSimPostInit(function()
        jit.on()

        local prefix = "../mods/workshop-"
        local blacklists = {
        }
        if enbaleBlackList and #blacklists > 0 then
            for i in ipairs(blacklists) do
                blacklists[i] = prefix .. blacklists[i]
            end
            local function startWith(str, prefix)
                return str:find(prefix, 1, true) == 1
            end
            local _kleiloadlua = _G.kleiloadlua
            _G.kleiloadlua = function(script, ...)
                local m = _kleiloadlua(script, ...)
                if (type(script) == "string") then
                    for _, blacklist in ipairs(blacklists) do
                        if startWith(script, blacklist) then
                            jit.off(m, true)
                            break
                        end
                    end
                end
                return m
            end
        end
    end)
end
