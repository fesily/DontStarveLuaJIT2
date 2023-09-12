_G = GLOBAL

if not _G.rawget(_G, "jit") then
    modimport "installer"
    _G.TheSim:Quit()
    return
end

_G.os.remove("luajit.mutex")

local TEMPLATES = require "widgets/redux/templates"
local old_getbuildstring = TEMPLATES.GetBuildString
TEMPLATES.GetBuildString = function()
    return (old_getbuildstring() or "") .. "(LuaJIT)"
end

if GetModConfigData("EnabledJIT") then
    local jit = require 'jit'

    if GetModConfigData("JitOpt") then
        require("jit.opt").start("minstitch=2", "maxtrace=4000",
        "maxrecord=8000", "sizemcode=64",
        "maxmcode=4000", "maxirconst=1000")
    end

    if GetModConfigData("ModBlackList") then

    end

    AddSimPostInit(function()
        jit.on()
        --TODO : add jit blacklists scripts/mods
    end)
end
