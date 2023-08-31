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

local jit = require 'jit'

AddSimPostInit(function()
    jit.on()
end)
