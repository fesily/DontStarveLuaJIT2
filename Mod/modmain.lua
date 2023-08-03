if 1 then
    return
end
local fenv = GLOBAL.getfenv()
GLOBAL.setmetatable(fenv, { __index = GLOBAL })
if rawget(GLOBAL, "jit") then
    return
end
local _G = GLOBAL
local IsWin32 = _G.IsWin32()
local TheFrontEnd = _G.TheFrontEnd
local STRINGS = _G.STRINGS
local RequestShutdown = _G.RequestShutdown
local PopupDialogScreen = require "screens/popupdialog"

--install dlls

modassert(IsWin32, "ONLY WIN32 NOW")
local newer = function(path)
    path = MODROOT .. "bin64/" .. path .. "/"

    ---@return file*
    local function create_handler(path, fn)
        local old_input = fn()
        fn(path)
        local input = fn()
        fn(old_input)
        return input
    end

    return function(filename)
        local input = create_handler(path .. filename, io.input)
        local output = create_handler("../bin64/" .. filename, io.output)
        local allInputs = input:read("*a")
        output:write(allInputs)
        input:close()
        output:close()
    end
end
local installer = newer(IsWin32 and "Windows" or "other")
installer("lua51.DLL")
installer("lua51DS.DLL")
installer("Winmm.DLL")

TheFrontEnd:PushScreen(
    PopupDialogScreen(
        STRINGS.UI.MAINSCREEN.ASKQUIT,
        "安装成功，需要重启游戏！\nInstaller success,need restart game!",
        {
            {
                text = STRINGS.UI.MAINSCREEN.YES,
                cb = function()
                    RequestShutdown()
                end
            }
        }
    )
)
