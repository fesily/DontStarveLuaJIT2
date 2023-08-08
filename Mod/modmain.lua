local _G = GLOBAL
if not _G.rawget(_G, "jit") then
    local PopupDialogScreen = require "screens/popupdialog"

    _G.TheFrontEnd:PushScreen(
        PopupDialogScreen(
            "Warning",
            "LuaJIT模块没有加载\nLuaJIT MOD is not installed!",
            {
                {
                    text = _G.STRINGS.UI.MAINSCREEN.YES,
                    cb = function()
                        _G.TheFrontEnd:PopScreen()
                    end
                }
            }
        )
    )
    return
end

AddGamePostInit(function()
    _G.STRINGS.UI.MAINSCREEN.MODTITLE = "LuaJIT:" .. _G.STRINGS.UI.MAINSCREEN.MODTITLE
end)
