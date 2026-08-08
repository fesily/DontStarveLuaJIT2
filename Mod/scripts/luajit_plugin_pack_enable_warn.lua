-- Client-only: confirm before enabling external mods with luajit_plugin_pack=true.
-- Confirm → original enable path; Cancel → leave disabled.

local THIS_MODNAME = modname

local function translate(t)
    local lc = (LOC and LOC.GetLocaleCode and LOC.GetLocaleCode()) or ""
    t.zhr = t.zh
    t.zht = t.zht or t.zh
    return t[lc] or t.en
end

local function should_warn(modname_to_enable)
    if type(modname_to_enable) ~= "string" or modname_to_enable == "" then
        return false
    end
    if THIS_MODNAME and modname_to_enable == THIS_MODNAME then
        return false
    end
    if type(KnownModIndex) ~= "table" or type(KnownModIndex.GetModInfo) ~= "function" then
        return false
    end
    -- Only when enabling (currently disabled).
    if type(KnownModIndex.IsModEnabled) == "function" and KnownModIndex:IsModEnabled(modname_to_enable) then
        return false
    end
    local ok, info = pcall(function()
        return KnownModIndex:GetModInfo(modname_to_enable)
    end)
    if not ok or type(info) ~= "table" then
        return false
    end
    return info.luajit_plugin_pack and true or false
end

local function warn_copy()
    local title = translate({
        zh = "启用 LuaJIT 插件包",
        en = "Enable LuaJIT plugin pack",
    })
    local body = translate({
        zh = "该模组标记为 LuaJIT 原生插件包（luajit_plugin_pack），可能向游戏进程加载本机代码（DLL/SO）。\n\n"
            .. "请仅启用你信任的来源。EarlyNative 钩子可能需要完全重启游戏后才生效。\n\n"
            .. "确定要启用吗？",
        en = "This mod is marked as a LuaJIT native plugin pack (luajit_plugin_pack) and may load native code (DLL/SO) into the game process.\n\n"
            .. "Only enable packs you trust. EarlyNative hooks may require a full game restart to take effect.\n\n"
            .. "Enable this mod?",
    })
    return title, body
end

local function hook_modstab(ModsTab)
    if type(ModsTab) ~= "table" or ModsTab._luajit_pack_warn_hooked then
        return
    end
    ModsTab._luajit_pack_warn_hooked = true

    local old_enable = ModsTab.EnableCurrent
    if type(old_enable) ~= "function" then
        return
    end

    function ModsTab:EnableCurrent(widget_idx)
        local items_table = self.currentmodtype == "client" and self.optionwidgets_client or self.optionwidgets_server
        local modname_to_enable = nil
        if type(items_table) == "table" and items_table[widget_idx] and items_table[widget_idx].index then
            local idx = items_table[widget_idx].index
            if self.currentmodtype == "client" and self.modnames_client and self.modnames_client[idx] then
                modname_to_enable = self.modnames_client[idx].modname
            elseif self.modnames_server and self.modnames_server[idx] then
                modname_to_enable = self.modnames_server[idx].modname
            end
        elseif type(widget_idx) == "number" then
            -- Legacy non-redux ModsTab:EnableCurrent(idx)
            if self.currentmodtype == "client" and self.modnames_client and self.modnames_client[widget_idx] then
                modname_to_enable = self.modnames_client[widget_idx].modname
            elseif self.modnames_server and self.modnames_server[widget_idx] then
                modname_to_enable = self.modnames_server[widget_idx].modname
            end
        end

        if should_warn(modname_to_enable) then
            local PopupDialogScreen = require "screens/redux/popupdialog"
            local title, body = warn_copy()
            local self_ref = self
            local idx_ref = widget_idx
            print("[luajit][plugin-discover] enable_warn mod=" .. tostring(modname_to_enable) .. " shown")
            TheFrontEnd:PushScreen(PopupDialogScreen(title, body, {
                {
                    text = translate({ zh = "启用", en = "Enable" }),
                    cb = function()
                        TheFrontEnd:PopScreen()
                        print("[luajit][plugin-discover] enable_warn mod=" .. tostring(modname_to_enable) .. " confirmed")
                        return old_enable(self_ref, idx_ref)
                    end,
                },
                {
                    text = STRINGS.UI.MODSSCREEN.CANCEL or translate({ zh = "取消", en = "Cancel" }),
                    cb = function()
                        TheFrontEnd:PopScreen()
                        print("[luajit][plugin-discover] enable_warn mod=" .. tostring(modname_to_enable) .. " cancelled")
                    end,
                },
            }))
            return
        end
        return old_enable(self, widget_idx)
    end
end

local function try_hook()
    if not TheFrontEnd then
        return false
    end
    local candidates = {
        "widgets/redux/modstab",
        "widgets/modstab",
    }
    for _, path in ipairs(candidates) do
        local ok, mod = pcall(require, path)
        if ok and type(mod) == "table" then
            hook_modstab(mod)
        end
    end
    return true
end

-- Pure helper for unit tests
M = {
    should_warn = should_warn,
    set_this_modname = function(n)
        THIS_MODNAME = n
    end,
}

if TheNet and not TheNet:IsDedicated() then
    -- Install ASAP for frontend mods screen; also retry after front-end ready.
    pcall(try_hook)
    if AddGamePostInit then
        AddGamePostInit(function()
            pcall(try_hook)
        end)
    end
end

return M
