if not _G.rawget(_G, "GameLuaInjector") then return end

local modname = env.modname
local server_modname = modname:find("workshop-", 1, true) and "DontStarveLuaJIT2-Server" or "DontStarveLuaJIT2-GitHub-Server"
local index = _G.KnownModIndex

local function is_locked(name)
    if (name ~= modname and name ~= server_modname) or index.badload then return false end
    local mods = index.savedata.known_mods
    local owner, row = mods[modname], mods[name]
    return owner ~= nil and type(owner.modinfo) == "table"
        and not owner.disabled_bad and not owner.disabled_incompatible_with_mode and not owner.modinfo.failed
        and row ~= nil and type(row.modinfo) == "table"
        and not row.disabled_bad and not row.disabled_incompatible_with_mode and not row.modinfo.failed
end

local function enable_server_mod()
    if is_locked(server_modname) then
        local row = index.savedata.known_mods[server_modname]
        row.enabled = true
        row.temp_disabled = false
    end
end

-- 崩溃/不兼容禁用使用原版的独立方法，仍允许游戏恢复；虚拟条目仍可正常清理。
local old_Disable = index.Disable
function index:Disable(name, ...)
    if name == modname and not self.startingup and is_locked(name) then return end
    return old_Disable(self, name, ...)
end

local old_TempDisable = index.TempDisable
function index:TempDisable(name, ...)
    if name == modname and is_locked(name) then return end
    return old_TempDisable(self, name, ...)
end

enable_server_mod()
if _G.TheNet:IsDedicated() then return end

AddClassPostConstruct("widgets/redux/modstab", function(self)
    local old_OnConfirmEnable = self.OnConfirmEnable
    function self:OnConfirmEnable(restart, name, ...)
        if is_locked(name) then return end
        return old_OnConfirmEnable(self, restart, name, ...)
    end
    local old_EnableCurrent = self.EnableCurrent
    function self:EnableCurrent(widget_idx, ...)
        local items = self.currentmodtype == "client" and self.optionwidgets_client or self.optionwidgets_server
        local data = items[widget_idx]
        if data and is_locked(data.mod.modname) then return end
        return old_EnableCurrent(self, widget_idx, ...)
    end

    -- SetModEnabled 在原版和 Lazy Controls 的行刷新中都会调用，不依赖 SetMod 的实现。
    for _, widget in pairs(self.mods_scroll_list:GetListWidgets()) do
        local opt = widget.moditem
        local old_SetModEnabled = opt.SetModEnabled
        function opt:SetModEnabled(enabled)
            old_SetModEnabled(self, enabled)
            if widget.data and widget.data.mod and is_locked(widget.data.mod.modname) then
                self.checkbox.image_disabled = self.checkbox.image_normal
                self.checkbox:SetImageDisabledColour(.5, .5, .5, 1)
                self.checkbox:Disable()
            else
                self.checkbox:Enable()
                self.checkbox.image:SetTint(1, 1, 1, 1)
            end
        end
        local old_GetHelpText = opt.GetHelpText
        opt.GetHelpText = function(...)
            if widget.data and widget.data.mod and is_locked(widget.data.mod.modname) then return "" end
            return old_GetHelpText(...)
        end
        if widget.data and widget.data.mod then
            opt:SetModEnabled(index:IsModEnabled(widget.data.mod.modname))
        end
    end

    -- 读取旧存档或全部禁用之后，在刷新/保存名单前恢复虚拟服务器条目。
    for _, method in ipairs({ "UpdateModsOrder", "Apply" }) do
        local original = self[method]
        self[method] = function(self, ...)
            if self.settings.is_configuring_server then enable_server_mod() end
            return original(self, ...)
        end
    end
end)

AddClassPostConstruct("screens/redux/servercreationscreen", function(self)
    local old_Create = self.Create
    function self:Create(...)
        enable_server_mod()
        return old_Create(self, ...)
    end
end)
