local modinfo = env.modinfo
local modname = env.modname
local KnownModIndex = _G.KnownModIndex
local rawget = _G.rawget
local type = _G.type
local LOC = _G.LOC

local server_folder_name = string.find(modname, "workshop%-") and "DontStarveLuaJIT2-Server" or "DontStarveLuaJIT2-GitHub-Server"

local locale = LOC.GetLocaleCode()
local lc = locale
local function translate(t)
    t.zhr = t.zh
    t.zht = t.zht or t.zh
    return t[lc] or t.en
end

local function is_locked(name)
    if (name ~= modname and name ~= server_folder_name) or KnownModIndex.badload then return false end
    local mods = KnownModIndex.savedata.known_mods
    local owner, row = mods[modname], mods[name]
    return owner ~= nil and type(owner.modinfo) == "table"
        and not owner.disabled_bad and not owner.disabled_incompatible_with_mode and not owner.modinfo.failed and owner.enabled
        and row ~= nil and type(row.modinfo) == "table"
        and not row.disabled_bad and not row.disabled_incompatible_with_mode and not row.modinfo.failed and row.enabled
end

local old_Disable = KnownModIndex.Disable
function KnownModIndex:Disable(name, ...)
    if not self.startingup and is_locked(name) then return end
    return old_Disable(self, name, ...)
end

AddClassPostConstruct("widgets/redux/modstab", function(self)
    local old_OnConfirmEnable = self.OnConfirmEnable
    function self:OnConfirmEnable(restart, name, ...)
        if is_locked(name) then return end
        return old_OnConfirmEnable(self, restart, name, ...)
    end

    for _, widget in pairs(self.mods_scroll_list:GetListWidgets()) do
        local opt = widget.moditem
        local old_SetModEnabled = opt.SetModEnabled
        function opt:SetModEnabled(enabled)
            old_SetModEnabled(self, enabled)
            if widget.data and widget.data.mod and is_locked(widget.data.mod.modname) then
                self.checkbox.image_disabled = self.checkbox.image_normal
                self.checkbox:SetHoverText(translate({zh = "已锁定，如需禁用请卸载Luajit", en = "Locked，please uninstall Luajit to disable"}))
                self.checkbox:SetImageDisabledColour(.5, .5, .5, 1)
                self.checkbox:Disable()
            else
                self.checkbox:ClearHoverText()
                self.checkbox:Enable()
                self.checkbox.image:SetTint(1, 1, 1, 1)
            end
        end
    end
end)

--------------------------------------------------------------

-- 创建虚拟模组信息
local modinfo_luajit_server = {
    name = modinfo.name, -- 名称
    description = modinfo.description, -- 介绍
    configuration_options = modinfo.configuration_options, -- 配置
    version = modinfo.version, -- 版本
    version_compatible = modinfo.version_compatible, -- 兼容的版本号
    author = modinfo.author, -- 作者
    api_version = modinfo.api_version, -- api版本

    dst_compatible = modinfo.dst_compatible, -- 兼容联机版
    forge_compatible = modinfo.forge_compatible, -- 兼容熔炉
    gorge_compatible = modinfo.gorge_compatible, -- 兼容暴食
    dont_starve_compatible = modinfo.dont_starve_compatible, -- 不兼容单机版

    all_clients_require_mod = false, -- 所有人需要下载
    client_only_mod = false, -- 客户端模组
    server_only_mod = true, -- 服务器模组

    server_filter_tags = modinfo.server_filter_tags, -- 服务器Tag

    folder_name = server_folder_name,
    locale = modinfo.locale,
    modinfo_message = "",

    icon_atlas = MODROOT .. "modicon.xml",
    iconpath = MODROOT .. "modicon.tex",
    icon = "modicon.tex",

    default_enabled = true,
	force_enabled_server_mod = true, -- 强制开启服务端模组
}

-- 必须立刻处理而不是等到游戏初始化后处理，否则太迟了，会引起网络变量不同步问题
if rawget(_G, "BBGOAT_utils") then -- 兼容【冰冰羊的模组运行库】
    local MOD_util = _G.BBGOAT_utils.MOD_util
    MOD_util:AddConversionMod(modname, modinfo_luajit_server)
else
    local function Import(file_name)
        local f = _G.kleiloadlua(file_name)
        _G.setfenv(f, env)
        return f()
    end
    local AddConversionMod = Import(MODROOT .. "inject_server_only_mod.lua")
    AddConversionMod(modname, modinfo_luajit_server)
end