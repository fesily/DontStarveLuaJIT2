-- 代码复制自【冰冰羊的模组运行库】，未开启运行库模组时加载

local AddClassPostConstruct = AddClassPostConstruct
_G.setfenv(1, _G)

local client_mod_list = {}
local mod_name_list = {}

---@param modname string 模组ID
---@param modinfo table 虚拟服务器模组信息
local function AddConversionMod(modname, modinfo)
    local default_enabled = modinfo.default_enabled
    if default_enabled == nil then
        default_enabled = true
    end

    modinfo.folder_name = modinfo.folder_name or (modname .. "-server")

    local moddata = {
        modinfo = modinfo,
        seen_api_version = 10,
        temp_disabled = false,
        temp_enabled = false,
        disabled_bad = false,
        disabled_incompatible_with_mode = false,
        enabled = default_enabled
    }

    client_mod_list[modname] = moddata
    mod_name_list[modinfo.folder_name] = modname

    -- 初始化模组信息
    if not (KnownModIndex.savedata and KnownModIndex.savedata.known_mods and KnownModIndex.savedata.known_mods[modinfo.folder_name]) then
        moddata.enable_flag = true
        KnownModIndex.forceddirs[modinfo.folder_name] = true
        KnownModIndex.savedata = KnownModIndex.savedata or {}
        KnownModIndex.savedata.known_mods = KnownModIndex.savedata.known_mods or {}
        KnownModIndex.savedata.known_mods[modinfo.folder_name] = deepcopy(moddata)
    end
end

-- 处理Mod信息
local old_InitializeModInfo = KnownModIndex.InitializeModInfo
KnownModIndex.InitializeModInfo = function(self, modname, ...)
    local client_modname = mod_name_list[modname]
    if client_mod_list[client_modname] and client_mod_list[client_modname].enable_flag and modname == client_mod_list[client_modname].modinfo.folder_name then
        return deepcopy(client_mod_list[client_modname].modinfo)
    end
    return old_InitializeModInfo(self, modname, ...)
end

-- 处理Mod图标
local old_LoadModInfo = KnownModIndex.LoadModInfo
KnownModIndex.LoadModInfo = function(self, modname, prev_info, ...)
    local info = old_LoadModInfo(self, modname, prev_info, ...)
    local client_modname = mod_name_list[modname]
    if type(info) == "table" and client_mod_list[client_modname] and modname == client_mod_list[client_modname].modinfo.folder_name then
        info.icon_atlas = client_mod_list[client_modname].modinfo.icon_atlas
        info.iconpath = client_mod_list[client_modname].modinfo.iconpath
        info.icon = client_mod_list[client_modname].modinfo.icon
    end
    return info
end

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

local old_GetEnabledServerModNames = _G.ModManager.GetEnabledServerModNames
_G.ModManager.GetEnabledServerModNames = function(self, ...)
    local server_mods = old_GetEnabledServerModNames(self, ...)
    if _G.IsNotConsole() then
        for modname, moddata in pairs(client_mod_list) do
            if KnownModIndex:IsModEnabled(modname) then
                for k,v in pairs(server_mods) do
                    if v == moddata.modinfo.folder_name then
                        server_mods[k] = modname -- 客户端在创建世界设置服务器模组时需要使用这个来替换为原模组（同时将 ShardIndex:GetEnabledServerMods 获取到的虚拟服务端模组替换回原模组 ）
                        break
                    end
                end
            else -- 客户端模组被关闭，服务器虚拟模组也跟着关
                for k,v in pairs(server_mods) do
                    if v == moddata.modinfo.folder_name or v == modname then
                        server_mods[k] = nil
                    end
                end
            end
        end
    end
    return server_mods
end

local default_get_mode = true
local function get(modname)
    local a, b = modname, client_mod_list[modname].modinfo.folder_name
    if default_get_mode then
        return a,b
    else
        return b,a
    end
end

local old_GetEnabledServerMods = _G.ShardIndex.GetEnabledServerMods
_G.ShardIndex.GetEnabledServerMods = function(self, ...)
    local enabled_mods = old_GetEnabledServerMods(self, ...)
    if type(enabled_mods) ~= "table" then return enabled_mods end

    for modname, moddata in pairs(client_mod_list) do
        local a, b = get(modname)
        if KnownModIndex:IsModEnabled(modname) then
            if enabled_mods[a] ~= nil and enabled_mods[b] == nil then
                enabled_mods[b], enabled_mods[a] = enabled_mods[a], nil
            end
        else -- 客户端模组被关闭，服务器也跟着关
            enabled_mods[a] = nil
            enabled_mods[b] = nil
        end
    end

    return enabled_mods
end

local HookServerCreationScreen = function(self)
    local old_Create = self.Create
    self.Create = function(self, warnedOffline, warnedDisabledMods, warnedOutOfDateMods, ...)
        local temp_client_modconfiglist = {}
        for modname, moddata in pairs(client_mod_list) do
            local server_folder_name = moddata.modinfo.folder_name
            if KnownModIndex:IsModEnabled(modname) then -- 检查客户端模组是否还开着
                temp_client_modconfiglist[modname] = deepcopy(KnownModIndex:LoadModConfigurationOptions(modname)) -- 读取客户端的配置；使用deepcopy，因为函数返回的值是一个table表 默认方法是引用而不是复制
                local server_modconfig = deepcopy(KnownModIndex:LoadModConfigurationOptions(server_folder_name))-- 读取服务器的配置
                KnownModIndex:SaveConfigurationOptions(function() end, modname, server_modconfig, false) -- 将服务器的设置存到客户端然后开服，这样玩家修改的服务器的设置就会生效
            else
                print(string.format("检测到客户端 %s 被关闭，取消启动 %s", moddata.modinfo.name, server_folder_name))
            end
        end
        default_get_mode = false
        old_Create(self, warnedOffline, warnedDisabledMods, warnedOutOfDateMods, ...) -- 启动服务器
        default_get_mode = true
        for modname, modconfig in pairs(temp_client_modconfiglist) do
            KnownModIndex:SaveConfigurationOptions(function() end, modname, modconfig, false) -- 启动后恢复客户端客户端的配置，避免服务器设置影响到客户端
        end
    end
end
-- HOOK 点击“回到世界”时的操作
AddClassPostConstruct("screens/redux/servercreationscreen", function(self)
    HookServerCreationScreen(self)
end)

-- 兼容独行长路
local old_FrontendLoadMod = ModManager.FrontendLoadMod
ModManager.FrontendLoadMod = function(self, modname, ...)
	old_FrontendLoadMod(self, modname, ...)
	if modname == "workshop-2657513551" then -- 独行长路
		if rawget(_G, "TheFrontEnd") ~= nil then
			-- 延迟0.1秒，等待ServerCreationScreen和独行长路加载完毕
			scheduler:ExecuteInTime(0.1, function()
				for _, screen in ipairs(_G.TheFrontEnd.screenstack) do
					if screen.name == "ServerCreationScreen" then
						if not screen.bbgoat_util_compatibility_dsa_hooked_flag then
							HookServerCreationScreen(screen) -- 重新HOOK 点击“回到世界”时的操作
							screen.bbgoat_util_compatibility_dsa_hooked_flag = true
						end
						break
					end
				end
			end)
		end
	end
end

local function ChangeModname()
    if ShardSaveGameIndex and type(ShardSaveGameIndex.slot_cache) == "table" then
        for slot, shards in pairs(ShardSaveGameIndex.slot_cache) do
            for shardName, shardIndex in pairs(shards) do
                for modname, moddata in pairs(client_mod_list) do
                    if shardIndex.enabled_mods and shardIndex.enabled_mods[modname] then
                        -- print(string.format("看起来 存档%s(%s) 世界%s 开启了 %s 将其转换为 %s 以供下次使用", slot, shardIndex.server and shardIndex.server.name or "未知存档名称", shardName, moddata.modinfo.name, moddata.modinfo.folder_name))
                        if shardIndex:IsValid() then
                            if shardIndex.enabled_mods[modname] then -- 被 ShardIndex:GetEnabledServerMods 函数从客户端模组修改为服务器模组前 （没有点击过创建世界按钮）
                                shardIndex.enabled_mods[moddata.modinfo.folder_name], shardIndex.enabled_mods[modname] = shardIndex.enabled_mods[modname], nil
                                shardIndex.invalid = false
                                shardIndex.isdirty = true
                                shardIndex:Save()
                            end
                        -- else
                            -- print(string.format("看起来 存档%s 世界%s 不是一个有效的shardIndex...？", slot, shardName))
                        end
                    elseif shardIndex.enabled_mods and moddata.modinfo.force_enabled_server_mod and not shardIndex.enabled_mods[moddata.modinfo.folder_name] then
                        -- print(string.format("看起来 存档%s(%s) 世界%s 没有开启 %s ，强制开启 %s 以供下次使用", slot, shardIndex.server and shardIndex.server.name or "未知存档名称", shardName, moddata.modinfo.name, moddata.modinfo.folder_name))
                        if shardIndex:IsValid() then
                            shardIndex.enabled_mods[moddata.modinfo.folder_name] = {
                                configuration_options = {},
                                enabled = true,
                            }
                            shardIndex.invalid = false
                            shardIndex.isdirty = true
                            shardIndex:Save()
                        -- else
                        --     print(string.format("看起来 存档%s 世界%s 不是一个有效的shardIndex...？", slot, shardName))
                        end
                    end
                end
            end
        end
    end
end

-- 登录后处理一次
AddClassPostConstruct("screens/redux/multiplayermainscreen", function(self)
    ChangeModname()
end)

return AddConversionMod