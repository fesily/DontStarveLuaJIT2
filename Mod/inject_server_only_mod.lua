local modinfo = env.modinfo
local modname = env.modname
local KnownModIndex = _G.KnownModIndex
local ModManager = _G.ModManager
local scheduler = _G.scheduler
local rawget = _G.rawget

local server_folder_name = string.find(modname, "workshop-") and "DontStarveLuaJIT2-Server" or "DontStarveLuaJIT2-GitHub-Server"

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
}

local moddata_luajit_server = {
    modinfo = modinfo_luajit_server,
    seen_api_version = 10,
    temp_disabled = false,
    temp_enabled = false,
    disabled_bad = false,
    disabled_incompatible_with_mode = false,
    enabled = true --[[
    说明：
    对于客户端：
        创建新档时是否默认勾选服务器端Luajit模组，进入已有存档/其它服务器时设置会被覆盖
    对于服务器(初始化时)：
        如果为true 开启DontStarveLuaJIT2-Server 然后下面的代码将 DontStarveLuaJIT2-Server 转换为 workshop-3444078585 服务器模组列表将显示服务器开启了DontStarveLuaJIT2
        如果为false 不开启DontStarveLuaJIT2-Server 下面的代码也不会触发并转换 所以服务器大厅显示的本服务器模组列表也不会有workshop-3444078585 但不影响模组的实际运行
    ]]
}

local enable_luajit_server
if not (KnownModIndex.savedata and KnownModIndex.savedata.known_mods and KnownModIndex.savedata.known_mods[server_folder_name]) then
    enable_luajit_server = true
    KnownModIndex.forceddirs[server_folder_name] = true
    KnownModIndex.savedata = KnownModIndex.savedata or {}
    KnownModIndex.savedata.known_mods = KnownModIndex.savedata.known_mods or {}
    KnownModIndex.savedata.known_mods[server_folder_name] = _G.deepcopy(moddata_luajit_server)
end

-- 处理Mod信息
local old_InitializeModInfo = KnownModIndex.InitializeModInfo
KnownModIndex.InitializeModInfo = function(self, modname, ...)
    if enable_luajit_server and modname == server_folder_name then
        return _G.deepcopy(modinfo_luajit_server)
    end
    return old_InitializeModInfo(self, modname, ...)
end

-- 处理Mod图标
local luajit_icon_atlas = _G.MODS_ROOT .. modname .. "/modicon.xml"
local luajit_iconpath = string.gsub(luajit_icon_atlas, "/[^/]*$", "") .. "/modicon.tex"
local luajit_icon = "modicon.tex"
local old_LoadModInfo = KnownModIndex.LoadModInfo
KnownModIndex.LoadModInfo = function(self, modname, prev_info, ...)
    local info = old_LoadModInfo(self, modname, prev_info, ...)
    if type(info) == "table" and modname == server_folder_name then
        info.icon_atlas = luajit_icon_atlas
        info.iconpath = luajit_iconpath
        info.icon = luajit_icon
    end
    return info
end

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

local old_GetEnabledServerModNames = _G.ModManager.GetEnabledServerModNames
_G.ModManager.GetEnabledServerModNames=function(self, ...)
    local server_mods = old_GetEnabledServerModNames(self, ...)
    if _G.IsNotConsole() then
        if KnownModIndex:IsModEnabled(modname) then
            for k,v in pairs(server_mods) do
                if v == server_folder_name then
                    server_mods[k] = modname
                    break
                end
            end
        else -- 客户端Luajit被关闭，服务器也跟着关
            for k,v in pairs(server_mods) do
                if v == server_folder_name or v == modname then
                    server_mods[k] = nil
                end
            end
        end
    end
    return server_mods
end

local a, b = modname, server_folder_name
local old_GetEnabledServerMods = _G.ShardIndex.GetEnabledServerMods
_G.ShardIndex.GetEnabledServerMods = function(self, ...)
    local enabled_mods = old_GetEnabledServerMods(self, ...)
    if type(enabled_mods) ~= "table" then return enabled_mods end

    if KnownModIndex:IsModEnabled(modname) then
        if enabled_mods[a] ~= nil and enabled_mods[b] == nil then
            enabled_mods[b], enabled_mods[a] = enabled_mods[a], nil
        end
    else -- 客户端Luajit被关闭，服务器也跟着关
        enabled_mods[modname] = nil
        enabled_mods[server_folder_name] = nil
    end

    return enabled_mods
end

-- HOOK 点击“回到世界”时的操作
local function HookServerCreationScreen(self)
    local old_Create = self.Create
    self.Create = function(self, warnedOffline, warnedDisabledMods, warnedOutOfDateMods, ...)
        if KnownModIndex:IsModEnabled(modname) then -- 检查客户端Luajit是否还开着
            local client_modconfig = _G.deepcopy(KnownModIndex:LoadModConfigurationOptions(modname)) -- 读取客户端 Luajit 的配置
            local server_modconfig = _G.deepcopy(KnownModIndex:LoadModConfigurationOptions(server_folder_name))-- 读取服务器 Luajit 的配置

            KnownModIndex:SaveConfigurationOptions(function() end, modname, server_modconfig, false) -- 将服务器Luajit的设置存到客户端Luajit，然后开服，这样玩家修改的服务器Luajit设置就会生效
            a, b = b, a -- 启动服务器前，将模组启用名单中的 DontStarveLuaJIT2-Server 替换为本体 DontStarveLuaJIT2
            old_Create(self, warnedOffline, warnedDisabledMods, warnedOutOfDateMods, ...) -- 启动服务器
            a, b = b, a
            KnownModIndex:SaveConfigurationOptions(function() end, modname, client_modconfig, false) -- 启动后恢复客户端 Luajit 的配置，避免服务器设置影响到客户端
        else -- 客户端Luajit未开启，正常启动服务器
            old_Create(self, warnedOffline, warnedDisabledMods, warnedOutOfDateMods, ...)
        end
    end
end

AddClassPostConstruct("screens/redux/servercreationscreen", function(self)
    HookServerCreationScreen(self)
end)

local function ChangeModname()
    if ShardSaveGameIndex and type(ShardSaveGameIndex.slot_cache) == "table" then
        for slot, shards in pairs(ShardSaveGameIndex.slot_cache) do
            for shardName, shardIndex in pairs(shards) do
                if shardIndex.enabled_mods and shardIndex.enabled_mods[modname] then
                    -- print(string.format("看起来 存档%s(%s) 世界%s 开启了 %s 将其转换为 %s 以供下次使用", slot, shardIndex.server and shardIndex.server.name or "未知存档名称", shardName, modinfo.name, server_folder_name))
                    if shardIndex:IsValid() then
                        if shardIndex.enabled_mods[modname] then
                            shardIndex.enabled_mods[server_folder_name], shardIndex.enabled_mods[modname] = shardIndex.enabled_mods[modname], nil
                            shardIndex.invalid = false
                            shardIndex.isdirty = true
                            shardIndex:Save()
                        end
                    else
                        -- print(string.format("看起来 存档%s 世界%s 不是一个有效的shardIndex...？", slot, shardName))
                    end
                end
            end
        end
    end
end

AddClassPostConstruct("screens/redux/multiplayermainscreen", function(self)
    ChangeModname()
end)

-- 兼容独行长路
-- 独行长路会覆盖servercreationscreen的Create方法，所以需要在独行长路加载后二次修改Create方法
local old_FrontendLoadMod = ModManager.FrontendLoadMod
ModManager.FrontendLoadMod = function(self, modname, ...)
    old_FrontendLoadMod(self, modname, ...)
	if modname == "workshop-2657513551" then
		if rawget(GLOBAL, "TheFrontEnd") ~= nil then
			-- 延迟0.1秒，等待ServerCreationScreen和独行长路加载完毕
			scheduler:ExecuteInTime(0.1, function()
				for _, screen in ipairs(GLOBAL.TheFrontEnd.screenstack) do
					if screen.name == "ServerCreationScreen" then
						if not screen.luajit_compatibility_dsa_hooked_flag then
							HookServerCreationScreen(screen)
							screen.luajit_compatibility_dsa_hooked_flag = true
						end
						break
					end
				end
			end)
		end
	end
end