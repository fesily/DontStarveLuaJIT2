_G = GLOBAL
local function main()
	local function should_show_dig()
		if TheNet:GetIsServer() and TheNet:GetServerIsDedicated() then
			return false
		end
		if not TheFrontEnd then
			return false
		end
		if IsMigrating() then
			return false
		end
		return not InGamePlay()
	end
	local hasluajit, jit = _G.pcall(require, "jit")

	local luajit_config_path = "unsafedata/luajit_config.json"
	local luajit_crash_path = "unsafedata/luajit_crash.json"


	local function read_config_file()
		local fp = io.open(luajit_config_path, "r")
		if fp then
			local str = fp:read("*a")
			fp:close()
			return json.decode(str)
		end
	end

	local function clean_crash_file()
		local fp = io.open(luajit_crash_path, "w")
		if fp then
			fp:close()
		end
	end

	local function is_crash()
		local fp = io.open(luajit_crash_path, "r")
		if fp then
			local content = fp:read("*a")
			fp:close()
			return content and #content ~= 0
		end
		return false
	end

	if not hasluajit then
		if should_show_dig() then
			AddGamePostInit(function()
				local PopupDialogScreen = require "screens/popupdialog"
				local locale = LOC.GetLocaleCode()
				local lc = locale
	
				local function translate(t)
					t.zhr = t.zh
					t.zht = t.zht or t.zh
					return t[lc] or t.en
				end
				-- check crash
				if is_crash() then
					TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.RESTART_TITLE, translate({
							zh = "检测luajit未成功加载,是否再次尝试?\n\n(还失败可能需要更新,请联系作者)",
							en =
							"Detected that luajit failed to load, do you want to try again?\n\n(If it fails again, it may need to be updated, please contact the author)"
						}),
						{
							{
								text = STRINGS.UI.MAINSCREEN.RESTART,
								cb = function()
									clean_crash_file()
									TheSim:Quit()
								end
							},
							{ text = STRINGS.UI.MAINSCREEN.OK, cb = function() TheFrontEnd:PopScreen() end }
						}))
				else
					TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MAINSCREEN.MODFAILTITLE, translate({
							zh = [[当前luajit模组未成功安装,前往该模组所在的文件夹,运行install.bat]],
							en =
							"The current luajit mod has not been successfully installed, please go to the folder where the luajit mod is located, and run install.bat/.sh to execute the installation"
						}),
						{
							{ text = STRINGS.UI.MAINSCREEN.OK, cb = function() TheFrontEnd:PopScreen() end }
						}))
				end
			end)
		end
		return
	end

	local function inject_server_only_mod()
		local old_GetServerModNames = KnownModIndex.GetServerModNames
		local old_GetServerModNamesTable = KnownModIndex.GetServerModNamesTable
		local old_GetEnabledServerModNames = ModManager.GetEnabledServerModNames

		KnownModIndex.GetServerModNames = function(self, ...)
			local names = old_GetServerModNames(self, ...)
			table.insert(names, modname)
			return names
		end

		KnownModIndex.GetServerModNamesTable = function(self, ...)
			local names = old_GetServerModNamesTable(self, ...)
			table.insert(names, { modname = modname })
			return names
		end
		ModManager.GetEnabledServerModNames = function(self, ...)
			local server_mods = old_GetEnabledServerModNames(self, ...)
			if IsNotConsole() then
				table.insert(server_mods, modname)
			end
			return server_mods
		end
	end

	local enabled_jit = GetModConfigData("EnabledJIT")
	local TEMPLATES = require("widgets/redux/templates")
	local old_getbuildstring = TEMPLATES.GetBuildString
	TEMPLATES.GetBuildString = function()
		return (old_getbuildstring() or "") .. "(LuaJIT)"
	end

	local jit_opt = require 'jit.opt'
	jit_opt.start("maxtrace=4000")
	if GetModConfigData("JitOpt") then
		jit_opt.start(
			"minstitch=2",
			"maxrecord=8000",
			"sizemcode=64",
			"maxmcode=4000",
			"maxirconst=1000"
		)
	end


	local ffi = require 'ffi'
	ffi.cdef [[
			int DS_LUAJIT_replace_profiler_api();
			void DS_LUAJIT_enable_tracy(int en);
			void DS_LUAJIT_enable_profiler(int en);
			void DS_LUAJIT_disable_fullgc(int mb);
			int DS_LUAJIT_set_frame_gc_time(int ms);
			const char* DS_LUAJIT_get_mod_version();
			const char* DS_LUAJIT_get_workshop_dir();
			int DS_LUAJIT_update(const char* mod_dictory, int tt);
			int DS_LUAJIT_set_target_fps(int fps, int tt);
			int DS_LUAJIT_replace_client_network_tick(char tick);
			const char* DS_LUAJIT_Fengxun_Decrypt(const char* filename);
		]]
	local injector = require 'luavm.ffi_load' ("Injector")

	local zone = require("jit.zone")
	local sim = getmetatable(TheSim).__index
	local old_profiler_push = sim.ProfilerPush
	local old_profiler_pop = sim.ProfilerPop
	rawset(_G, "ProfilerJitEx", {
		start = function(m)
			injector.DS_LUAJIT_enable_profiler(1)
		end,
		stop = function()
			injector.DS_LUAJIT_enable_profiler(0)
		end,
	})
	if GetModConfigData("EnableProfiler") == "on" then
		local profiler = require("jit.p")
		local mode = GetModConfigData("EnableProfiler")
		local enabled_profiler = false
		sim.ProfilerPush = function(self, name, ...)
			if enabled_profiler then
				zone(name)
			end
			old_profiler_push(self, name, ...)
		end
		sim.ProfilerPop = function(...)
			if enabled_profiler then
				zone()
			end
			old_profiler_pop(...)
		end
		rawset(_G, "ProfilerJit", {
			start = function(m)
				enabled_profiler = true
				profiler.start(m or mode, "unsafedata/profiler")
			end,
			stop = function()
				enabled_profiler = false
				profiler.stop()
			end,
		})
	end

	local enbaleBlackList = GetModConfigData("ModBlackList")
	local prefix = "../mods/workshop-"
	local blacklists = {}
	if true then
		for i in ipairs(blacklists) do
			blacklists[i] = prefix .. blacklists[i]
		end
		local function startWith(str, prefix)
			return str:find(prefix, 1, true) == 1
		end
		local frostxxMods = {}
		local _kleiloadlua = kleiloadlua
		local function decrypt_file(filename)
			local str = injector.DS_LUAJIT_Fengxun_Decrypt(filename)
			if str ~= nil then
				return loadstring(ffi.string(str), filename)
			end
		end
		local function isfrostxx(filename)
			for l in io.lines(filename) do
				if l:find("frostxx@qq.com", 1, true) then
					---@type string
					local left = filename:sub(#prefix + 1)
					local pos, id = left:find('(%d+)')
					if pos then
						frostxxMods[#frostxxMods + 1] = prefix .. left:sub(pos, id)
					end
					return true
				end
			end
			return false
		end
		rawset(_G, "kleiloadlua", function(filename, ...)
			for _, frostxxMod in ipairs(frostxxMods) do
				if startWith(filename, frostxxMod) then
					local fn = decrypt_file(filename)
					if fn then
						return fn
					end
				end
			end
			if filename:find("modmain.lua", 1, true) or filename:find("modworldgenmain.lua", 1, true) then
				local ok, needdecrypt = pcall(isfrostxx, filename)
				if ok and needdecrypt then
					filename = filename:gsub("modmain.lua", "modmain0.lua")
					filename = filename:gsub("modworldgenmain.lua", "modworldgenmain0.lua")
					local fn = decrypt_file(filename)
					if fn then
						return fn
					end
				end
			end

			local m = _kleiloadlua(filename, ...)
			if enbaleBlackList and type(m) == "function" and type(filename) == "string" and startWith(filename, prefix) then
				for _, blacklist in ipairs(blacklists) do
					if startWith(filename, blacklist) then
						jit.off(m, true)
						break
					end
				end
			end
			return m
		end)
	end
	AddSimPostInit(function()
		if enabled_jit then
			jit.on()
		end
	end)

	local modmain_path = debug.getinfo(1).source
	do
		local pos = modmain_path:find(prefix, 1, true)
		if pos ~= nil and pos == 1 then
			local workshop_id = modmain_path:sub(pos + #prefix)
			pos = workshop_id:find("/", 1, true)
			if pos ~= nil then
				workshop_id = workshop_id:sub(1, pos - 1)
			end
			-- maybe inworkshop
			local workshop_dir = injector.DS_LUAJIT_get_workshop_dir();
			if workshop_dir ~= nil then
				workshop_dir = ffi.string(workshop_dir)
				workshop_dir = workshop_dir .. "/" .. workshop_id .. "/"
				local fp = io.open(workshop_dir .. "install.bat", "r")
				if fp then
					fp:close()
					modmain_path = workshop_dir .. "modmain.lua"
				end
			end
		end
		if not TheNet:IsDedicated() then
			local fp = io.open(luajit_config_path, "w")
			if fp then
				local config = {
					modmain_path = modmain_path,
					server_disable_luajit = GetModConfigData("DisableJITWhenServer"),
					logic_fps = GetModConfigData("TargetLogincFPS"),
				}
				fp:write(json.encode(config))
				fp:close()
			end
		end
	end
	if GetModConfigData("EnableTracy") == "on" then
		injector.DS_LUAJIT_replace_profiler_api()
		injector.DS_LUAJIT_enable_tracy(1)
	end

	if GetModConfigData("DisableForceFullGC") ~= 0 then
		injector.DS_LUAJIT_disable_fullgc(tonumber(GetModConfigData("DisableForceFullGC")))
	end

	if GetModConfigData("EnbaleFrameGC") ~= 0 then
		injector.DS_LUAJIT_replace_profiler_api()
		injector.DS_LUAJIT_set_frame_gc_time(tonumber(GetModConfigData("EnbaleFrameGC")))
	end

	if GetModConfigData("TargetRenderFPS") then
		local targetfps = GetModConfigData("TargetRenderFPS")
		injector.DS_LUAJIT_set_target_fps(targetfps, 1)
		TheSim:SetNetbookMode(false);
	end

	if GetModConfigData("TargetLogincFPS") then
		local targetfps = GetModConfigData("TargetLogincFPS")
		if injector.DS_LUAJIT_set_target_fps(targetfps, 2) ~= targetfps then
			print("[luajit] diff logic fps, need restart")
			scheduler:ExecuteInTime(0, function ()
				c_reset()
			end)
		end
	end

	if GetModConfigData("ClientNetWorkTick") then
		local targetfps = GetModConfigData("ClientNetWorkTick")
		injector.DS_LUAJIT_replace_client_network_tick(targetfps)
	end
	local root_dictory = modmain_path:gsub("modmain.lua", "")
	AddGamePostInit(function()
		local PopupDialogScreen = require "screens/popupdialog"
		local locale = LOC.GetLocaleCode()
		local lc = locale

		local function translate(t)
			t.zhr = t.zh
			t.zht = t.zht or t.zh
			return t[lc] or t.en
		end
		if injector.DS_LUAJIT_get_mod_version() ~= nil and should_show_dig() then
			local version = ffi.string(injector.DS_LUAJIT_get_mod_version())
			if modinfo.version ~= version then
				local function update_mod()
					return injector.DS_LUAJIT_update(root_dictory, 0) == 1
				end

				local btns = {}
				local content = translate({
					zh = [[当前luajit模组有更新,是否要执行更新?]],
					en = "The current luajit mod has been updated, do you want to execute the update?"
				})
				if jit.os == "Windows" then
					btns[#btns + 1] = {
						text = STRINGS.UI.MAINSCREEN.RESTART,
						cb = function()
							update_mod()
						end
					}
				else
					content = translate({
						zh = [[当前luajit模组有更新,需要重新执行install.sh]],
						en = "The current luajit mod has been updated, should execute install.sh again"
					})
				end

				btns[#btns + 1] = { text = STRINGS.UI.MAINSCREEN.CANCEL, cb = function() TheFrontEnd:PopScreen() end }
				TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.RESTART_TITLE, content,
					btns))
			end
		end

		scheduler:ExecuteInTime(3, clean_crash_file)
		-- motify ModConfigurationScreen

		local luajit_config_screen_ctor = function(self, client_config)
			local function uninstall_mod()
				if jit.os == "Windows" then
					injector.DS_LUAJIT_update(root_dictory, 1)
				else
					TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.MODFAILTITLE, translate({
							zh = "当前操作系统不支持卸载luajit模组\n麻烦手动删除",
							en =
							"The current operating system does not support uninstalling the luajit mod\nPlease manually delete"
						}),
						{
							{ text = STRINGS.UI.MAINSCREEN.OK, cb = function() TheFrontEnd:PopScreen() end }
						}))
				end
			end

			for _,v in pairs(self.dialog.actions.items) do
				if v.name == "应用" then
					local old_onclick = v.onclick
					v.onclick = function(...)
						old_onclick(...)
						local config
						local fp = io.open(luajit_config_path, "r")
						if not fp then return end
						local data = fp:read("*a")
						fp:close()
						if data and string.len(data) > 0 then
							config = json.decode(data)
							local fp = io.open(luajit_config_path, "w")
							if fp then
								config.logic_fps = GetModConfigData("TargetLogincFPS",InGamePlay())
								fp:write(json.encode(config))
								fp:close()
								injector.DS_LUAJIT_set_target_fps(config.logic_fps, 2)
							end
						end
					end
					break
				end
			end

			local actions = self.dialog.actions
			if actions then
				self.uninstall = actions:AddItem(translate({ en = "uninstall mod", zh = "卸载模组" }),
					function()
						TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.RESTART_TITLE, translate({
								zh = "是否要卸载luajit模组?",
								en = "Are you sure you want to uninstall the luajit mod?"
							}),
							{
								{ text = STRINGS.UI.MAINSCREEN.RESTART, cb = function() uninstall_mod() end },
								{ text = STRINGS.UI.MAINSCREEN.CANCEL,  cb = function() TheFrontEnd:PopScreen() end }
							}))
					end)
				local sizeX, sizeY = actions:GetSize()
				local buttons_len = actions:GetNumberOfItems()
				local button_spacing
				-- 1,2,3,4 buttons can be big at 210,420,630,840 widths.
				local space_per_button = sizeX / buttons_len
				local has_space_for_big_buttons = space_per_button > 209
				if has_space_for_big_buttons then
					button_spacing = 320
				else
					button_spacing = 230
				end
				local button_height = -30 -- cover bottom crown
				actions:SetPosition(-(button_spacing * (buttons_len - 1)) / 2, button_height)
			end
		end
		local ModConfigurationScreen = KnownModIndex:IsModEnabledAny("workshop-3317960157") and require "widgets/remi_newmodconfigurationscreen" or require "screens/redux/modconfigurationscreen"
		local old_ctor = ModConfigurationScreen._ctor
		ModConfigurationScreen._ctor = function(self, _modname, client_config, ...)
			old_ctor(self, _modname, client_config, ...)
			if _modname == modname and jit.os == "Windows" then
				luajit_config_screen_ctor(self, client_config)
			end
		end
	end)
	inject_server_only_mod()
end

local env = _G.getfenv(main)
_G.setfenv(main, _G.setmetatable({}, {
	__index = function(t, k)
		return env[k] or _G[k]
	end
}))
main()
