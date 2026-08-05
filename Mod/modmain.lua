_G = GLOBAL
local modname = modname
local modinfo = modinfo
local function main()
	local old_print = print
	local function print(...)
		old_print("[luajit]", ...)
	end

	local main_fenv = getfenv(1)
	local _modimport = modimport
	local function modimport(modulename)
		local saved_env = env.env
		env.env = main_fenv
		_modimport(modulename)
		env.env = saved_env
	end

	local function startWith(str, prefix)
		return str:find(prefix, 1, true) == 1
	end
	local function Version2Number(version)
		local num = 0
		string.gsub(version, "(%d+)", function(v)
			num = num * 100000 + tonumber(v)
		end)
		return num
	end


	local locale = LOC.GetLocaleCode()
	local lc = locale

	local function translate(t)
		t.zhr = t.zh
		t.zht = t.zht or t.zh
		return t[lc] or t.en
	end

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

	local function LoadGameInjector()
		return _G.rawget(_G, "GameInjector")
	end

	local hasluajit, jit = _G.pcall(require, "jit")
	local os_is_windows = _G.IsWin32()
	local GameInjector = LoadGameInjector()

	local ModManagerFile = { filepath = nil, json_mode = true }
	function ModManagerFile:read_file()
		if not self.filepath then return end
		local fp = io.open(self.filepath, 'r')
		if not fp then return end
		local str = fp:read('*a')
		fp:close()
		if self.json_mode then
			local ok, result = pcall(json.decode, str)
			return ok and result or nil
		end
		return str
	end

	function ModManagerFile:clean_file()
		self:write_file(nil)
	end

	function ModManagerFile:write_file(data)
		if not self.filepath then return end
		local fp = io.open(self.filepath, 'w')
		if not fp then return end
		if data and self.json_mode then
			data = json.encode(data)
		end
		if data then
			fp:write(data)
		end

		fp:close()
	end

	local luajit_crash = setmetatable({ filepath = "unsafedata/luajit_crash.json", json_mode = false },
		{ __index = ModManagerFile })

	function luajit_crash:is_crash()
		local content = self:read_file()
		return content and #content ~= 0 and false
	end

	AddGamePostInit(function()
		luajit_crash:clean_file()
	end)


	local _M = {
		NotWindowsInvalidOptions = {
			TargetRenderFPS = true,
			TargetLogicFPS = true,
			ClientNetWorkTick = true,
		},
	}

	local function ResolveDisabledValueByOptionData(option)
		if type(option) ~= "table" or type(option.options) ~= "table" then
			return nil
		end

		local has_false = false
		local has_zero = false
		local has_off = false
		for _, item in ipairs(option.options) do
			local data = type(item) == "table" and item.data or nil
			if data == false then
				has_false = true
			elseif data == 0 then
				has_zero = true
			elseif data == "off" then
				has_off = true
			end
		end

		if has_false then
			return false
		end
		if has_zero then
			return 0
		end
		if has_off then
			return "off"
		end
		return nil
	end

	local function GetModConfigurationOptionsForCurrentMod()
		if KnownModIndex and KnownModIndex.GetModConfigurationOptions_Internal then
			local ok, options = pcall(KnownModIndex.GetModConfigurationOptions_Internal, KnownModIndex, modname, true)
			if ok and type(options) == "table" then
				return options
			end
		end

		if type(modinfo) == "table" and type(modinfo.configuration_options) == "table" then
			return modinfo.configuration_options
		end

		return nil
	end

	local function BuildConfigDisableRulesFromModInfo()
		local options = GetModConfigurationOptionsForCurrentMod()
		if type(options) ~= "table" then
			return nil
		end

		local rules = {}
		for _, option in ipairs(options) do
			if type(option) == "table" and type(option.name) == "string" and type(option.disabled_by) == "table" and type(option.disabled_by.option) == "string" then
				local rule = {
					name = option.name,
					option = option.disabled_by.option,
					value = option.disabled_by.value,
					values = option.disabled_by.values,
				}
				rule.disabled_value = option.disabled_value
				if rule.disabled_value == nil then
					rule.disabled_value = ResolveDisabledValueByOptionData(option)
				end

				if rule.disabled_value ~= nil then
					rules[#rules + 1] = rule
				else
					print("DisableBy skip no disabled value: " .. option.name)
				end
			end
		end

		if #rules == 0 then
			return nil
		end

		return rules
	end

	function _M:NoInjectorMain()
		AddGamePostInit(function()
			if should_show_dig() then
				local PopupDialogScreen = require "screens/popupdialog"
				-- check crash
				if luajit_crash:is_crash() then
					TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.RESTART_TITLE, translate({
							zh = "检测luajit未成功加载,是否再次尝试?\n\n(还失败可能需要更新,请联系作者)",
							en =
							"Detected that luajit failed to load, do you want to try again?\n\n(If it fails again, it may need to be updated, please contact the author)"
						}),
						{
							{
								text = STRINGS.UI.MAINSCREEN.RESTART,
								cb = function()
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
			end
		end)
	end

	local function IsConfigDisabledByRule(rule, get_raw_config, get_local_config)
		local option_value = get_raw_config(rule.option, get_local_config)
		if rule.value ~= nil then
			return option_value == rule.value
		end
		if rule.values ~= nil then
			for _, v in ipairs(rule.values) do
				if option_value == v then
					return true
				end
			end
		end
		return false
	end

	local function HookGetModConfigData()
		local old_GetModConfigData = GetModConfigData
		local dynamic_disable_rules = BuildConfigDisableRulesFromModInfo()
		if dynamic_disable_rules then
			print("DisableBy rules loaded from configuration_options: " .. tostring(#dynamic_disable_rules))
		else
			print("DisableBy rules not available, skip runtime disable action")
		end
		local function get_raw_config(key, get_local_config)
			return old_GetModConfigData(key, get_local_config)
		end

		function GetModConfigData(key, get_local_config)
			if not os_is_windows and _M.NotWindowsInvalidOptions[key] then
				print("InvalidOptions: " .. key)
				return nil
			end

			if dynamic_disable_rules then
				for _, rule in ipairs(dynamic_disable_rules) do
					if rule.name == key and IsConfigDisabledByRule(rule, get_raw_config, get_local_config) then
						print("DisableBy: " .. key .. " by " .. rule.option)
						return rule.disabled_value
					end
				end
			end

			return get_raw_config(key, get_local_config)
		end
	end



	local function HookGameVersionUI()
		local TEMPLATES = require("widgets/redux/templates")
		local old_getbuildstring = TEMPLATES.GetBuildString
		local function format_vm_name(name)
			if name == "jit" then
				return "LuaJIT"
			elseif name == "_51" then
				return "Lua 5.1"
			elseif name == "game" then
				return "GameLua"
			elseif name == "jit_gen" then
				return "LuaJIT-Gen"
			end
			return tostring(name or "unknown")
		end

		local function get_vm_type_suffix()
			if not GameInjector or not GameInjector.DS_LUAJIT_get_vm_type_name then
				return "(LuaJIT)"
			end

			local backend_suffix = ""
			if GameInjector.DS_LUAJIT_get_render_backend_name then
				local ok_backend_name, backend_name = pcall(GameInjector.DS_LUAJIT_get_render_backend_name)
				if ok_backend_name and type(backend_name) == "string" and backend_name ~= "" then
					backend_suffix = "/" .. backend_name
				end
			end

			local ok_current_name, current_name = pcall(GameInjector.DS_LUAJIT_get_vm_type_name, 0)
			local ok_next_name, next_name = pcall(GameInjector.DS_LUAJIT_get_vm_type_name, 1)
			if not ok_current_name or not ok_next_name then
				return "(LuaJIT)"
			end

			current_name = format_vm_name(current_name)
			next_name = format_vm_name(next_name)
			if current_name ~= next_name then
				return string.format("(%s->%s%s)", current_name, next_name, backend_suffix)
			end
			return string.format("(%s%s)", current_name, backend_suffix)
		end

		TEMPLATES.GetBuildString = function()
			return (old_getbuildstring() or "") .. get_vm_type_suffix()
		end
	end


	local function filename2modname(filename)
		local prefix = "../mods/"
		local modname_prefix_pos = #"../mods/" + 1
		if startWith(filename, prefix) then
			-- fixed pos = ../mods/
			local pos = filename:find("/", #prefix + 1, true)
			if pos then
				return filename:sub(modname_prefix_pos, pos - 1)
			end
		end
	end


	function _M:GetModMainPath(injector)
		local modmain_path = debug.getinfo(1).source

		local modname = filename2modname(modmain_path)
		if modname then
			local modnames = { modname }
			local workshop_context_prefix = "workshop-"
			if startWith(modname, workshop_context_prefix) then
				modnames[#modnames + 1] = modname:sub(#workshop_context_prefix + 1)
			end
			for _, modname in ipairs(modnames) do
				local workshop_dir = injector.DS_LUAJIT_get_workshop_dir();
				if workshop_dir ~= nil then
					assert(type(workshop_dir) == "string")
					local workshop_dir_root = workshop_dir .. "/" .. modname .. "/"
					local io = rawget(_G, "io2") or io
					local ok, fp = pcall(io.open, workshop_dir_root .. "install.bat", "r")
					if ok and fp then
						fp:close()
						self.modmain_path = workshop_dir_root .. "modmain.lua"
						self.workshop_dir_root = workshop_dir_root
						break
					end
				end
			end
		end
	end

	function _M:GetModVersion(injector)
		local so_version = injector.DS_LUAJIT_get_mod_version()
		if so_version then
			assert(type(so_version) == "string")
		else
			so_version = "0.0.0"
		end
		self.so_version = so_version
	end

	local luajit_config = setmetatable({ filepath = "unsafedata/luajit_config.json" }, { __index = ModManagerFile })
	function luajit_config:create(modmain_path, DisableJITWhenServer, AlwaysEnableMod, config)
		if config == nil then
			return {
				modmain_path = modmain_path,
				DisableJITWhenServer = DisableJITWhenServer,
				AlwaysEnableMod = AlwaysEnableMod,
			}
		else
			if modmain_path ~= nil then
				config.modmain_path = modmain_path
			end
			if DisableJITWhenServer ~= nil then
				config.DisableJITWhenServer = DisableJITWhenServer
			end
			if AlwaysEnableMod ~= nil then
				config.AlwaysEnableMod = AlwaysEnableMod
			end
			return config
		end
	end

	function luajit_config:WriteConfig(modmain_path)
		if not TheNet:IsDedicated() then
			local DisableJITWhenServer = GetModConfigData("DisableJITWhenServer")
			local AlwaysEnableMod = GetModConfigData("AlwaysEnableMod")
			self.data = self:create(modmain_path, DisableJITWhenServer, AlwaysEnableMod)
			self:write_file(self.data)
		end
	end



	local function ReloadSim()
		print("need restart")
		scheduler:ExecuteInTime(0, function()
			c_reset()
		end)
	end

	function _M:SwitchVm(noreset)
		luavmType = GetModConfigData("LuaVmType")
		if type(luavmType) ~= "string" then
			return false
		end
		print("current vm type: ",
			GameInjector and GameInjector.DS_LUAJIT_get_vm_type_name and GameInjector.DS_LUAJIT_get_vm_type_name() or
			"unknown",
			"target vm type: ", luavmType)
		if GameInjector and luavmType ~= GameInjector.DS_LUAJIT_get_vm_type_name() then
			print("switch vm to ", luavmType)
			GameInjector.DS_LUAJIT_set_vm_type(luavmType)
			if not noreset then
				ReloadSim()
			end
			return true
		end
		return false
	end

	function _M:AlwaysLoad(injector, VersionMissMatch)
		AddGamePostInit(function()
			local workshop_dir_root = self.workshop_dir_root
			local PopupDialogScreen = require "screens/popupdialog"

			if should_show_dig() then
				if VersionMissMatch then
					local function update_mod()
						return injector.DS_LUAJIT_update(workshop_dir_root, 0) == 1
					end

					local btns = {}
					local version_info = translate({
						zh = "\n 模组版本:" .. modinfo.version .. " 模块版本:" .. version,
						en = "\n Mod version:" .. modinfo.version .. " Module version:" .. version
					})
					local content = translate({
						zh = [[当前luajit模组有更新,是否要执行更新?]] .. version_info,
						en = "The current luajit mod has been updated, do you want to execute the update?" ..
							version_info
					})
					if os_is_windows then
						btns[#btns + 1] = {
							text = STRINGS.UI.MAINSCREEN.RESTART,
							cb = function()
								update_mod()
							end
						}
					else
						content = translate({
							zh = [[当前luajit模组有更新,需要重新执行install.sh]] .. version_info,
							en = "The current luajit mod has been updated, should execute install.sh again" ..
								version_info
						})
					end

					btns[#btns + 1] = { text = STRINGS.UI.MAINSCREEN.CANCEL, cb = function() TheFrontEnd:PopScreen() end }
					TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.RESTART_TITLE, content,
						btns))
				end
			end

			-- motify ModConfigurationScreen

			local luajit_config_screen_ctor = function(self, client_config)
				local function uninstall_mod()
					if os_is_windows then
						injector.DS_LUAJIT_update(workshop_dir_root, 1)
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
			local ModConfigurationScreen = KnownModIndex:IsModEnabledAny("workshop-3317960157") and
				require "widgets/remi_newmodconfigurationscreen" or require "screens/redux/modconfigurationscreen"
			local old_ctor = ModConfigurationScreen._ctor
			ModConfigurationScreen._ctor = function(self, _modname, client_config, ...)
				old_ctor(self, _modname, client_config, ...)
				if _modname == modname then
					-- Plugin Manager entry is available on all platforms (soft-absent when DLL missing).
					do
						local pm = require "plugin_manager_screen"
						local actions = self.dialog and self.dialog.actions
						if actions then
							self.plugin_manager_btn = actions:AddItem(
								translate({ en = "Plugin Manager", zh = "插件管理" }),
								function()
									pm.open_plugin_manager()
								end
							)
							local sizeX, sizeY = actions:GetSize()
							local buttons_len = actions:GetNumberOfItems()
							local space_per_button = sizeX / buttons_len
							local has_space_for_big_buttons = space_per_button > 209
							local button_spacing = has_space_for_big_buttons and 320 or 230
							local button_height = -30 -- cover bottom crown
							actions:SetPosition(-(button_spacing * (buttons_len - 1)) / 2, button_height)
						end
					end
					-- Uninstall remains Windows-only (native update path).
					if os_is_windows then
						luajit_config_screen_ctor(self, client_config)
					end
				end
			end

			local ModsScreen = require "screens/redux/modsscreen"
			local old_ModsScreen_ctor = ModsScreen._ctor
			ModsScreen._ctor = function(self, ...)
				old_ModsScreen_ctor(self, ...)
				if self.Apply then
					local old_Apply = self.Apply
					self.Apply = function(...)
						old_Apply(...)
						_M:SwitchVm(true)
					end
				end
			end
			require "config_patch_bootstrap.bootstrap" ()
		end)
	end

	function _M:Main()
		assert(GameInjector ~= nil, "Load GameInjector Failed!")

		self:GetModVersion(GameInjector)
		local VersionMissMatch = Version2Number(modinfo.version) < Version2Number(self.so_version)
		self:AlwaysLoad(GameInjector, VersionMissMatch)
		if VersionMissMatch then
			return
		end
		HookGetModConfigData()
		-- Path A Lua PluginHost (AfterModMain). M4+ features load from plugins/init.
		-- kleiloadlua chunks do NOT inherit the mod env (strict.lua treats MODROOT as undeclared).
		-- Always setfenv to main_fenv so MODROOT / modimport / Add*PostInit resolve.
		do
			local function run_mod_chunk(relpath)
				local path = MODROOT .. relpath
				local chunk = kleiloadlua(path)
				if type(chunk) == "string" then
					error(string.format("error loading %s:\n%s", path, chunk), 2)
				end
				if type(chunk) ~= "function" then
					error(string.format("expected function chunk for %s, got %s", path, type(chunk)), 2)
				end
				-- main_fenv is often a proxy (MODROOT only via __index). Give plugin chunks
				-- a thin env with raw MODROOT/kleiloadlua so rawget and loaders work.
				local plugin_env = setmetatable({
					MODROOT = MODROOT,
					kleiloadlua = kleiloadlua,
					modimport = modimport,
					GetModConfigData = GetModConfigData,
					print = print,
				}, { __index = main_fenv, __newindex = main_fenv })
				setfenv(chunk, plugin_env)
				return chunk()
			end
			local PluginHost = run_mod_chunk("plugins/host.lua")
			local registry = run_mod_chunk("plugins/init.lua") or {}
			local host = PluginHost.new()
			host:register_all(registry)
			-- Resolve against already-hooked GetModConfigData when available; raw otherwise.
			local function config_lookup(key)
				return GetModConfigData(key)
			end
			local gate_ctx = {
				injector = GameInjector,
				has_luajit = hasluajit,
				is_client = not TheNet:IsDedicated(),
				is_windows = os_is_windows,
				-- nil when TheWorld is not ready yet; plugins fall back to TheWorld.
				-- Keep boolean false (client shard) distinct from nil (world not ready).
				is_mastersim = TheWorld and TheWorld.ismastersim,
				-- jit.runtime HideGlobalJIT needs the real jit table + this mod env.
				jit = env.jit or jit,
				mod_env = env,
			}
			host:resolve(config_lookup, gate_ctx)
			local lr = host:load_phase(PluginHost.Phase.AfterModMain)
			if not lr.ok then
				print("[luajit][plugin] AfterModMain load reported failures")
			end
			for _, ev in ipairs(host:events_list()) do
				if ev.status == PluginHost.Status.Failed then
					print(string.format(
						"[luajit][plugin] plugin=%s phase=%s status=%s reason=%s detail=%s",
						tostring(ev.plugin_id), tostring(ev.phase), tostring(ev.status),
						tostring(ev.reason), tostring(ev.detail)))
				end
			end
			_M.plugin_host = host
		end
		if self:SwitchVm() then
			return
		end
		self:GetModMainPath(GameInjector)
		HookGameVersionUI()
		luajit_config:WriteConfig(self.modmain_path)

		modimport("inject_server_only_mod")
	end

	if GameInjector then
		_M:Main()
	else
		_M:NoInjectorMain()
	end
end

local env = _G.getfenv(main)
-- Keep a real jit table on this mod env (not pcall's boolean status).
env.jit = _G.rawget(_G, "jit") or env.jit
local new_env = _G.setmetatable({}, {
	__index = function(t, k)
		return env[k] or _G[k]
	end
})
_G.setfenv(main, new_env)

-- Workshop require goes through package.path + mod.manifest. Files under this
-- mod's scripts/ that are missing from the manifest (e.g. config_patch_bootstrap)
-- fail even though they exist on disk. Prefer MODROOT/scripts like modimport.
local _require = env.require
env.require = function(modulename)
	if package.loaded[modulename] ~= nil then
		return package.loaded[modulename]
	end

	local modulepath = string.gsub(modulename, "[%.\\]", "/")
	local filepath = env.MODROOT .. "scripts/" .. modulepath .. ".lua"
	local chunk = kleiloadlua(filepath)
	if type(chunk) == "string" then
		error(string.format("error loading module '%s' from '%s':\n%s", modulename, filepath, chunk), 2)
	end
	if type(chunk) == "function" then
		package.loaded[modulename] = true
		_G.setfenv(chunk, new_env)
		local result = chunk(modulename)
		if result ~= nil then
			package.loaded[modulename] = result
		end
		return package.loaded[modulename]
	end

	return _require(modulename)
end
_G.setfenv(env.require, new_env)
main()
