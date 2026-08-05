-- Plugin Manager screen (optional plugin.manager). Soft-absent when exports missing.
-- Optional CString plugin APIs take "" (not nil): channel default / apply all.
local Screen = require "widgets/screen"
local Widget = require "widgets/widget"
local Text = require "widgets/text"
local TEMPLATES = require "widgets/redux/templates"
local PopupDialogScreen = require "screens/redux/popupdialog"
local InputDialogScreen = require "screens/redux/inputdialog"

local function locale_code()
	local ok, code = pcall(function()
		return LOC.GetLocaleCode()
	end)
	return (ok and code) or "en"
end

local function translate(t)
	local lc = locale_code()
	t.zhr = t.zh
	t.zht = t.zht or t.zh
	return t[lc] or t.en
end

local function decode_json(str)
	if type(str) ~= "string" or str == "" then
		return nil
	end
	local decoder = rawget(_G, "json")
	if type(decoder) ~= "table" or type(decoder.decode) ~= "function" then
		local ok_req, mod = pcall(require, "json")
		if ok_req and type(mod) == "table" then
			decoder = mod
		end
	end
	if type(decoder) ~= "table" or type(decoder.decode) ~= "function" then
		return nil
	end
	local ok, result = pcall(decoder.decode, str)
	if ok and type(result) == "table" then
		return result
	end
	return nil
end

local function injector()
	return rawget(_G, "GameInjector")
end

local function manager_available()
	local inj = injector()
	if not inj or inj.DS_LUAJIT_plugin_manager_status_json == nil then
		return false
	end
	local ok, status = pcall(inj.DS_LUAJIT_plugin_manager_status_json)
	return ok and status ~= nil
end

-- Call a GameInjector export under pcall.
-- Optional CString plugin APIs (fetch_manifest release_tag, apply id) MUST receive
-- "" not nil: binding uses luaL_checkstring. Empty string = channel default / apply all.
local function call_api(name, ...)
	local inj = injector()
	if not inj then
		return nil, false
	end
	local fn = inj[name]
	if fn == nil then
		return nil, false
	end
	local ok, a, b, c = pcall(fn, ...)
	if not ok then
		return nil, false
	end
	return a, true, b, c
end

local function str_or(v, fallback)
	if v == nil then
		return fallback or "-"
	end
	local s = tostring(v)
	if s == "" then
		return fallback or "-"
	end
	return s
end

local function manual_install_body()
	return translate({
		zh = table.concat({
			"插件管理器未安装（plugin_manager 模块缺失）。",
			"",
			"请从 GitHub Release 手动安装：",
			"1) 解压 {platform}_Mod.zip，复制其中的 plugins/ 到游戏注入目录；或",
			"2) 解压 plugin_manager-*-{platform}.zip，将 DLL/SO 放入 plugins/ 文件夹。",
			"",
			"业务插件也可单独从 plugin_*-{ver}-{platform}.zip 手动复制。",
			"安装后重启游戏即可使用本界面。",
		}, "\n"),
		en = table.concat({
			"Plugin Manager is not installed (plugin_manager module missing).",
			"",
			"Install manually from a GitHub Release:",
			"1) Unpack {platform}_Mod.zip and copy its plugins/ folder into the injector directory; or",
			"2) Unpack plugin_manager-*-{platform}.zip and place the module into the plugins/ folder.",
			"",
			"Business plugins can also be copied from plugin_*-{ver}-{platform}.zip.",
			"Restart the game after install to use this screen.",
		}, "\n"),
	})
end

local function show_manual_install_popup()
	TheFrontEnd:PushScreen(PopupDialogScreen(
		translate({ zh = "插件管理", en = "Plugin Manager" }),
		manual_install_body(),
		{
			{
				text = STRINGS.UI.MAINSCREEN.OK or "OK",
				cb = function()
					TheFrontEnd:PopScreen()
				end,
			},
		},
		nil,
		"bigger"
	))
end

local function open_plugin_manager()
	if not manager_available() then
		show_manual_install_popup()
		return
	end
	local PluginManagerScreen = require "plugin_manager_screen"
	TheFrontEnd:PushScreen(PluginManagerScreen())
end

local PluginManagerScreen = Class(Screen, function(self)
	Screen._ctor(self, "PluginManagerScreen")

	self.status = {
		plugins = {},
		channel_name = "-",
		release_tag = "-",
		prefer_proxy = "-",
		last_error = nil,
		needs_restart = false,
	}
	self.selected = nil

	self.black = self:AddChild(TEMPLATES.BackgroundTint())
	self.root = self:AddChild(TEMPLATES.ScreenRoot())

	local win_w, win_h = 760, 520
	local title = translate({ zh = "插件管理", en = "Plugin Manager" })

	local buttons = {
		{
			text = translate({ zh = "刷新", en = "Refresh" }),
			cb = function()
				self:OnRefresh()
			end,
		},
		{
			text = translate({ zh = "应用全部", en = "Apply All" }),
			cb = function()
				self:OnApplyAll()
			end,
		},
		{
			text = translate({ zh = "固定版本", en = "Pin" }),
			cb = function()
				self:OnPinSelected()
			end,
		},
		{
			text = translate({ zh = "清除固定", en = "Clear Pin" }),
			cb = function()
				self:OnClearPinSelected()
			end,
		},
		{
			text = STRINGS.UI.MODSSCREEN and STRINGS.UI.MODSSCREEN.BACK or "Back",
			cb = function()
				self:Close()
			end,
			controller_control = CONTROL_CANCEL,
		},
	}

	self.dialog = self.root:AddChild(TEMPLATES.RectangleWindow(win_w, win_h, title, buttons))
	self.buttons = buttons
	self.oncontrol_fn, self.gethelptext_fn = TEMPLATES.ControllerFunctionsFromButtons(self.buttons)
	if TheInput:ControllerAttached() and self.dialog.actions then
		self.dialog.actions:Hide()
	end

	self.channel_label = self.dialog:AddChild(Text(CHATFONT, 22, "", UICOLOURS.GOLD_UNIMPORTANT))
	self.channel_label:SetPosition(0, 210)
	self.channel_label:SetRegionSize(win_w - 40, 30)
	self.channel_label:SetHAlign(ANCHOR_LEFT)

	self.error_label = self.dialog:AddChild(Text(CHATFONT, 20, "", UICOLOURS.GOLD))
	self.error_label:SetPosition(0, 180)
	self.error_label:SetRegionSize(win_w - 40, 30)
	self.error_label:SetHAlign(ANCHOR_LEFT)

	local item_width, item_height = win_w - 60, 42
	local list_height = 320

	local function ScrollWidgetsCtor(context, index)
		local widget = Widget("plugin-row-" .. tostring(index))
		widget.bg = widget:AddChild(TEMPLATES.ListItemBackground(item_width, item_height, function()
			if widget.data then
				self:SelectPlugin(widget.data)
			end
		end))
		widget.label = widget:AddChild(Text(CHATFONT, 20, "", UICOLOURS.GOLD_UNIMPORTANT))
		widget.label:SetHAlign(ANCHOR_LEFT)
		widget.label:SetRegionSize(item_width - 24, item_height - 8)
		widget.label:SetPosition(0, 0)
		widget.focus_forward = widget.bg
		widget:SetOnGainFocus(function()
			if self.scroll_list then
				self.scroll_list:OnWidgetFocus(widget)
			end
			if widget.data then
				self:SelectPlugin(widget.data)
			end
		end)
		return widget
	end

	local function ScrollWidgetApply(context, widget, data, index)
		widget.data = data
		if data then
			local id = str_or(data.id, "?")
			local local_v = str_or(data.local_version, "-")
			local desired = str_or(data.desired_version, "-")
			local state = str_or(data.state, "-")
			local pin = data.pin_source and (" [" .. tostring(data.pin_source) .. "]") or ""
			local line = string.format("%s  local=%s  desired=%s  %s%s", id, local_v, desired, state, pin)
			widget.label:SetTruncatedString(line, item_width - 30, 120, true)
			widget:Show()
		else
			widget.label:SetString("")
			widget:Hide()
		end
	end

	self.scroll_list = self.dialog:AddChild(TEMPLATES.ScrollingGrid({}, {
		context = {},
		widget_width = item_width,
		widget_height = item_height,
		num_visible_rows = math.floor(list_height / item_height),
		num_columns = 1,
		item_ctor_fn = ScrollWidgetsCtor,
		apply_fn = ScrollWidgetApply,
		scrollbar_height_offset = -60,
		force_peek = true,
	}))
	self.scroll_list:SetPosition(0, -10)

	if self.dialog.actions then
		self.scroll_list:SetFocusChangeDir(MOVE_DOWN, self.dialog.actions)
		self.dialog.actions:SetFocusChangeDir(MOVE_UP, self.scroll_list)
	end
	self.default_focus = self.scroll_list

	self:OnRefresh()
end)

function PluginManagerScreen:Close()
	TheFrontEnd:PopScreen(self)
end

function PluginManagerScreen:OnControl(control, down)
	if PluginManagerScreen._base.OnControl(self, control, down) then
		return true
	end
	return self.oncontrol_fn(control, down)
end

function PluginManagerScreen:GetHelpText()
	return self.gethelptext_fn()
end

function PluginManagerScreen:SelectPlugin(data)
	self.selected = data
end

function PluginManagerScreen:FetchStatus()
	local raw = call_api("DS_LUAJIT_plugin_manager_status_json")
	local decoded = decode_json(raw)
	if type(decoded) ~= "table" then
		decoded = { plugins = {}, last_error = "status_json decode failed" }
	end
	if type(decoded.plugins) ~= "table" then
		decoded.plugins = {}
	end
	self.status = decoded
	return decoded
end

function PluginManagerScreen:UpdateLabels()
	local st = self.status or {}
	local channel = str_or(st.channel_name, "-")
	local tag = str_or(st.release_tag, "-")
	local proxy = str_or(st.prefer_proxy, "-")
	local repo = st.repo and ("  repo=" .. tostring(st.repo)) or ""
	self.channel_label:SetString(string.format(
		translate({
			zh = "频道: %s  标签: %s  代理: %s%s",
			en = "Channel: %s  Tag: %s  Proxy: %s%s",
		}),
		channel, tag, proxy, repo
	))

	local err = st.last_error
	if err == nil or err == "" then
		err = nil
	end
	if err then
		self.error_label:SetString(translate({
			zh = "错误: ",
			en = "Error: ",
		}) .. tostring(err))
	else
		local needs = st.needs_restart and translate({ zh = "（需要重启）", en = " (restart required)" }) or ""
		local n = type(st.plugins) == "table" and #st.plugins or 0
		self.error_label:SetString(translate({
			zh = "插件数: ",
			en = "Plugins: ",
		}) .. tostring(n) .. needs)
	end
end

function PluginManagerScreen:RebuildList()
	local plugins = {}
	if type(self.status.plugins) == "table" then
		-- support both array and map forms
		local is_array = self.status.plugins[1] ~= nil or #self.status.plugins > 0
		if is_array then
			for _, row in ipairs(self.status.plugins) do
				if type(row) == "table" then
					table.insert(plugins, row)
				end
			end
		else
			for id, row in pairs(self.status.plugins) do
				if type(row) == "table" then
					row.id = row.id or id
					table.insert(plugins, row)
				end
			end
			table.sort(plugins, function(a, b)
				return tostring(a.id or "") < tostring(b.id or "")
			end)
		end
	end
	self.plugin_rows = plugins
	if self.selected then
		local keep = nil
		for _, row in ipairs(plugins) do
			if row.id == self.selected.id then
				keep = row
				break
			end
		end
		self.selected = keep
	end
	if self.scroll_list and self.scroll_list.SetItemsData then
		self.scroll_list:SetItemsData(plugins)
	end
end

function PluginManagerScreen:OnRefresh()
	call_api("DS_LUAJIT_plugin_config_reload")
	-- Empty string release_tag => follow configured channel / latest resolution.
	-- (GameInjector CString binding uses luaL_checkstring; Lua nil errors before native runs.)
	call_api("DS_LUAJIT_plugin_fetch_manifest", "")
	self:FetchStatus()
	self:UpdateLabels()
	self:RebuildList()
end

function PluginManagerScreen:ShowMessage(title, body, buttons)
	TheFrontEnd:PushScreen(PopupDialogScreen(title, body, buttons or {
		{
			text = STRINGS.UI.MAINSCREEN.OK or "OK",
			cb = function()
				TheFrontEnd:PopScreen()
			end,
		},
	}))
end

function PluginManagerScreen:MaybeConfirmRestart()
	local needs = false
	local v, ok = call_api("DS_LUAJIT_plugin_needs_restart")
	if ok and v then
		needs = true
	elseif self.status and self.status.needs_restart then
		needs = true
	end
	if not needs then
		return
	end
	self:ShowMessage(
		STRINGS.UI.MODSSCREEN and STRINGS.UI.MODSSCREEN.RESTART_TITLE or "Restart",
		translate({
			zh = "插件已写入磁盘，需要退出游戏后重新启动以加载新版本。",
			en = "Plugins were written to disk. Quit and restart the game to load the new versions.",
		}),
		{
			{
				text = STRINGS.UI.MAINSCREEN.RESTART or "Restart",
				cb = function()
					TheFrontEnd:PopScreen()
					if DoRestart then
						DoRestart(true)
					elseif TheSim and TheSim.Quit then
						TheSim:Quit()
					end
				end,
			},
			{
				text = STRINGS.UI.MAINSCREEN.CANCEL or "Cancel",
				cb = function()
					TheFrontEnd:PopScreen()
				end,
			},
		}
	)
end

function PluginManagerScreen:OnApplyAll()
	local ok_apply
	-- Empty string id => apply all planned plugins (same as native nullptr/empty).
	local result, ok = call_api("DS_LUAJIT_plugin_apply", "")
	ok_apply = ok and result and true or false
	self:FetchStatus()
	self:UpdateLabels()
	self:RebuildList()

	local err = self.status and self.status.last_error
	if not ok_apply then
		self:ShowMessage(
			translate({ zh = "应用失败", en = "Apply failed" }),
			tostring(err or translate({
				zh = "plugin_apply 返回失败（可能无更新或网络错误）。",
				en = "plugin_apply returned failure (nothing to apply or network error).",
			}))
		)
		return
	end
	self:MaybeConfirmRestart()
end

function PluginManagerScreen:OnPinSelected()
	local row = self.selected
	if not row or not row.id then
		self:ShowMessage(
			translate({ zh = "固定版本", en = "Pin" }),
			translate({
				zh = "请先在列表中选择一个插件。",
				en = "Select a plugin from the list first.",
			})
		)
		return
	end
	local plugin_id = tostring(row.id)
	local default_ver = str_or(row.desired_version, str_or(row.local_version, ""))
	if default_ver == "-" then
		default_ver = ""
	end

	local dialog
	dialog = InputDialogScreen(
		translate({ zh = "固定版本: ", en = "Pin version: " }) .. plugin_id,
		{
			{
				text = STRINGS.UI.MODSSCREEN and STRINGS.UI.MODSSCREEN.OK or "OK",
				cb = function()
					local ver = dialog:GetActualString()
					TheFrontEnd:PopScreen()
					if not ver or ver:match("^%s*$") then
						self:ShowMessage(
							translate({ zh = "固定版本", en = "Pin" }),
							translate({
								zh = "版本不能为空。",
								en = "Version cannot be empty.",
							})
						)
						return
					end
					ver = ver:match("^%s*(.-)%s*$")
					local result, ok = call_api("DS_LUAJIT_plugin_pin_set", plugin_id, ver, true)
					if not (ok and result) then
						self:FetchStatus()
						self:UpdateLabels()
						self:ShowMessage(
							translate({ zh = "固定失败", en = "Pin failed" }),
							tostring((self.status and self.status.last_error) or "pin_set failed")
						)
						return
					end
					self:OnRefresh()
				end,
			},
			{
				text = STRINGS.UI.MAINSCREEN.CANCEL or "Cancel",
				cb = function()
					TheFrontEnd:PopScreen()
				end,
			},
		},
		true,
		true
	)
	dialog:OverrideText(default_ver)
	dialog:SetValidChars("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-+")
	TheFrontEnd:PushScreen(dialog)
end

function PluginManagerScreen:OnClearPinSelected()
	local row = self.selected
	if not row or not row.id then
		self:ShowMessage(
			translate({ zh = "清除固定", en = "Clear Pin" }),
			translate({
				zh = "请先在列表中选择一个插件。",
				en = "Select a plugin from the list first.",
			})
		)
		return
	end
	local result, ok = call_api("DS_LUAJIT_plugin_pin_clear", tostring(row.id))
	if not (ok and result) then
		self:FetchStatus()
		self:UpdateLabels()
		self:ShowMessage(
			translate({ zh = "清除失败", en = "Clear failed" }),
			tostring((self.status and self.status.last_error) or "pin_clear failed")
		)
		return
	end
	self:OnRefresh()
end

-- Module table: screen class + helpers for modmain entry.
return setmetatable({
	PluginManagerScreen = PluginManagerScreen,
	manager_available = manager_available,
	show_manual_install_popup = show_manual_install_popup,
	open_plugin_manager = open_plugin_manager,
	translate = translate,
}, {
	__call = function(_, ...)
		return PluginManagerScreen(...)
	end,
})
