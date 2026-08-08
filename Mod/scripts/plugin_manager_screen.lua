-- Plugin Manager screen (optional plugin.manager).
-- Layout mirrors screens/redux/modconfigurationscreen.lua:
--   RectangleWindow + InsertWidget(optionspanel) + ScrollingGrid of ListItemBackground rows.
-- Text stays at local (0,y) with RegionSize + HAlign LEFT so glyphs stay inside the row frame.
-- Open path is zero-native until first OnUpdate; network is async.
local Screen = require "widgets/screen"
local Widget = require "widgets/widget"
local Text = require "widgets/text"
local Image = require "widgets/image"
local TEMPLATES = require "widgets/redux/templates"
local PopupDialogScreen = require "screens/redux/popupdialog"

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
	return inj ~= nil and inj.DS_LUAJIT_plugin_manager_status_json ~= nil
end

local function call_api(name, ...)
	local inj = injector()
	if not inj then
		return nil, false, "no GameInjector"
	end
	local fn = inj[name]
	if fn == nil then
		return nil, false, "missing " .. tostring(name)
	end
	local ok, a, b, c = pcall(fn, ...)
	if not ok then
		return nil, false, tostring(a)
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

local function is_busy_status(st)
	return type(st) == "table" and (st.fetching or st.applying or st.busy) or false
end

local function show_manual_install_popup()
	TheFrontEnd:PushScreen(PopupDialogScreen(
		translate({ zh = "插件管理", en = "Plugin Manager" }),
		translate({
			zh = "插件管理器未安装（导出缺失）。请确认 plugin_manager.dll 已部署并完全重启游戏。",
			en = "Plugin Manager export missing. Deploy plugin_manager.dll and fully restart.",
		}),
		{
			{
				text = STRINGS.UI.MAINSCREEN.OK or "OK",
				cb = function()
					TheFrontEnd:PopScreen()
				end,
			},
		}
	))
end

-- Geometry family as ModConfigurationScreen list rows.
-- Columns are separate Text widgets (not one concatenated string).
local ITEM_W = 620
local ITEM_H = 42
local VISIBLE_ROWS = 10
-- Column widths must sum <= ITEM_W - pad.
local COL_ID = 180
local COL_LOCAL = 110
local COL_DESIRED = 110
local COL_STATE = 100
local COL_GAP = 12
local COL_PAD = 16

local PluginManagerScreen = Class(Screen, function(self)
	Screen._ctor(self, "PluginManagerScreen")

	self.status = {
		plugins = {},
		channel_name = "-",
		release_tag = "-",
		prefer_proxy = "-",
		last_error = nil,
		needs_restart = false,
		fetching = false,
		applying = false,
		busy = false,
		progress = { phase = "idle", percent = 0, current = 0, total = 0, message = "" },
	}
	self.selected = nil
	self.plugin_rows = {}
	self._boot_pending = true
	self._poll_active = false
	self._poll_elapsed = 0
	self._poll_accum = 0
	self._awaiting_apply_result = false
	self._pulse_t = 0

	self.black = self:AddChild(TEMPLATES.BackgroundTint())
	self.root = self:AddChild(TEMPLATES.ScreenRoot())

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
			text = STRINGS.UI.MODSSCREEN and STRINGS.UI.MODSSCREEN.BACK or "Back",
			cb = function()
				self:Close()
			end,
			controller_control = CONTROL_CANCEL,
		},
	}

	-- Match mod config window proportions.
	self.dialog = self.root:AddChild(TEMPLATES.RectangleWindow(ITEM_W + 20, 580, nil, buttons))
	self.buttons = buttons
	self.oncontrol_fn, self.gethelptext_fn = TEMPLATES.ControllerFunctionsFromButtons(self.buttons)

	-- Header (compact): title + 2 status lines. Positioned like option_header in mod config.
	self.option_header = self.dialog:AddChild(Widget("option_header"))
	self.option_header:SetPosition(0, 255)

	self.title = self.option_header:AddChild(Text(HEADERFONT, 28,
		translate({ zh = "插件管理", en = "Plugin Manager" }), UICOLOURS.GOLD_SELECTED))
	self.title:SetPosition(0, 0)

	-- Channel / status / progress: centered origin, full-width region, LEFT align.
	-- DO NOT SetPosition(x negative large) — that puts the text center off-frame.
	self.channel_label = self.option_header:AddChild(Text(CHATFONT, 18, "", UICOLOURS.GOLD_UNIMPORTANT))
	self.channel_label:SetPosition(0, -32)
	self.channel_label:SetRegionSize(ITEM_W + 10, 22)
	self.channel_label:SetHAlign(ANCHOR_LEFT)

	self.error_label = self.option_header:AddChild(Text(CHATFONT, 17, "", UICOLOURS.GOLD_UNIMPORTANT))
	self.error_label:SetPosition(0, -52)
	self.error_label:SetRegionSize(ITEM_W + 10, 20)
	self.error_label:SetHAlign(ANCHOR_LEFT)

	self.progress_label = self.option_header:AddChild(Text(CHATFONT, 16, "", UICOLOURS.GOLD_UNIMPORTANT))
	self.progress_label:SetPosition(0, -70)
	self.progress_label:SetRegionSize(ITEM_W + 10, 18)
	self.progress_label:SetHAlign(ANCHOR_LEFT)

	-- List panel: InsertWidget so crowns/frame stay correct (same as mod config).
	self.optionspanel = self.dialog:InsertWidget(Widget("optionspanel"))
	self.optionspanel:SetPosition(0, -70)

	-- Column header above the scroll list.
	local function make_col_header(parent, text, width, x)
		local t = parent:AddChild(Text(HEADERFONT, 16, text, UICOLOURS.GOLD_SELECTED))
		-- Center of this column: x is left edge relative to row center-left system below.
		t:SetPosition(x + width * 0.5, 0)
		t:SetRegionSize(width, 20)
		t:SetHAlign(ANCHOR_LEFT)
		return t
	end

	-- Helper: place a column Text like LabelSpinner does.
	-- total row content width, left edge at -total/2.
	local function place_col(parent, width, left_x, font_size)
		local t = parent:AddChild(Text(CHATFONT, font_size or 18, "", UICOLOURS.GOLD_UNIMPORTANT))
		t:SetPosition(left_x + width * 0.5, 0)
		t:SetRegionSize(width, ITEM_H - 8)
		t:SetHAlign(ANCHOR_LEFT)
		t:SetVAlign(ANCHOR_MIDDLE)
		return t
	end

	local content_w = COL_ID + COL_LOCAL + COL_DESIRED + COL_STATE + COL_GAP * 3
	local left0 = -content_w * 0.5
	local x_id = left0
	local x_local = x_id + COL_ID + COL_GAP
	local x_desired = x_local + COL_LOCAL + COL_GAP
	local x_state = x_desired + COL_DESIRED + COL_GAP

	self.col_header = self.optionspanel:AddChild(Widget("col_header"))
	-- sits just under top divider line
	self.col_header:SetPosition(0, VISIBLE_ROWS / 2 * ITEM_H - 8)
	make_col_header(self.col_header, translate({ zh = "插件", en = "Plugin" }), COL_ID, x_id)
	make_col_header(self.col_header, translate({ zh = "本地", en = "Local" }), COL_LOCAL, x_local)
	make_col_header(self.col_header, translate({ zh = "目标", en = "Desired" }), COL_DESIRED, x_desired)
	make_col_header(self.col_header, translate({ zh = "状态", en = "State" }), COL_STATE, x_state)

	local function ScrollWidgetsCtor(context, idx)
		local widget = Widget("plugin_row_" .. tostring(idx))
		widget.bg = widget:AddChild(TEMPLATES.ListItemBackground(ITEM_W, ITEM_H, function()
			if widget.data then
				self:SelectPlugin(widget.data)
			end
		end))

		-- Four independent column controls inside the row frame.
		widget.col_id = place_col(widget, COL_ID, x_id, 18)
		widget.col_local = place_col(widget, COL_LOCAL, x_local, 18)
		widget.col_desired = place_col(widget, COL_DESIRED, x_desired, 18)
		widget.col_state = place_col(widget, COL_STATE, x_state, 18)

		widget.focus_forward = widget.bg
		widget:SetOnGainFocus(function()
			if self.options_scroll_list then
				self.options_scroll_list:OnWidgetFocus(widget)
			end
			if widget.data then
				self:SelectPlugin(widget.data)
			end
		end)
		return widget
	end

	local function ApplyDataToWidget(context, widget, data, idx)
		widget.data = data
		if data then
			local id = str_or(data.id, "?")
			local local_v = str_or(data.local_version, "-")
			local desired = str_or(data.desired_version, "-")
			local state = str_or(data.state, "-")

			widget.col_id:SetString(id)
			widget.col_local:SetString(local_v)
			widget.col_desired:SetString(desired)
			widget.col_state:SetString(state)

			if state == "ok" then
				widget.col_state:SetColour(UICOLOURS.GOLD_UNIMPORTANT)
			elseif state == "update_available" then
				widget.col_state:SetColour(UICOLOURS.GOLD_SELECTED)
			elseif state == "missing" then
				widget.col_state:SetColour(UICOLOURS.GOLD)
			else
				widget.col_state:SetColour(UICOLOURS.GOLD)
			end
			widget.col_id:SetColour(UICOLOURS.GOLD_UNIMPORTANT)
			widget.col_local:SetColour(UICOLOURS.GOLD_UNIMPORTANT)
			widget.col_desired:SetColour(UICOLOURS.GOLD_UNIMPORTANT)

			widget.bg:Show()
			widget.col_id:Show()
			widget.col_local:Show()
			widget.col_desired:Show()
			widget.col_state:Show()
			widget:Show()
		else
			widget.col_id:SetString("")
			widget.col_local:SetString("")
			widget.col_desired:SetString("")
			widget.col_state:SetString("")
			widget.bg:Hide()
			widget:Hide()
		end
	end

	self.options_scroll_list = self.optionspanel:AddChild(TEMPLATES.ScrollingGrid({}, {
		scroll_context = {},
		widget_width = ITEM_W,
		widget_height = ITEM_H,
		num_visible_rows = VISIBLE_ROWS,
		num_columns = 1,
		item_ctor_fn = ScrollWidgetsCtor,
		apply_fn = ApplyDataToWidget,
		scrollbar_offset = 20,
		scrollbar_height_offset = -60,
	}))
	self.options_scroll_list:SetPosition(0, -6)

	self.horizontal_line = self.optionspanel:AddChild(Image("images/global_redux.xml", "item_divider.tex"))
	self.horizontal_line:SetPosition(0, self.options_scroll_list.visible_rows / 2 * ITEM_H)
	self.horizontal_line:SetSize(ITEM_W + 30, 5)

	self.list_count_label = self.optionspanel:AddChild(Text(CHATFONT, 16, "", UICOLOURS.GOLD_UNIMPORTANT))
	self.list_count_label:SetPosition(0, self.options_scroll_list.visible_rows / 2 * ITEM_H + 14)
	self.list_count_label:SetRegionSize(ITEM_W, 18)
	self.list_count_label:SetHAlign(ANCHOR_RIGHT)

	if TheInput:ControllerAttached() then
		self.dialog.actions:Hide()
	end

	self.default_focus = self.options_scroll_list
	if self.dialog.actions then
		self.options_scroll_list:SetFocusChangeDir(MOVE_DOWN, self.dialog.actions)
		self.dialog.actions:SetFocusChangeDir(MOVE_UP, self.options_scroll_list)
	end

	self.channel_label:SetString(translate({ zh = "正在打开…", en = "Opening…" }))
	self.error_label:SetString(translate({ zh = "状态  首帧加载本地列表", en = "Status  loading local list" }))
	self.progress_label:SetString(translate({ zh = "进度  空闲", en = "Prog  idle" }))
	self.list_count_label:SetString("")
end)

function PluginManagerScreen:Close()
	TheFrontEnd:PopScreen(self)
end

function PluginManagerScreen:OnControl(control, down)
	if PluginManagerScreen._base.OnControl(self, control, down) then
		return true
	end
	if self.oncontrol_fn then
		return self.oncontrol_fn(control, down)
	end
	return false
end

function PluginManagerScreen:GetHelpText()
	if self.gethelptext_fn then
		return self.gethelptext_fn()
	end
	return ""
end

function PluginManagerScreen:SelectPlugin(data)
	self.selected = data
end

function PluginManagerScreen:FetchStatus()
	local raw, ok, err = call_api("DS_LUAJIT_plugin_manager_status_json")
	if not ok then
		self.status = {
			plugins = {},
			last_error = "status_json failed: " .. tostring(err),
			progress = { phase = "error", percent = 0, current = 0, total = 0, message = tostring(err) },
		}
		return self.status
	end
	if type(raw) ~= "string" then
		raw = tostring(raw or "")
	end
	local decoded = decode_json(raw)
	if type(decoded) ~= "table" then
		decoded = {
			plugins = {},
			last_error = "status_json decode failed",
			progress = { phase = "error", percent = 0, current = 0, total = 0, message = "decode failed" },
		}
	end
	if type(decoded.plugins) ~= "table" then
		decoded.plugins = {}
	end
	if type(decoded.progress) ~= "table" then
		decoded.progress = { phase = "idle", percent = 0, current = 0, total = 0, message = "" }
	end
	self.status = decoded
	return decoded
end

function PluginManagerScreen:NormalizePluginRows()
	local plugins = {}
	local src = self.status and self.status.plugins
	if type(src) == "table" then
		local n = #src
		if n > 0 then
			for i = 1, n do
				local row = src[i]
				if type(row) == "table" then
					table.insert(plugins, row)
				end
			end
		else
			for id, row in pairs(src) do
				if type(row) == "table" then
					if row.id == nil then
						row.id = id
					end
					table.insert(plugins, row)
				end
			end
			table.sort(plugins, function(a, b)
				return tostring(a.id or "") < tostring(b.id or "")
			end)
		end
	end
	self.plugin_rows = plugins
end

function PluginManagerScreen:RebuildList()
	self:NormalizePluginRows()
	local rows = self.plugin_rows or {}
	self.list_count_label:SetString(string.format(
		translate({ zh = "%d 个插件", en = "%d plugins" }),
		#rows
	))
	if self.options_scroll_list and self.options_scroll_list.SetItemsData then
		self.options_scroll_list:SetItemsData(rows)
	end
	if self.selected then
		local keep = nil
		for _, row in ipairs(rows) do
			if row.id == self.selected.id then
				keep = row
				break
			end
		end
		self.selected = keep
	end
end

function PluginManagerScreen:UpdateLabels()
	local st = self.status or {}
	local channel = str_or(st.channel_name, "-")
	local tag = str_or(st.release_tag, "-")
	local resolved = str_or(st.resolved_release_tag, "-")
	local proxy = str_or(st.prefer_proxy, "-")
	local repo = str_or(st.repo, "-")
	local tag_show = tag
	if resolved ~= "-" and resolved ~= tag then
		tag_show = tag .. "->" .. resolved
	elseif resolved ~= "-" then
		tag_show = resolved
	end

	self.channel_label:SetString(string.format(
		translate({
			zh = "频道 %s   标签 %s   代理 %s   %s",
			en = "ch %s   tag %s   proxy %s   %s",
		}),
		channel, tag_show, proxy, repo
	))

	if is_busy_status(st) then
		self.error_label:SetString(translate({
			zh = "状态  进行中: ",
			en = "Status  busy: ",
		}) .. str_or(st.busy_op, "..."))
		self.error_label:SetColour(UICOLOURS.GOLD_SELECTED)
	elseif st.last_error and st.last_error ~= "" then
		local err = tostring(st.last_error)
		if err:find("plugins%-manifest%.json", 1, false) or err:find("HTTP status 404", 1, true) then
			err = translate({
				zh = "远程无 plugins-manifest.json（404），本地列表仍可用",
				en = "Remote plugins-manifest.json missing (404); local list ok",
			})
		elseif #err > 80 then
			err = err:sub(1, 77) .. "..."
		end
		self.error_label:SetString(translate({ zh = "状态  ", en = "Status  " }) .. err)
		self.error_label:SetColour(UICOLOURS.GOLD)
	else
		local needs = st.needs_restart and translate({ zh = " · 需重启", en = " · restart" }) or ""
		self.error_label:SetString(translate({ zh = "状态  就绪", en = "Status  ready" }) .. needs)
		self.error_label:SetColour(UICOLOURS.GOLD_UNIMPORTANT)
	end
end

function PluginManagerScreen:UpdateProgressUI()
	local st = self.status or {}
	local prog = st.progress or {}
	local phase = str_or(prog.phase, "idle")
	local msg = str_or(prog.message, "")
	local cur = tonumber(prog.current) or 0
	local tot = tonumber(prog.total) or 0
	local pct = prog.percent
	if type(pct) ~= "number" then
		pct = 0
	end

	if not is_busy_status(st) then
		if phase == "done" and msg ~= "-" and msg ~= "" then
			local m = msg
			if #m > 55 then
				m = m:sub(1, 52) .. "..."
			end
			self.progress_label:SetString(translate({ zh = "进度  ", en = "Prog  " }) .. m)
		else
			self.progress_label:SetString(translate({ zh = "进度  空闲", en = "Prog  idle" }))
		end
		self.progress_label:SetColour(UICOLOURS.GOLD_UNIMPORTANT)
		return
	end

	local width = 14
	local bar
	if pct < 0 then
		local n = (math.floor((self._pulse_t or 0) * 4) % (width + 1))
		local filled = math.max(1, n)
		bar = "[" .. string.rep("=", filled) .. string.rep(".", width - filled) .. "]"
	else
		local filled = math.floor(math.max(0, math.min(1, pct)) * width + 0.5)
		bar = "[" .. string.rep("=", filled) .. string.rep(".", width - filled) .. string.format(" %2d%%]",
			math.floor(math.max(0, math.min(1, pct)) * 100 + 0.5))
	end
	local extra = tot > 0 and string.format(" %d/%d", cur, tot) or ""
	local op = str_or(st.busy_op, phase)
	self.progress_label:SetString(string.format("%s %s%s", bar, op, extra))
	self.progress_label:SetColour(UICOLOURS.GOLD_SELECTED)
end

function PluginManagerScreen:StartPoll(opts)
	opts = opts or {}
	self._poll_active = true
	self._poll_elapsed = 0
	self._poll_accum = 0
	if opts.await_apply then
		self._awaiting_apply_result = true
	end
end

function PluginManagerScreen:StopPoll()
	self._poll_active = false
	self._poll_accum = 0
end

function PluginManagerScreen:OnRefresh()
	if is_busy_status(self.status) then
		return
	end
	self.error_label:SetString(translate({ zh = "状态  刷新中…", en = "Status  refreshing…" }))
	call_api("DS_LUAJIT_plugin_config_reload")
	self:FetchStatus()
	self:UpdateLabels()
	self:UpdateProgressUI()
	self:RebuildList()
	call_api("DS_LUAJIT_plugin_fetch_manifest", "")
	self:StartPoll()
	self:FetchStatus()
	self:UpdateLabels()
	self:UpdateProgressUI()
	self:RebuildList()
end

function PluginManagerScreen:OnUpdate(dt)
	dt = dt or 0
	self._pulse_t = (self._pulse_t or 0) + dt

	if self._boot_pending then
		self._boot_pending = false
		local ok, err = pcall(function()
			self:OnRefresh()
		end)
		if not ok then
			self.error_label:SetString("boot error: " .. tostring(err))
			self.error_label:SetColour(UICOLOURS.GOLD)
		end
		return
	end

	if is_busy_status(self.status) then
		self:UpdateProgressUI()
	end

	if not self._poll_active then
		return
	end

	self._poll_elapsed = (self._poll_elapsed or 0) + dt
	if self._poll_elapsed > 180 then
		self:StopPoll()
		self:FetchStatus()
		self:UpdateLabels()
		self:UpdateProgressUI()
		self:RebuildList()
		if self._awaiting_apply_result then
			self._awaiting_apply_result = false
			self:ShowMessage(
				translate({ zh = "超时", en = "Timed out" }),
				translate({
					zh = "操作超时，请检查网络后重试。",
					en = "Operation timed out. Check network and retry.",
				})
			)
		end
		return
	end

	self._poll_accum = (self._poll_accum or 0) + dt
	if self._poll_accum < 0.25 then
		return
	end
	self._poll_accum = 0

	self:FetchStatus()
	self:UpdateLabels()
	self:UpdateProgressUI()
	self:RebuildList()

	if is_busy_status(self.status) then
		return
	end

	self:StopPoll()
	if self._awaiting_apply_result then
		self._awaiting_apply_result = false
		local err = self.status and self.status.last_error
		local phase = self.status and self.status.progress and self.status.progress.phase
		if err and err ~= "" and phase == "error" then
			self:ShowMessage(translate({ zh = "应用失败", en = "Apply failed" }), tostring(err))
		else
			self:MaybeConfirmRestart()
		end
	end
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
		self:ShowMessage(
			translate({ zh = "应用完成", en = "Apply complete" }),
			translate({
				zh = "插件已更新（本次无需重启，或尚未替换已加载模块）。",
				en = "Plugins updated (no restart required, or no loaded module was replaced).",
			})
		)
		return
	end
	self:ShowMessage(
		translate({ zh = "需要重启", en = "Restart required" }),
		translate({
			zh = "部分插件写入 update_pending 或替换了已加载模块，请重启游戏后生效。",
			en = "Some plugins landed in update_pending or replaced a loaded module. Restart the game to apply.",
		})
	)
end

function PluginManagerScreen:OnApplyAll()
	if is_busy_status(self.status) then
		return
	end
	local result, ok, err = call_api("DS_LUAJIT_plugin_apply", "")
	if not ok then
		self:ShowMessage(
			translate({ zh = "应用失败", en = "Apply failed" }),
			tostring(err or "apply export missing")
		)
		return
	end
	if result == false then
		self:FetchStatus()
		self:UpdateLabels()
		self:UpdateProgressUI()
		self:ShowMessage(
			translate({ zh = "应用失败", en = "Apply failed" }),
			tostring((self.status and self.status.last_error) or "apply rejected")
		)
		return
	end
	self:StartPoll({ await_apply = true })
	self:FetchStatus()
	self:UpdateLabels()
	self:UpdateProgressUI()
end

local function open_plugin_manager()
	if not manager_available() then
		show_manual_install_popup()
		return
	end
	local ok, err = pcall(function()
		TheFrontEnd:PushScreen(PluginManagerScreen())
	end)
	if not ok then
		TheFrontEnd:PushScreen(PopupDialogScreen(
			translate({ zh = "插件管理", en = "Plugin Manager" }),
			"PushScreen failed: " .. tostring(err),
			{
				{
					text = STRINGS.UI.MAINSCREEN.OK or "OK",
					cb = function()
						TheFrontEnd:PopScreen()
					end,
				},
			}
		))
	end
end

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
