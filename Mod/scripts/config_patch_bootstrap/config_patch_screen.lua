local helpers = require("config_patch_bootstrap/config_patch_helpers")
local ModConfigurationScreen = require "screens/redux/modconfigurationscreen"
local PopupDialogScreen = require "screens/redux/popupdialog"

local _original_ctor = ModConfigurationScreen._ctor

ModConfigurationScreen._ctor = function(self, modname, client_config)
    _original_ctor(self, modname, client_config)

    local raw_by_name = {}
    if self.config and type(self.config) == "table" then
        for _, v in ipairs(self.config) do
            if v.name then
                raw_by_name[v.name] = v
            end
        end
    end

    for _, opt in ipairs(self.options) do
        opt.initial_value   = opt.value
        local raw           = raw_by_name[opt.name]
        if raw then
            opt.disabled_by     = raw.disabled_by
            opt.require_restart = raw.require_restart
        end
    end

    for _, widget in ipairs(self.options_scroll_list.widgets_to_update or {}) do
        local original_on_changed = widget.opt.spinner.OnChanged
        if original_on_changed then
            local screen = self
            widget.opt.spinner.OnChanged = function(spinner_self, data)
                original_on_changed(spinner_self, data)
                screen:RefreshDisabledStates()
            end
        end
    end

    local scroll_list        = self.options_scroll_list
    local original_refresh   = scroll_list.RefreshView
    local screen             = self
    scroll_list.RefreshView  = function(sl, ...)
        original_refresh(sl, ...)
        screen:RefreshDisabledStates()
    end

    self:RefreshDisabledStates()
end

function ModConfigurationScreen:RefreshDisabledStates()
    local options_by_name = {}
    for _, opt in ipairs(self.options) do
        options_by_name[opt.name] = opt
    end

    for _, opt in ipairs(self.options) do
        opt.is_disabled = helpers.IsOptionDisabled(opt, options_by_name)
    end

    for _, widget in ipairs(self.options_scroll_list.widgets_to_update or {}) do
        if widget.opt and widget.opt.data and widget.opt.data.option then
            local opt = widget.opt.data.option
            if opt.is_disabled then
                widget.opt.spinner:Disable()
                widget.opt.label:SetColour(0.5, 0.5, 0.5, 1)
            else
                widget.opt.spinner:Enable()
                widget.opt.label:SetColour(UICOLOURS.GOLD)
            end
        end
    end
end

local _original_reset = ModConfigurationScreen.ResetToDefaultValues
function ModConfigurationScreen:ResetToDefaultValues()
    _original_reset(self)
    self:RefreshDisabledStates()
end

local _original_apply = ModConfigurationScreen.Apply
function ModConfigurationScreen:Apply()
    if self:IsDirty() then
        if helpers.HasRequireRestartChanges(self.options) then
            local settings = self:CollectSettings()
            TheFrontEnd:PushScreen(PopupDialogScreen(
                STRINGS.UI.MODSSCREEN.RESTART_TITLE,
                STRINGS.UI.MODSSCREEN.RESTART_REQUIRED,
                {
                    {
                        text = STRINGS.UI.MODSSCREEN.RESTART,
                        cb = function()
                            KnownModIndex:SaveConfigurationOptions(function()
                                self:MakeDirty(false)
                                TheSim:Quit()
                            end, self.modname, settings, self.client_config)
                        end,
                    },
                    {
                        text = STRINGS.UI.MODSSCREEN.CANCEL,
                        cb = function()
                            TheFrontEnd:PopScreen()
                        end,
                    },
                }
            ))
        else
            _original_apply(self)
        end
    else
        _original_apply(self)
    end
end

return true
