-- config_patch_screen_spec.lua
-- Regression for the /史诗 (Epic Healthbar) crash: a foreign mod subclasses
-- ModConfigurationScreen with Class(), which shallow-copies the base class.
-- The copy predates this patch, so calling ModConfigurationScreen._ctor(self, ...)
-- on such an instance used to fail with
--   "attempt to call method 'RefreshDisabledStates' (a nil value)".
-- The patch is also scoped to its owning mod: foreign screens keep the vanilla
-- behaviour and must not be touched.
-- Runner: tests/config_patch/run_spec.py

local REPO_ROOT = (os.getenv("REPO_ROOT") or "")
if REPO_ROOT == "" then
    REPO_ROOT = (debug.getinfo(1, "S").source:gsub("^@?", ""):gsub("\\", "/"):match("^(.*)/tests/config_patch/[^/]+$")) or "."
end
REPO_ROOT = REPO_ROOT:gsub("\\", "/")

local OWNER = "workshop-3444078585"
local FOREIGN = "workshop-1185229307"

local failures = 0
local function check(cond, msg)
    if not cond then
        failures = failures + 1
        io.stderr:write("[FAIL] " .. tostring(msg) .. "\n")
    else
        print("[ok] " .. tostring(msg))
    end
end

UICOLOURS = { GOLD = { 1, 1, 1, 1 } }
STRINGS = { UI = { MODSSCREEN = {
    RESTART_TITLE = "Restart required",
    RESTART_REQUIRED = "Restart required",
    RESTART = "Restart",
    CANCEL = "Cancel",
} } }

-- fakes ---------------------------------------------------------------
package.preload["config_patch_bootstrap/config_patch_helpers"] = function()
    return {
        IsOptionDisabled = function(opt)
            opt.is_disabled_seen = true
            return opt.name == "disabled_opt"
        end,
        HasRequireRestartChanges = function(self) return self.has_restart_changes == true end,
    }
end
package.preload["screens/redux/popupdialog"] = function()
    return function() return { kind = "restart_prompt" } end
end

local function widget(opt)
    local s = { opt = { data = { option = opt }, spinner = {}, label = {} } }
    s.opt.spinner.Disable = function() s.disabled = true end
    s.opt.spinner.Enable = function() s.enabled = true end
    s.opt.label.SetColour = function(_, ...) s.colour = { ... } end
    return s
end

local Base = {}
Base.__index = Base
function Base.new() return setmetatable({}, Base) end
function Base:_ctor(modname)
    self.modname = modname
    self.client_config = true
    self.config = {}
    self.options = { { name = "disabled_opt" }, { name = "enabled_opt" } }
    self.w_d = widget(self.options[1])
    self.w_e = widget(self.options[2])
    self.options_scroll_list = {
        widgets_to_update = { self.w_d, self.w_e },
        RefreshView = function() end,
    }
end
function Base:IsDirty() return self.dirty == true end
function Base:CollectSettings() return {} end
function Base:MakeDirty(v) self.dirty = v end
function Base:ResetToDefaultValues() self.reset_called = true end
function Base:Apply() self.apply_called = true end
package.preload["screens/redux/modconfigurationscreen"] = function() return Base end

-- a foreign mod's subclass, copied BEFORE the patch installs ----------
local Sub = {}
for k, v in pairs(Base) do Sub[k] = v end
Sub.__index = Sub
Sub._base = Base
function Sub.new() return setmetatable({}, Sub) end
function Sub:_ctor(modname)
    Base._ctor(self, modname)  -- Epic Healthbar's ConfigurationScreen calls this
end

-- install --------------------------------------------------------------
local patch = REPO_ROOT .. "/Mod/scripts/config_patch_bootstrap/config_patch_screen.lua"
local install = assert(loadfile(patch), "cannot load " .. patch)()
check(type(install) == "function", "patch exposes an installer function")
install(OWNER)

-- own mod's screen: enhancements apply --------------------------------
local own = Base.new()
local ok, err = pcall(Base._ctor, own, OWNER)
check(ok, "owner screen ctor survives: " .. tostring(err))
check(own.w_d.disabled == true, "owner: disabled option spinner:Disable called")
check(own.w_d.colour and own.w_d.colour[1] == 0.5, "owner: disabled option label greyed")
check(own.w_e.enabled == true, "owner: enabled option spinner:Enable called")
check(own.w_e.colour and own.w_e.colour[1] == UICOLOURS.GOLD, "owner: enabled option label GOLD")

-- foreign screen (Epic Healthbar subclass): untouched -----------------
local foreign = Sub.new()
local ok2, err2 = pcall(Sub._ctor, foreign, FOREIGN)
check(ok2, "foreign subclass ctor survives (was: RefreshDisabledStates nil): " .. tostring(err2))
check(foreign.options[1].is_disabled == nil, "foreign screen options not patched")
check(foreign.w_d.disabled == nil and foreign.w_e.enabled == nil, "foreign widgets untouched")

-- foreign instance that still enters our ctor path: no method needed --
local stray = Sub.new()
local ok3, err3 = pcall(Base._ctor, stray, OWNER)
check(ok3, "local-helper path works on a foreign instance: " .. tostring(err3))
check(stray.w_d.disabled == true, "local-helper path still refreshes the stray screen")

-- ResetToDefaultValues / Apply scoping -------------------------------
local own2 = Base.new(); Base._ctor(own2, OWNER)
pcall(Base.ResetToDefaultValues, own2)
check(own2.reset_called == true and own2.options[1].is_disabled ~= nil, "owner reset refreshes states")

local foreign2 = Sub.new(); Base._ctor(foreign2, FOREIGN)
pcall(Base.ResetToDefaultValues, foreign2)
check(foreign2.reset_called == true and foreign2.options[1].is_disabled == nil,
    "foreign reset: original behaviour only")

local pushes = 0
TheFrontEnd = { PushScreen = function() pushes = pushes + 1 end, PopScreen = function() end }
local own3 = Base.new(); Base._ctor(own3, OWNER)
own3.dirty = true; own3.options.has_restart_changes = true
pcall(Base.Apply, own3)
check(pushes == 1 and own3.apply_called == nil, "owner Apply with restart changes shows prompt")

local foreign3 = Sub.new(); Base._ctor(foreign3, FOREIGN)
foreign3.dirty = true; foreign3.options.has_restart_changes = true
pcall(Base.Apply, foreign3)
check(foreign3.apply_called == true, "foreign Apply goes through the original implementation")

check(type(Base.RefreshDisabledStates) == "function", "public method still exported")

if failures > 0 then
    io.stderr:write(string.format("%d failure(s)\n", failures))
    os.exit(1)
end
print("all config_patch_screen checks passed")
