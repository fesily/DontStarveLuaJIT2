-- 隔离验证原生启动引导和模组内禁用逻辑，不启动游戏、不改玩家配置。
local root = os.getenv("REPO_ROOT") or "."
local real, virtual, other = "workshop-3444078585", "DontStarveLuaJIT2-Server", "other-mod"
local checks = 0
local function check(value, message)
    checks = checks + 1
    assert(value, message)
end

local function fixture(native, dedicated)
    local env = setmetatable({}, { __index = _G })
    env._G, env.GLOBAL = env, env
    env.env = { modname = real }
    env.package = { loaded = {} }
    env.kleiloadlua = function() end
    env.print = function() end
    env.TheNet = { IsDedicated = function() return dedicated end }
    local index = { savedata = { known_mods = {
        [real] = { enabled = false, temp_disabled = true, modinfo = {} },
        [virtual] = { enabled = false, modinfo = {} },
        [other] = { enabled = true, modinfo = {} },
    } } }
    function index:UpdateModInfo() self.updates = (self.updates or 0) + 1 end
    function index:InitializeModInfo() return {} end
    function index:Disable(name) self.savedata.known_mods[name].enabled = false end
    function index:DisableAllMods() for name in pairs(self.savedata.known_mods) do self:Disable(name) end end
    function index:TempDisable(name) self.savedata.known_mods[name].temp_disabled = true end
    function index:IsModEnabled(name) return self.savedata.known_mods[name].enabled end
    function index:Enable(name)
        local row = self.savedata.known_mods[name]
        row.enabled, row.disabled_bad, row.disabled_incompatible_with_mode = true, false, false
    end
    function index:DisableBecauseBad(name)
        local row = self.savedata.known_mods[name]
        row.disabled_bad, row.enabled = true, false
    end
    function index:GetModsToLoad()
        local result = {}
        for _, name in ipairs({ real, other }) do
            local row = self.savedata.known_mods[name]
            if row and row.enabled and not row.temp_disabled then result[#result + 1] = name end
        end
        return result
    end
    env.require = function(name)
        assert(name == "modindex")
        env.KnownModIndex = index
        return true
    end
    if native then
        local chunk = assert(loadfile(root .. "/src/DontStarveInjector/plugins/plugin_core_vm/injector/GameLuaInjectFramework.lua"))
        setfenv(chunk, env)
        chunk({ info = function() end, warn = function() end, error = function() end })
        env.GameLuaInjector.init()
        env.GameLuaInjector.requireLuaJITMod(real)
        env.require("modindex")
    else
        env.KnownModIndex = index
    end
    local postinits = {}
    env.AddClassPostConstruct = function(name, fn) postinits[name] = fn end
    local function load_mod()
        local chunk = assert(loadfile(root .. "/Mod/force_enable_mod.lua"))
        setfenv(chunk, env)
        chunk()
    end
    return env, index, postinits, load_mod
end

local function screen_fixture(index, postinits, replace_set_mod, readonly)
    local checkbox = { enabled = true, shown = true, image = {} }
    function checkbox.image:SetTint(r, g, b, a) self.tint = { r, g, b, a } end
    function checkbox:Disable()
        self.enabled = false
        self.texture = self.image_disabled
        self.image:SetTint(unpack(self.imagedisabledcolour))
    end
    function checkbox:Enable() self.enabled = true; self.texture = self.image_normal end
    function checkbox:SetImageDisabledColour(...) self.imagedisabledcolour = { ... } end
    local opt = { checkbox = checkbox, status = { shown = true } }
    function opt:SetModReadOnly(value) self.checkbox.shown = not value; self.status.shown = not value end
    function opt:SetModEnabled(enabled)
        self.checkbox.image_normal = enabled and "checked" or "unchecked"
        -- 原版 SetTextures 会按当前 enabled 状态立即刷新禁用纹理与颜色。
        self.checkbox.image_disabled = enabled and "unchecked" or "checked"
        if not self.checkbox.enabled then self.checkbox:Disable() end
    end
    function opt:SetMod(name) self:SetModEnabled(index:IsModEnabled(name)) end
    if replace_set_mod then
        function opt:SetMod(name)
            self.folder_label = name
            self:SetModEnabled(index:IsModEnabled(name))
            return "replacement", 43
        end
    end
    function opt:GetHelpText() return "Toggle" end
    local widget = { moditem = opt, data = { mod = { modname = real } } }
    local screen = { settings = { is_configuring_server = true }, currentmodtype = "client",
        optionwidgets_client = { { mod = { modname = real } }, { mod = { modname = other } } },
        optionwidgets_server = { { mod = { modname = virtual } } },
        mods_scroll_list = { GetListWidgets = function() return { widget } end } }
    function screen:OnConfirmEnable(_, name)
        if index:IsModEnabled(name) then index:Disable(name) else index:Enable(name) end
        self.toggles = (self.toggles or 0) + 1
        return "toggled", 17
    end
    function screen:EnableCurrent(i)
        local items = self.currentmodtype == "client" and self.optionwidgets_client or self.optionwidgets_server
        return self:OnConfirmEnable(false, items[i].mod.modname)
    end
    function screen:UpdateModsOrder() return "updated", 29 end
    function screen:Apply() return index:IsModEnabled(virtual), 31 end
    opt:SetModReadOnly(readonly)
    opt:SetMod(real)
    if postinits["widgets/redux/modstab"] then postinits["widgets/redux/modstab"](screen) end
    local function bind(name)
        widget.data.mod.modname = name
        opt:SetMod(name)
    end
    return screen, opt, bind
end

for _, replace_set_mod in ipairs({ false, true }) do
    local env, index, postinits, load_mod = fixture(true, false)
    index:UpdateModInfo()
    check(index:GetModsToLoad()[1] == real, "disabled/temp-disabled companion did not bootstrap")
    check(next(postinits) == nil, "native framework installed UI hooks")
    load_mod()
    check(index:IsModEnabled(virtual), "virtual entry did not enable")
    local screen, opt, bind = screen_fixture(index, postinits, replace_set_mod, false)
    check(opt.checkbox.shown and opt.status.shown and not opt.checkbox.enabled, "checkbox not visibly disabled")
    check(opt.checkbox.texture == "checked" and opt.checkbox.image.tint[1] == .5, "disabled checkbox lost gray check")
    check(opt:GetHelpText() == "", "controller advertises locked toggle")
    screen:EnableCurrent(1)
    screen:OnConfirmEnable(false, virtual)
    check(screen.toggles == nil, "mouse/controller changed protected mod")
    index:Disable(real); index:TempDisable(real)
    check(index:IsModEnabled(real) and not index.savedata.known_mods[real].temp_disabled, "direct disable bypassed lock")
    local a, b = screen:EnableCurrent(2)
    check(a == "toggled" and b == 17, "ordinary toggle lost return values")
    bind(other)
    check(opt.checkbox.enabled and opt.checkbox.image.tint[1] == 1 and opt:GetHelpText() == "Toggle", "recycled row retained gray/disabled state")
    screen.currentmodtype = "server"
    bind(virtual)
    screen:EnableCurrent(1)
    check(not opt.checkbox.enabled and opt.checkbox.shown and screen.toggles == 1, "server toggle unlocked")
    if replace_set_mod then check(opt.folder_label == virtual, "mod folder replacement was lost") end
    opt:SetModReadOnly(true)
    bind(real); bind(other)
    check(not opt.checkbox.shown and not opt.status.shown, "original read-only state changed")
    opt:SetModReadOnly(false)
    bind(real)
    index:DisableAllMods()
    check(index:IsModEnabled(real), "bulk disable disabled companion")
    a, b = screen:UpdateModsOrder()
    check(a == "updated" and b == 29 and index:IsModEnabled(virtual), "server refresh did not restore virtual mod")
    index:Disable(virtual)
    check(not index:IsModEnabled(virtual), "virtual frontend cleanup blocked")
    a, b = screen:Apply()
    check(a and b == 31, "server apply saved disabled virtual entry")
    local creation = { Create = function() return index:IsModEnabled(virtual), 37 end }
    postinits["screens/redux/servercreationscreen"](creation)
    index:Disable(virtual)
    a, b = creation:Create()
    check(a and b == 37, "server creation did not restore virtual entry")
    index:DisableBecauseBad(real)
    bind(real)
    check(not index:IsModEnabled(real) and opt.checkbox.enabled, "crash recovery was blocked")
    index:UpdateModInfo()
    for _, name in ipairs(index:GetModsToLoad()) do check(name ~= real, "native bootstrap undid crash disable") end
    screen.currentmodtype = "client"
    screen:EnableCurrent(1)
    bind(real)
    check(index:IsModEnabled(real) and not opt.checkbox.enabled and opt.checkbox.texture == "checked", "manual re-enable did not relock")
    index.badload = true
    index:DisableAllMods()
    bind(real)
    check(opt.checkbox.enabled and #index:GetModsToLoad() == 0, "startup recovery did not unlock")
    index.badload = nil
    for _, field in ipairs({ "disabled_bad", "disabled_incompatible_with_mode" }) do
        index.savedata.known_mods[real][field] = true
        bind(real)
        check(opt.checkbox.enabled, "invalid companion stayed locked: " .. field)
        index.savedata.known_mods[real][field] = false
    end
    index.savedata.known_mods[real].modinfo.failed = true
    bind(real)
    check(opt.checkbox.enabled, "failed mod stayed locked")
    index.savedata.known_mods[real].modinfo = nil
    bind(real)
    check(opt.checkbox.enabled, "missing metadata stayed locked")
    index.savedata.known_mods[real] = nil
    for _, name in ipairs(index:GetModsToLoad()) do check(name ~= real, "missing mod was invented") end
    print("PASS: mod-side gray toggle (replacement=" .. tostring(replace_set_mod) .. ")")
end

do
    local _, index, postinits, load_mod = fixture(false, false)
    load_mod()
    check(next(postinits) == nil, "no DLL still installed UI hooks")
    index:Enable(real); index:Disable(real)
    check(not index:IsModEnabled(real), "no DLL prevented disabling")
end

do
    local _, index, postinits, load_mod = fixture(true, true)
    index:GetModsToLoad()
    load_mod()
    check(next(postinits) == nil, "dedicated server loaded UI classes")
    index:Disable(real)
    check(index:IsModEnabled(real), "dedicated server companion was disabled")
end

do
    local env, index = fixture(true, false)
    env.GameLuaInjector.forceEnableLuaMod(true, other)
    env.require("modindex")
    index:UpdateModInfo()
    index:Disable(other)
    check(not index:IsModEnabled(other), "generic forced mod became locked")
end

do
    local _, index, postinits, load_mod = fixture(true, false)
    index.savedata.known_mods[real].disabled_bad = true
    index:UpdateModInfo()
    for _, name in ipairs(index:GetModsToLoad()) do check(name ~= real, "previous crash was ignored during bootstrap") end
    index:Enable(real)
    check(index:GetModsToLoad()[1] == real, "manually recovered companion did not bootstrap")
    load_mod()
    local _, opt = screen_fixture(index, postinits, false, false)
    check(not opt.checkbox.enabled, "recovered mod did not install gray toggle")
    index.startingup = true
    index:Disable(real)
    check(not index:IsModEnabled(real), "startup disable was blocked")
end
print("Required-mod checks passed: " .. checks)
