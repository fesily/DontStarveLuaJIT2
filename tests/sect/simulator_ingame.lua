local arg = arg or { ... }

local hook_files = {}
local autohook_files = false;

local function parser_args()
    --[[
	-f <filename> <hook_file> hook_file
	]]
    for i, v in ipairs(arg) do
        if v == "-f" then
            i = i + 1
            local filename = arg[i]
            if filename then
                i = i + 1
                local hook_file = arg[i]
                if hook_file then
                    hook_files[filename] = hook_file
                    print("Hook file for " .. filename .. " is set to " .. hook_file)
                else
                    print("No hook file specified for " .. filename)
                end
            else
                print("No filename specified after -f")
            end
        elseif v == '--autohookfiles' then
            autohook_files = true
            print("autohook_files is set to true")
        end
    end
end

local function parser_env()
    --[[
	--hook_files <filename>:<hook_file>;<filename1>:<hook_file1>
	]]
    local hook_files_str = os.getenv("hook_files")
    if hook_files_str then
        for pair in string.gmatch(hook_files_str, "([^;]+)") do
            local filename, hook_file = pair:match("([^:]+):(.+)")
            if filename and hook_file then
                hook_files[filename] = hook_file
                print("Hook file for " .. filename .. " is set to " .. hook_file)
            else
                print("Invalid format for hook_files: " .. pair)
            end
        end
    end
    local val = os.getenv("autohook_files")
    if val then
        autohook_files = (val == "true" or val == "1")
        print("autohook_files is set to " .. tostring(autohook_files))
    end
end

parser_env()
parser_args()

local function chunkname2filename(chunkname)
    chunkname = chunkname:gsub("[%/%\\]", "_")
    chunkname = "unsafedata/" .. chunkname
    return chunkname
end

local function readfile(filename)
    local fp = io.open(filename, "r")
    if fp then
        local code = fp:read("*a")
        fp:close()
        return code
    end
    return nil
end

local function fileexsits(filepath)
    local fp = io.open(filepath, "r")
    if fp then
        fp:close()
        return true
    end
    return false
end

local function readHookFile(chunkname)
    if autohook_files and not hook_files[chunkname] then
        local filename = chunkname2filename(chunkname)
        if fileexsits(filename) then
            hook_files[chunkname] = filename
            print("Auto hook file for " .. chunkname .. " is set to " .. filename)
        else
            print("No auto hook file found for " .. chunkname)
        end
    end
    if hook_files[chunkname] then
        local code = readfile(hook_files[chunkname])
        if code then
            print("Hook file loaded:", chunkname, code)
            return code
        end
    end
    return nil
end

local HOOK_APIS = {
    debug = {
        getinfo = {
            __hooker = nil,
        },
        sethook = {
            __hooker = false
        },
    },
    load = {
        __hooker = function(hooker, old_load)
            hooker.load_get_thunk_func = nil
            hooker.load_codes = nil
            local function get_thunk()
                local code = hooker.load_get_thunk_func()
                hooker.load_codes = (hooker.load_codes or '') .. code
                return code
            end
            return function(chunk, chunkname, mode, env)
                print("load:", chunkname, mode)
                chunk = readHookFile(chunkname) or chunk
                if type(chunk) == "string" then
                    return old_load(chunk, chunkname, mode, env)
                end
                assert(type(chunk) == 'function')
                hooker.load_get_thunk_func = chunk
                hooker.load_codes = nil
                local fn = old_load(get_thunk, chunkname, mode, env)
                -- replace chunkname path to safe filename
                if hooker.load_codes and #hooker.load_codes > 0 then
                    local fp = io.open(chunkname2filename(chunkname), "w")
                    if not fp then
                        print("Failed to open file for writing: " .. chunkname)
                        return fn
                    end
                    fp:write(hooker.load_codes)
                    fp:close()
                end
                return fn
            end
        end
    },
    loadstring = {
        __hooker = function(hooker, old_loadstring)
            return function(chunk, chunkname)
                print("loadstring:", chunkname)
                chunk = readHookFile(chunkname) or chunk
                return old_loadstring(chunk, chunkname)
            end
        end
    },
}
HOOK_APIS.debug.getinfo = function(hooker, old_debug_getinfo)
    return function(f, what)
        print("debug.getinfo:", f, what)
        if (type(f) == 'number') and f > 0 then
            f = f + 2             --跳过getinfo的cproxy luaproxy
            -- 判断一下 是不是在load函数里面执行的, 这个地方执行的话直接,跳过load函数堆栈,应该有两层, get_thunk, proxy, luaproxy, load
            local info = old_debug_getinfo(f, 'f')
            if info.func == HOOK_APIS.load.get_thunk then
                f = f + 3
            elseif info.func == HOOK_APIS.load.load_function_proxy then
                f = f + 2
            elseif info.func == HOOK_APIS.load.__newval then
                f = f + 1
            end
        end
        return old_debug_getinfo(f, what)
    end
end

local function HookApi(key, hooker)
    if hooker.__hooker then
        local old_val = _G[key]
        assert(old_val, "Hook API " .. key .. " not found in global environment.")
        local new_fn = hooker.__hooker == false and function() end or hooker:__hooker(old_val)
        _G[key] = newproxy(new_fn) -- create a proxy that does nothing
        hooker.__val = old_val
        hooker.__newval = new_fn
    else
        local subtable = _G[key]
        assert(subtable, "Hook API " .. key .. " not found in global environment.")
        assert(type(subtable) == "table", "Hook API " .. key .. " is not a table.")
        for k, v in pairs(subtable) do
            HookApi(k, v)
        end
    end
end

local function ResetHookApi(key, hooker)
    if hooker.__newval then
        _G[key] = hooker.__val
    else
        local subtable = _G[key]
        assert(subtable, "Reset Hook API " .. key .. " not found in global environment.")
        assert(type(subtable) == "table", "Reset Hook API " .. key .. " is not a table.")
        for k, v in pairs(subtable) do
            ResetHookApi(k, v)
        end
    end
end

local function StartHook()
    for k, v in pairs(HOOK_APIS) do
        HookApi(k, v)
    end
end

local function StopHook()
    for k, v in pairs(HOOK_APIS) do
        ResetHookApi(k, v)
    end
end


function ModWrangler:TryLoadMod(modname)
    local initenv = KnownModIndex:GetModInfo(modname)
    local env = CreateEnvironment(modname, self.worldgen)
    env.modinfo = initenv
    local t = {}
    env.MYPRINT = function(str, level)
        t[#t + 1] = { str, level }
    end
    StartHook()

    local mod = env
    local old_modimport = env.modimport
    function mod.modimport(modulename)
        return old_modimport(modulename)
    end

    package.path = MODS_ROOT .. mod.modname .. "\\scripts\\?.lua;" .. package.path
    local manifest
    --manifests are on by default for workshop mods, off by default for local mods.
    --manifests can be toggled on and off in modinfo with forcemanifest = false or forcemanifest = true
    if ((mod.modinfo.forcemanifest == nil and IsWorkshopMod(mod.modname)) or
            (mod.modinfo.forcemanifest ~= nil and mod.modinfo.forcemanifest)) then
        ManifestManager:LoadModManifest(mod.modname, mod.modinfo.version)
        manifest = mod.modname
    end
    table.insert(package.assetpath, { path = MODS_ROOT .. mod.modname .. "\\", manifest = manifest })

    self.currentlyloadingmod = mod.modname
    self:InitializeModMain(mod.modname, mod, "modworldgenmain.lua")
    if not self.worldgen then
        -- worldgen has to always run (for customization screen) but modmain can be
        -- skipped for worldgen. This reduces a lot of issues with missing globals.
        self:InitializeModMain(mod.modname, mod, "modmain.lua")
    end
    self.currentlyloadingmod = nil
    StopHook()
    if #t > 0 then
        local fp = io.open("unsafedata/ok.txt", "w")
        local levels = {
            [0] = "",
            "\t",
            "\t\t",
            "\t\t\t",
            "\t\t\t\t",
            "\t\t\t\t\t",
            "\t\t\t\t\t\t",
            "\t\t\t\t\t\t\t",
        }
        for i, v in ipairs(t) do
            local str, level = v[1], v[2]
            fp:write(levels[level] .. tostring(str) .. "\n")
        end
        fp:close()
    else
        print("Mod: " .. ModInfoname(modname), "  No print statements in modmain.")
    end
end
