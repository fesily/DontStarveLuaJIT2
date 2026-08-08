
local ROOT = (os.getenv("REPO_ROOT") or "."):gsub("\\", "/")
package.path = ROOT .. "/Mod/?.lua;" .. ROOT .. "/Mod/?/init.lua;" .. package.path

-- Load script without running TheNet path: provide stubs
_G.modname = "DontStarveLuaJit2"
_G.TheNet = { IsDedicated = function() return true end } -- skip auto hook
_G.TheFrontEnd = nil
_G.LOC = { GetLocaleCode = function() return "en" end }
_G.STRINGS = { UI = { MODSSCREEN = { CANCEL = "Cancel" } } }
_G.KnownModIndex = {
  IsModEnabled = function(_, n) return n == "already_on" end,
  GetModInfo = function(_, n)
    if n == "pack" then return { luajit_plugin_pack = true } end
    if n == "plain" then return { name = "plain" } end
    if n == "already_on" then return { luajit_plugin_pack = true } end
    return nil
  end,
}

-- loadfile as modimport substitute
local chunk = assert(loadfile(ROOT .. "/Mod/scripts/luajit_plugin_pack_enable_warn.lua"))
local M = chunk()
assert(type(M) == "table" and type(M.should_warn) == "function")
M.set_this_modname("DontStarveLuaJit2")
assert(M.should_warn("pack") == true)
assert(M.should_warn("plain") == false)
assert(M.should_warn("already_on") == false)
assert(M.should_warn("DontStarveLuaJit2") == false)
assert(M.should_warn(nil) == false)
print("ALL PASS enable_warn_spec")
