
package.path = "Mod/?.lua;Mod/?/init.lua;" .. package.path
-- simulate mod env with strict
local env = {
  modname = "workshop-3444078585",
  MODROOT = "Mod/",
  print = print,
  pairs = pairs, ipairs = ipairs, type = type, pcall = pcall, require = require,
  tostring = tostring, assert = assert, error = error, setmetatable = setmetatable,
  rawget = rawget, rawset = rawset, getmetatable = getmetatable,
  table = table, string = string, math = math,
  TheNet = { IsDedicated = function() return false end },
  TheFrontEnd = nil,
  AddGamePostInit = function(fn) print("AddGamePostInit registered") end,
  LOC = { GetLocaleCode = function() return "en" end },
  STRINGS = { UI = { MODSSCREEN = { CANCEL = "Cancel" } } },
  KnownModIndex = { IsModEnabled = function() return false end, GetModInfo = function() return {} end },
}
-- strict-like
local declared = {}
local mt = {
  __index = function(t,k)
    if not declared[k] then error("variable '"..tostring(k).."' is not declared", 2) end
    return rawget(t,k)
  end,
  __newindex = function(t,k,v)
    if not declared[k] then error("assign to undeclared variable '"..tostring(k).."'", 2) end
    rawset(t,k,v)
  end,
}
-- don't use strict for first test - just load
local chunk, err = loadfile("Mod/scripts/luajit_plugin_pack_enable_warn.lua")
if not chunk then print("loaderr", err); os.exit(1) end
setfenv = setfenv or function(fn, e)
  -- luajit 5.1 has setfenv
  if debug and debug.setupvalue then
    -- lua 5.2+
  end
  return setfenv(fn, e)
end
if _VERSION == "Lua 5.1" or (type(jit)=="table") then
  setfenv(chunk, env)
  local ok, res = pcall(chunk)
  print("run", ok, res)
else
  local ok, res = pcall(chunk)
  print("run52", ok, res)
end
