
-- strict-like parent
local declared = {print=true, pairs=true, ipairs=true, type=true, pcall=true, error=true, assert=true,
  setmetatable=true, getmetatable=true, rawget=true, rawset=true, setfenv=true, getfenv=true,
  loadfile=true, require=true, table=true, string=true, math=true, tostring=true, tonumber=true,
  _G=true, package=true, select=true, next=true, unpack=true}
local parent = {}
setmetatable(parent, {
  __index = function(t,k)
    if not declared[k] then error("variable '"..tostring(k).."' is not declared", 2) end
    return rawget(t,k)
  end,
  __newindex = function(t,k,v)
    if not declared[k] then error("assign to undeclared '"..tostring(k).."'", 2) end
    rawset(t,k,v)
  end,
})
for k,v in pairs(_G) do if type(v)~="userdata" then rawset(parent,k,v); declared[k]=true end end
-- undeclare when specifically if any
declared["when"]=nil
rawset(parent, "when", nil)

package.path = "Mod/?.lua;"..package.path
local R = loadfile("Mod/plugins/package_load.lua")()
local api = {
  MODROOT="Mod/",
  kleiloadlua=function(p) local f,e=loadfile(p); return f or e end,
  parent_env=parent,
  GetModConfigData=function() end,
  print=print,
}
local ok, err = pcall(function() return R.load_package("plugin_network_rpc", api) end)
print("network_rpc", ok, err)
local ok2, err2 = pcall(function() return R.load_package("plugin_debug_profiler", api) end)
print("profiler", ok2, err2)
