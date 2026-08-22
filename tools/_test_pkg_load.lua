
package.path = "Mod/?.lua;Mod/?/init.lua;"..package.path
local R = require("plugins.package_load")
local api = {
  MODROOT = "Mod/",
  kleiloadlua = function(p)
    local f, err = loadfile(p)
    if not f then return err end
    return f
  end,
  parent_env = _G,
  GetModConfigData = function() return nil end,
  print = print,
}
local ok, err = pcall(function()
  return R.load_package("plugin_debug_profiler", api)
end)
print("load_package result", ok, err)
