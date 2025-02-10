_G = GLOBAL

local hasluajit, jit = _G.pcall(require, "jit")
if not hasluajit then
	return
end

if not _G.TheNet:IsDedicated() then
	local fp = _G.io.open("unsafedata/luajit_config.json", "w")
	if fp then
		local config = {
			modmain_path = _G.debug.getinfo(1).source,
			server_disable_luajit = GetModConfigData("DisableJITWhenServer"),
		}
		fp:write(_G.json.encode(config))
        fp:close()
	end
end

local old_GetServerModNames = _G.KnownModIndex.GetServerModNames
local old_GetServerModNamesTable = _G.KnownModIndex.GetServerModNamesTable
local old_GetEnabledServerModNames = _G.ModManager.GetEnabledServerModNames

_G.KnownModIndex.GetServerModNames = function (...)
    local names = old_GetServerModNames(...)
    table.insert(names, modname)
    return names
end

_G.KnownModIndex.GetServerModNamesTable = function (...)
    local names = old_GetServerModNamesTable(...)
    table.insert(names,  {modname = modname})
    return names
end
_G.ModManager.GetEnabledServerModNames = function (...)
	local names = old_GetEnabledServerModNames(...)
    table.insert(names, modname)
    return names
end

if GetModConfigData("EnabledJIT") then
	local TEMPLATES = require("widgets/redux/templates")
	local old_getbuildstring = TEMPLATES.GetBuildString
	TEMPLATES.GetBuildString = function()
		return (old_getbuildstring() or "") .. "(LuaJIT)"
	end

	if GetModConfigData("JitOpt") then
		require("jit.opt").start(
			"minstitch=2",
			"maxtrace=4000",
			"maxrecord=8000",
			"sizemcode=64",
			"maxmcode=4000",
			"maxirconst=1000"
		)
	end

	local enbaleBlackList = GetModConfigData("ModBlackList")

	AddSimPostInit(function()
		jit.on()

		local prefix = "../mods/workshop-"
		local blacklists = {}
		if enbaleBlackList and #blacklists > 0 then
			for i in ipairs(blacklists) do
				blacklists[i] = prefix .. blacklists[i]
			end
			local function startWith(str, prefix)
				return str:find(prefix, 1, true) == 1
			end
			local _kleiloadlua = _G.kleiloadlua
			_G.kleiloadlua = function(script, ...)
				local m = _kleiloadlua(script, ...)
				if type(script) == "string" then
					for _, blacklist in ipairs(blacklists) do
						if startWith(script, blacklist) then
							jit.off(m, true)
							break
						end
					end
				end
				return m
			end
		end
	end)

	if GetModConfigData("EnableProfiler") ~= "off" then
		local env = _G.getfenv()
		env.modimport = function(modulename)
			_G.print("modimport: " .. MODROOT .. modulename, _G.package.path)
			if string.sub(modulename, #modulename - 3, #modulename) ~= ".lua" then
				modulename = modulename .. ".lua"
			end
			local result = _G.kleiloadlua(MODROOT .. modulename)
			if result == nil then
				_G.error("Error in modimport: " .. modulename .. " not found!")
			elseif type(result) == "string" then
				_G.error(
					"Error in modimport: " .. ModInfoname(modname) .. " importing " .. modulename .. "!\n" .. result
				)
			else
				_G.setfenv(result, setmetatable(env, { __index = _G }))
				result()
			end
		end
		local old_require = env.require
		env.require = function(modulename)
			local ok, ret = _G.pcall(old_require, modulename)
			if ok then
				return ret
			end
			return env.modimport(modulename)
		end

		local profiler = require("jit.p")
		local zone = require("jit.zone")
		local mode = GetModConfigData("EnableProfiler")

		_G.rawset(_G, "ProfilerJit", {
			start = function(m)
				m = m or mode
				local sim = _G.getmetatable(TheSim).__index
				local old_profiler_push = sim.ProfilerPush
				sim.ProfilerPush = function(name, ...)
					zone(name)
					old_profiler_push(name, ...)
				end
				local old_profiler_pop = sim.ProfilerPop
				sim.ProfilerPop = function(...)
					zone()
					old_profiler_pop(...)
				end
				profiler.start(m, "unsafedata/profiler")
			end,
			stop = profiler.stop,
		})
	end
end
