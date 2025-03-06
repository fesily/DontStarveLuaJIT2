_G = GLOBAL
local hasluajit, jit = _G.pcall(require, "jit")
if not hasluajit then
	return
end

local function main()
	if not TheNet:IsDedicated() then
		local fp = io.open("unsafedata/luajit_config.json", "w")
		if fp then
			local config = {
				modmain_path = debug.getinfo(1).source,
				server_disable_luajit = GetModConfigData("DisableJITWhenServer"),
			}
			fp:write(json.encode(config))
			fp:close()
		end
	end

	function inject_server_only_mod()
		local old_GetServerModNames = KnownModIndex.GetServerModNames
		local old_GetServerModNamesTable = KnownModIndex.GetServerModNamesTable
		local old_GetEnabledServerModNames = ModManager.GetEnabledServerModNames

		KnownModIndex.GetServerModNames = function(self, ...)
			local names = old_GetServerModNames(self, ...)
			table.insert(names, modname)
			return names
		end

		KnownModIndex.GetServerModNamesTable = function(self, ...)
			local names = old_GetServerModNamesTable(self, ...)
			table.insert(names, { modname = modname })
			return names
		end
		ModManager.GetEnabledServerModNames = function(self, ...)
			local server_mods = old_GetEnabledServerModNames(self, ...)
			if IsNotConsole() then
				table.insert(server_mods, modname)
			end
			return server_mods
		end
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
				local _kleiloadlua = kleiloadlua
				rawset(_G, "kleiloadlua", function(script, ...)
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
				end)
			end
		end)

		local zone = require("jit.zone")
		local sim = getmetatable(TheSim).__index
		local old_profiler_push = sim.ProfilerPush
		local old_profiler_pop = sim.ProfilerPop
		if GetModConfigData("EnableProfiler") == "on" then
			local profiler = require("jit.p")
			local mode = GetModConfigData("EnableProfiler")
			local enabled_profiler = false
			sim.ProfilerPush = function(self, name, ...)
				if enabled_profiler then
					zone(name)
				end
				old_profiler_push(self, name, ...)
			end
			sim.ProfilerPop = function(...)
				if enabled_profiler then
					zone()
				end
				old_profiler_pop(...)
			end
			rawset(_G, "ProfilerJit", {
				start = function(m)
					enabled_profiler = true
					profiler.start(m or mode, "unsafedata/profiler")
				end,
				stop = function()
					enabled_profiler = false
					profiler.stop()
				end,
			})
		end

		local injector
		local function get_injector()
			if not injector then
				local ffi = require 'ffi'
				ffi.cdef [[
					int replace_profiler_api();
					void enable_tracy(int en);
					void disable_fullgc(int mb);
					int set_frame_gc_time(int ms);
				]]
				local injector = require 'luavm.ffi_load'("Injector")
				return injector
			end
		end
		if GetModConfigData("EnableTracy") == "on" then
			get_injector().replace_profiler_api()
			get_injector().enable_tracy(1)
		end

		if GetModConfigData("DisableForceFullGC") ~= 0 then
			get_injector().replace_profiler_api()
			get_injector().disable_fullgc(tonumber(GetModConfigData("DisableForceFullGC")))
		end

		if GetModConfigData("EnbaleFrameGC") ~= 0 then
			get_injector().set_frame_gc_time(tonumber(GetModConfigData("EnbaleFrameGC")))
		end

	end
	inject_server_only_mod()
end

local env = _G.getfenv(main)
_G.setfenv(main, _G.setmetatable({}, {
	__index = function(t, k)
		return env[k] or _G[k]
	end
}))
main()
