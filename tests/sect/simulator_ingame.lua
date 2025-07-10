local arg = arg or { ... }

local hook_files = {}

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
end

parser_args()
parser_env()


function ModWrangler:TryLoadMod(modname)
	local initenv = KnownModIndex:GetModInfo(modname)
	local env = CreateEnvironment(modname, self.worldgen)
	env.modinfo = initenv
	local t = {}
	env.MYPRINT = function(str, level)
		t[#t + 1] = { str, level }
	end
	local old_debug_sethook = debug.sethook
	function debug.sethook(...) end

	local old_load = load
	local load_get_thunk_func
	local load_codes
	local function get_thunk()
		local code = load_get_thunk_func()
		load_codes = (load_codes or '') .. code
		return code
	end
	local function load_function_proxy(chunk, chunkname, mode, env)
		print("load:", chunkname, mode)
		if hook_files[chunkname] then
			local fp = io.open(hook_files[chunkname], "r")
			if fp then
				local code = fp:read("*a")
				fp:close()
				print("hook file loaded:", chunkname, code)
				return old_load(code, chunkname, mode, env)
			end
		end
		if type(chunk) == "string" then
			return old_load(chunk, chunkname, mode, env)
		end
		assert(type(chunk) == 'function')
		load_get_thunk_func = chunk
		load_codes = nil
		local fn = old_load(get_thunk, chunkname, mode, env)
		-- replace chunkname path to safe filename
		chunkname = chunkname:gsub("[%/%\\]", "_")
		if load_codes and #load_codes > 0 then
			local fp = io.open("unsafedata/"..chunkname, "w")
			if not fp then
				print("Failed to open file for writing: unsafedata/" .. chunkname)
				return fn
			end
			fp:write(load_codes)
			fp:close()
		end
		return fn
	end
	load = newproxy(load_function_proxy)
	local old_debug_getinfo = debug.getinfo
	local debug_getinfo_proxy
	function debug_getinfo_proxy(f, what)
		print("debug.getinfo:", f, what)
		if (type(f) == 'number') and f > 0 then
			f = f + 2 --跳过getinfo的cproxy luaproxy
			-- 判断一下 是不是在load函数里面执行的, 这个地方执行的话直接,跳过load函数堆栈,应该有两层, get_thunk, proxy, luaproxy, load
			local info = old_debug_getinfo(f, 'f')
			if info.func == get_thunk then
				f = f + 3
			elseif info.func == load_function_proxy then
				f = f + 2
			elseif info.func == load then
				f = f + 1
			end
		end
		return old_debug_getinfo(f, what)
	end

	debug.getinfo = newproxy(debug_getinfo_proxy)
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
	debug.sethook = old_debug_sethook
	load = old_load
	debug.getinfo = old_debug_getinfo
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
