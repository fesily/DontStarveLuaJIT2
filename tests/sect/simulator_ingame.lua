
function ModWrangler:TryLoadMod(modname)
	local initenv = KnownModIndex:GetModInfo(modname)
	local env = CreateEnvironment(modname,  self.worldgen)
	env.modinfo = initenv
	local t = {}
	env.MYPRINT = function (str, level)
		t[#t+1] = {str,level}
	end
	local old_debug_sethook = debug.sethook
	function debug.sethook(...) end
	local old_io_open = io.open
	io.open1 = io.open
	function io.open(filename, mode) 
		print("io.open: "..filename.." mode: "..mode)
		if filename:find("modmain.lua", 1, true) then
			filename = MODS_ROOT..modname.."/".."modmain1.lua"
			print("io.open: "..filename.." mode: "..mode)
			local fp, err = old_io_open(filename, mode)
			if fp then
				return fp
			end
		end
		return old_io_open(filename, mode)
	end
	local mod = env
	local old_modimport = env.modimport
	function mod.modimport(modulename)
		return old_modimport(modulename)
	end
	package.path = MODS_ROOT..mod.modname.."\\scripts\\?.lua;"..package.path
	local manifest
	--manifests are on by default for workshop mods, off by default for local mods.
	--manifests can be toggled on and off in modinfo with forcemanifest = false or forcemanifest = true
	if((mod.modinfo.forcemanifest == nil and IsWorkshopMod(mod.modname)) or
		(mod.modinfo.forcemanifest ~= nil and mod.modinfo.forcemanifest)) then
		ManifestManager:LoadModManifest(mod.modname, mod.modinfo.version)
		manifest = mod.modname
	end
	table.insert(package.assetpath, {path = MODS_ROOT..mod.modname.."\\", manifest = manifest})

	self.currentlyloadingmod = mod.modname
	self:InitializeModMain(mod.modname, mod, "modworldgenmain.lua")
	if not self.worldgen then
		-- worldgen has to always run (for customization screen) but modmain can be
		-- skipped for worldgen. This reduces a lot of issues with missing globals.
		self:InitializeModMain(mod.modname, mod, "modmain.lua")
	end
	self.currentlyloadingmod = nil
	debug.sethook = old_debug_sethook
	io.open = old_io_open
	io.open1 = nil
	if #t > 0 then
		local fp = io.open("unsafedata/ok.txt","w")
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
			fp:write(levels[level]..tostring(str).."\n")
		end
		fp:close()
	else 
		print("Mod: "..ModInfoname(modname), "  No print statements in modmain.")
	end
end

