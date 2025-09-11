_G = GLOBAL
local modname = modname
local modinfo = modinfo
local EnableFrostxxMods = false
local function main()
	local function startWith(str, prefix)
		return str:find(prefix, 1, true) == 1
	end
	local function Version2Number(version)
		local num = 0
		string.gsub(version, "(%d+)", function(v)
			num = num * 100000 + tonumber(v)
		end)
		return num
	end

	local function table_hmask(tab)
		if type(tab) ~= "table" then
			return 0
		end
		local count = 0
		for k, v in pairs(tab) do
			if k ~= nil and v ~= nil then
				count = count + 1
			end
		end
		return count
	end

	local locale = LOC.GetLocaleCode()
	local lc = locale

	local function translate(t)
		t.zhr = t.zh
		t.zht = t.zht or t.zh
		return t[lc] or t.en
	end

	local function should_show_dig()
		if TheNet:GetIsServer() and TheNet:GetServerIsDedicated() then
			return false
		end
		if not TheFrontEnd then
			return false
		end
		if IsMigrating() then
			return false
		end
		return not InGamePlay()
	end
	local hasluajit, jit = _G.pcall(require, "jit")

	local ModManagerFile = { filepath = nil, json_mode = true }

	function ModManagerFile:read_file()
		if not self.filepath then return end
		local fp = io.open(self.filepath, 'r')
		if not fp then return end
		local str = fp:read('*a')
		fp:close()
		if self.json_mode then
			return json.decode(str)
		end
		return str
	end

	function ModManagerFile:clean_file()
		self:write_file(nil)
	end

	function ModManagerFile:write_file(data)
		if not self.filepath then return end
		local fp = io.open(self.filepath, 'w')
		if not fp then return end
		if data and self.json_mode then
			data = json.encode(data)
		end
		if data then
			fp:write(data)
		end

		fp:close()
	end

	local luajit_crash = setmetatable({ filepath = "unsafedata/luajit_crash.json", json_mode = false },
		{ __index = ModManagerFile })

	function luajit_crash:is_crash()
		local content = self:read_file()
		return content and #content ~= 0 and false
	end

	AddGamePostInit(function()
		luajit_crash:clean_file()
	end)


	local _M = {
		NotWindowsInvalidOptions = {
			TargetRenderFPS = true,
			TargetLogicFPS = true,
			ClientNetWorkTick = true,
		}
	}

	function _M:NoJitMain()
		AddGamePostInit(function()
			if should_show_dig() then
				local PopupDialogScreen = require "screens/popupdialog"
				-- check crash
				if luajit_crash:is_crash() then
					TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.RESTART_TITLE, translate({
							zh = "检测luajit未成功加载,是否再次尝试?\n\n(还失败可能需要更新,请联系作者)",
							en =
							"Detected that luajit failed to load, do you want to try again?\n\n(If it fails again, it may need to be updated, please contact the author)"
						}),
						{
							{
								text = STRINGS.UI.MAINSCREEN.RESTART,
								cb = function()
									TheSim:Quit()
								end
							},
							{ text = STRINGS.UI.MAINSCREEN.OK, cb = function() TheFrontEnd:PopScreen() end }
						}))
				else
					TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MAINSCREEN.MODFAILTITLE, translate({
							zh = [[当前luajit模组未成功安装,前往该模组所在的文件夹,运行install.bat]],
							en =
							"The current luajit mod has not been successfully installed, please go to the folder where the luajit mod is located, and run install.bat/.sh to execute the installation"
						}),
						{
							{ text = STRINGS.UI.MAINSCREEN.OK, cb = function() TheFrontEnd:PopScreen() end }
						}))
				end
			end
		end)
	end

	local function HookGetModConfigData()
		if jit.os ~= "Windows" then
			local old_GetModConfigData = GetModConfigData
			function GetModConfigData(key, get_local_config)
				if _M.NotWindowsInvalidOptions[key] then
					print("[luajit] InvalidOptions: " .. key)
					return nil
				end
				return old_GetModConfigData(key, get_local_config)
			end
		end
	end

	function _M:GetEncryptedModManager()
		local luajit_encryptmods = setmetatable({ filepath = "unsafedata/luajit_encryptmods.json" },
			{ __index = ModManagerFile })


		local AutoDetectEncryptedMod = GetModConfigData("AutoDetectEncryptedMod")

		local EncryptedModManager = AutoDetectEncryptedMod and luajit_encryptmods:read_file() or nil
		if EncryptedModManager == nil or EncryptedModManager.version ~= APP_VERSION then
			EncryptedModManager = { EncryptedMods = {}, frostxxMods = {}, version = APP_VERSION, hash = 0 }
		end

		local function HashString(str)
			local hash = 0
			for i = 1, #str do
				hash = bit.bxor(hash, str:byte(i))
			end
			return hash
		end

		local function HashModDirectoryNames(ModDirectoryNames)
			local hash = 0
			for i, v in ipairs(ModDirectoryNames) do
				hash = bit.bxor(hash, HashString(v))
			end
			return hash
		end

		local function InitEncryptedModManager()
			local self = EncryptedModManager
			local ModDirectoryNames = TheSim:GetModDirectoryNames()
			if not ModDirectoryNames then return end

			local hash = HashModDirectoryNames(ModDirectoryNames)
			if hash == self.hash then
				return
			end

			local function is_visible_byte(b)
				return (b >= 32 and b <= 126)
			end

			-- 检查字符串中所有不可见字符是否属于合法 UTF-8 编码
			local function all_invisible_chars_are_utf8(str)
				local i = 1
				local len = #str
				while i <= len do
					local b = str:byte(i)
					if not is_visible_byte(b) then
						-- 检查 UTF-8 多字节序列
						if b >= 0 and b <= 127 then
							-- 单字节不可见字符，允许常见控制符（如 \n, \r, \t, \v, \f, \b, \a, ESC）
							if not (b == 9 or b == 10 or b == 13 or b == 27) then
								return false
							end
							i = i + 1
						elseif b >= 194 and b <= 223 then
							-- 2字节序列
							if i + 1 > len then return false end
							local b2 = str:byte(i + 1)
							if not (b2 >= 128 and b2 <= 191) then return false end
							i = i + 2
						elseif b >= 224 and b <= 239 then
							-- 3字节序列
							if i + 2 > len then return false end
							local b2, b3 = str:byte(i + 1), str:byte(i + 2)
							if not (b2 >= 128 and b2 <= 191 and b3 >= 128 and b3 <= 191) then return false end
							i = i + 3
						elseif b >= 240 and b <= 244 then
							-- 4字节序列
							if i + 3 > len then return false end
							local b2, b3, b4 = str:byte(i + 1), str:byte(i + 2), str:byte(i + 3)
							if not (b2 >= 128 and b2 <= 191 and b3 >= 128 and b3 <= 191 and b4 >= 128 and b4 <= 191) then return false end
							i = i + 4
						else
							return false
						end
					else
						i = i + 1
					end
				end
				return true
			end
			local function check_encrypted(filename, modname)
				local limit = 64
				for line in io.lines(filename) do
					if limit <= 12 then
						if line:find("frostxx@qq.com", 1, true) then
							self.frostxxMods[modname] = true
							print(filename, modname, " is frostxx mod!")
						end
					end
					---@cast line string
					if #line > 1024 then
						self.EncryptedMods[modname] = true
						print(filename, modname, " is encrypted! by line length")
						return true
					end
					if not all_invisible_chars_are_utf8(line) then
						self.EncryptedMods[modname] = true
						print(filename, modname, " is encrypted! by invalid utf8", line)
						return true
					end

					limit = limit - 1
					if limit <= 0 then
						return
					end
				end
			end

			local MODS_ROOT = "../mods/"
			for i, modname in ipairs(ModDirectoryNames) do
				if self.EncryptedMods[modname] == nil then
					local ok, isencrypted = pcall(check_encrypted, MODS_ROOT .. modname .. "/modmain.lua", modname)
					if ok and not isencrypted then
						pcall(check_encrypted, MODS_ROOT .. modname .. "/modworldgenmain.lua", modname)
					end
				end
			end
			luajit_encryptmods:write_file(EncryptedModManager)
		end

		if AutoDetectEncryptedMod then
			InitEncryptedModManager()
		end
		return EncryptedModManager
	end

	local function ForceDisableTailCall()
		if GetModConfigData("ForceDisableTailCall") then
			local jit_util = require 'jit.util'
			jit_util.disabletailcall(true)
		end
	end

	local function inject_server_only_mod()
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

	local function HookGameVersionUI()
		local TEMPLATES = require("widgets/redux/templates")
		local old_getbuildstring = TEMPLATES.GetBuildString
		TEMPLATES.GetBuildString = function()
			return (old_getbuildstring() or "") .. "(LuaJIT)"
		end
	end

	local function ForceJitOpt()
		local jit_opt = require 'jit.opt'
		jit_opt.start(
			"maxtrace=4000",
			"minstitch=2",
			"maxrecord=8000",
			"sizemcode=64",
			"maxmcode=4000",
			"maxirconst=1000"
		)
	end

	local function EnabledJIT()
		local enabled_jit = GetModConfigData("EnabledJIT")
		if enabled_jit then
			AddSimPostInit(function()
				jit.on()
			end)
		end
	end

	local function EnableProfiler(injector)
		if GetModConfigData("EnableProfiler") == "on" then
			local zone = require("jit.zone")
			local sim = getmetatable(TheSim).__index
			local old_profiler_push = sim.ProfilerPush
			local old_profiler_pop = sim.ProfilerPop
			rawset(_G, "ProfilerJitEx", {
				start = function(m)
					injector.DS_LUAJIT_enable_profiler(1)
				end,
				stop = function()
					injector.DS_LUAJIT_enable_profiler(0)
				end,
			})
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
	end

	local function LoadFFI()
		local ffi = require 'ffi'
		ffi.cdef [[
			int DS_LUAJIT_replace_profiler_api();
			void DS_LUAJIT_enable_tracy(int en);
			void DS_LUAJIT_enable_profiler(int en);
			void DS_LUAJIT_disable_fullgc(int mb);
			bool DS_LUAJIT_enable_framegc(bool enable);
			const char* DS_LUAJIT_get_mod_version();
			const char* DS_LUAJIT_get_workshop_dir();
			int DS_LUAJIT_update(const char* mod_dictory, int tt);
			int DS_LUAJIT_set_target_fps(int fps, int tt);
			int DS_LUAJIT_replace_network_tick(char tick, char download_tick, bool client);
			const char* DS_LUAJIT_Fengxun_Decrypt(const char* filename);
			struct DS_LUAJIT_NetworkExtension {
				char channel;
			};
			struct DS_LUAJIT_NetworkExtension* DS_LUAJIT_EntityNetWorkExtension_Register(void *luanetworkwarrper);
			/// These enumerations are used to describe when packets are delivered.
			enum PacketPriority
			{
				/// The highest possible priority. These message trigger sends immediately, and are generally not buffered or aggregated into a single datagram.
				IMMEDIATE_PRIORITY,

				/// For every 2 IMMEDIATE_PRIORITY messages, 1 HIGH_PRIORITY will be sent.
				/// Messages at this priority and lower are buffered to be sent in groups at 10 millisecond intervals to reduce UDP overhead and better measure congestion control.
				HIGH_PRIORITY,

				/// For every 2 HIGH_PRIORITY messages, 1 MEDIUM_PRIORITY will be sent.
				/// Messages at this priority and lower are buffered to be sent in groups at 10 millisecond intervals to reduce UDP overhead and better measure congestion control.
				MEDIUM_PRIORITY,

				/// For every 2 MEDIUM_PRIORITY messages, 1 LOW_PRIORITY will be sent.
				/// Messages at this priority and lower are buffered to be sent in groups at 10 millisecond intervals to reduce UDP overhead and better measure congestion control.
				LOW_PRIORITY,

				/// \internal
				NUMBER_OF_PRIORITIES
			};

			/// These enumerations are used to describe how packets are delivered.
			/// \note  Note to self: I write this with 3 bits in the stream.  If I add more remember to change that
			/// \note In ReliabilityLayer::WriteToBitStreamFromInternalPacket I assume there are 5 major types
			/// \note Do not reorder, I check on >= UNRELIABLE_WITH_ACK_RECEIPT
			enum PacketReliability
			{
				/// Same as regular UDP, except that it will also discard duplicate datagrams.  RakNet adds (6 to 17) + 21 bits of overhead, 16 of which is used to detect duplicate packets and 6 to 17 of which is used for message length.
				UNRELIABLE,

				/// Regular UDP with a sequence counter.  Out of order messages will be discarded.
				/// Sequenced and ordered messages sent on the same channel will arrive in the order sent.
				UNRELIABLE_SEQUENCED,

				/// The message is sent reliably, but not necessarily in any order.  Same overhead as UNRELIABLE.
				RELIABLE,

				/// This message is reliable and will arrive in the order you sent it.  Messages will be delayed while waiting for out of order messages.  Same overhead as UNRELIABLE_SEQUENCED.
				/// Sequenced and ordered messages sent on the same channel will arrive in the order sent.
				RELIABLE_ORDERED,

				/// This message is reliable and will arrive in the sequence you sent it.  Out or order messages will be dropped.  Same overhead as UNRELIABLE_SEQUENCED.
				/// Sequenced and ordered messages sent on the same channel will arrive in the order sent.
				RELIABLE_SEQUENCED,

				/// Same as UNRELIABLE, however the user will get either ID_SND_RECEIPT_ACKED or ID_SND_RECEIPT_LOSS based on the result of sending this message when calling RakPeerInterface::Receive(). Bytes 1-4 will contain the number returned from the Send() function. On disconnect or shutdown, all messages not previously acked should be considered lost.
				UNRELIABLE_WITH_ACK_RECEIPT,

				/// Same as UNRELIABLE_SEQUENCED, however the user will get either ID_SND_RECEIPT_ACKED or ID_SND_RECEIPT_LOSS based on the result of sending this message when calling RakPeerInterface::Receive(). Bytes 1-4 will contain the number returned from the Send() function. On disconnect or shutdown, all messages not previously acked should be considered lost.
				/// 05/04/10 You can't have sequenced and ack receipts, because you don't know if the other system discarded the message, meaning you don't know if the message was processed
				// UNRELIABLE_SEQUENCED_WITH_ACK_RECEIPT,

				/// Same as RELIABLE. The user will also get ID_SND_RECEIPT_ACKED after the message is delivered when calling RakPeerInterface::Receive(). ID_SND_RECEIPT_ACKED is returned when the message arrives, not necessarily the order when it was sent. Bytes 1-4 will contain the number returned from the Send() function. On disconnect or shutdown, all messages not previously acked should be considered lost. This does not return ID_SND_RECEIPT_LOSS.
				RELIABLE_WITH_ACK_RECEIPT,

				/// Same as RELIABLE_ORDERED_ACK_RECEIPT. The user will also get ID_SND_RECEIPT_ACKED after the message is delivered when calling RakPeerInterface::Receive(). ID_SND_RECEIPT_ACKED is returned when the message arrives, not necessarily the order when it was sent. Bytes 1-4 will contain the number returned from the Send() function. On disconnect or shutdown, all messages not previously acked should be considered lost. This does not return ID_SND_RECEIPT_LOSS.
				RELIABLE_ORDERED_WITH_ACK_RECEIPT,

				/// Same as RELIABLE_SEQUENCED. The user will also get ID_SND_RECEIPT_ACKED after the message is delivered when calling RakPeerInterface::Receive(). Bytes 1-4 will contain the number returned from the Send() function. On disconnect or shutdown, all messages not previously acked should be considered lost.
				/// 05/04/10 You can't have sequenced and ack receipts, because you don't know if the other system discarded the message, meaning you don't know if the message was processed
				// RELIABLE_SEQUENCED_WITH_ACK_RECEIPT,

				/// \internal
				NUMBER_OF_RELIABILITIES
			};

			void DS_LUAJIT_SetNextRpcInfo(enum PacketPriority *packetPriority, enum PacketReliability *reliability, char *orderingChannel);
		]]
		local injector, so_path = require 'luavm.ffi_load' ("Injector")
		local init_fn = package.loadlib(so_path, "luaopen_injector")
		if init_fn then
			init_fn()
			print("load JitModInjector")
		end
		return injector, rawget(_G, "JitModInjector")
	end


	function _M:SlowTailCall()
		if GetModConfigData("SlowTailCall") then
			local function getmodname(env)
				return env.modname
			end
			debug.getregistry()["LJ_DS_dynamic_tailcall_cb"] = function(reader, data, chunkname, mode)
				if not chunkname then
					return true, "no chunkname"
				end

				if startWith(chunkname, "@scripts/") then
					return false, "@scripts"
				end

				local env = getfenv(3)
				local ok, modname = pcall(getmodname, env)
				if not ok or not modname then
					return false, "no modname"
				end
				if modname and _M.SlowTailCallModList[modname] then
					return true, "slow tailcall", modname
				end

				if data == chunkname then
					return false, "no filename"
				end

				return false, ""
			end
		end
	end

	local function filename2modname(filename)
		local prefix = "../mods/"
		local modname_prefix_pos = #"../mods/" + 1
		if startWith(filename, prefix) then
			-- fixed pos = ../mods/
			local pos = filename:find("/", #prefix + 1, true)
			if pos then
				return filename:sub(modname_prefix_pos, pos - 1)
			end
		end
	end

	local function HookKleiloadlua(frostxxMods, injector)
		local ffi = require 'ffi'
		local enbaleBlackList = GetModConfigData("ModBlackList")
		local blacklists = {
			--- format
			--- 'workshop-<modid>'
		}
		local function decrypt_file(filename)
			local str = injector.DS_LUAJIT_Fengxun_Decrypt(filename)
			if str ~= nil then
				return loadstring(ffi.string(str), filename)
			end
		end

		if enbaleBlackList then
			enbaleBlackList = #blacklists > 0
		end
		local hmask = table_hmask(frostxxMods)
		if enbaleBlackList or hmask > 0 then
			local _kleiloadlua = kleiloadlua

			rawset(_G, "kleiloadlua", function(filename, ...)
				---@cast filename string
				local modname = filename2modname(filename)
				if modname and hmask > 0 then
					if frostxxMods[modname] and not filename:find('modinfo.lua', 1, true) then
						if filename:find("modmain.lua", 1, true) then
							filename = filename:gsub("modmain.lua", "modmain0.lua")
						elseif filename:find("modworldgenmain.lua", 1, true) then
							filename = filename:gsub("modworldgenmain.lua", "modworldgenmain0.lua")
						end

						local fn = decrypt_file(filename)
						if fn then
							return fn
						end
					end
				end

				local m = _kleiloadlua(filename, ...)
				if enbaleBlackList and modname and type(m) == "function" then
					if blacklists[modname] then
						jit.off(m, true)
					end
				end
				return m
			end)
		end
	end

	function _M:GetModMainPath(injector, ffi)
		local modmain_path = debug.getinfo(1).source

		local modname = filename2modname(modmain_path)
		if modname then
			local modnames = { modname }
			local workshop_context_prefix = "workshop-"
			if startWith(modname, workshop_context_prefix) then
				modnames[#modnames + 1] = modname:sub(#workshop_context_prefix + 1)
			end
			for _, modname in ipairs(modnames) do
				local workshop_dir = injector.DS_LUAJIT_get_workshop_dir();
				if workshop_dir ~= nil then
					workshop_dir = ffi.string(workshop_dir)
					local workshop_dir_root = workshop_dir .. "/" .. modname .. "/"
					local io = rawget(_G, "io2") or io
					local ok, fp = pcall(io.open, workshop_dir_root .. "install.bat", "r")
					if ok and fp then
						fp:close()
						self.modmain_path = workshop_dir_root .. "modmain.lua"
						self.workshop_dir_root = workshop_dir_root
						break
					end
				end
			end
		end
	end

	function _M:GetModVersion(injector, ffi)
		local so_version = injector.DS_LUAJIT_get_mod_version()
		if so_version then
			so_version = ffi.string(so_version)
		else
			so_version = "0.0.0"
		end
		self.so_version = so_version
	end

	local luajit_config = setmetatable({ filepath = "unsafedata/luajit_config.json" }, { __index = ModManagerFile })
	function luajit_config:create(modmain_path, server_disable_luajit, always_enable_mod, config)
		if config == nil then
			return {
				modmain_path = modmain_path,
				server_disable_luajit = server_disable_luajit,
				always_enable_mod = always_enable_mod,
			}
		else
			config.modmain_path = modmain_path or config.modmain_path
			config.server_disable_luajit = server_disable_luajit or config.server_disable_luajit
			config.always_enable_mod = always_enable_mod or config.always_enable_mod
		end
	end

	function luajit_config:WriteConfig(modmain_path)
		if not TheNet:IsDedicated() then
			self.data = self:create(modmain_path, GetModConfigData("DisableJITWhenServer"),
				GetModConfigData("AlwaysEnableMod"))
			self:write_file(self.data)
		end
	end

	local function EnableTracy(injector)
		if GetModConfigData("EnableTracy") == "on" then
			injector.DS_LUAJIT_replace_profiler_api()
			injector.DS_LUAJIT_enable_tracy(1)
		end
	end

	local function NetWorkOpt(injector)
		local ffi = require 'ffi'
		do
			local net_mt = getmetatable(TheNet).__index;
			local c_packetPriority = ffi.new("enum PacketPriority[1]")
			local c_reliability = ffi.new("enum PacketReliability[1]")
			local c_channel = ffi.new("char[1]")
			local default_packetPriority = ffi.C.HIGH_PRIORITY
			local default_reliability = ffi.C.RELIABLE_ORDERED
			local default_channel = 0
			local old_SendRPCToServer = net_mt.SendRPCToServer
			local old_SendRPCToClient = net_mt.SendRPCToClient
			local old_SendRPCToShard = net_mt.SendRPCToShard
			local old_SendModRPCToServer = net_mt.SendModRPCToServer
			local old_SendModRPCToClient = net_mt.SendModRPCToClient
			local old_SendModRPCToShard = net_mt.SendModRPCToShard

			local _FNV_offset_basis = 2166136261;
			local _FNV_prime = 16777619;
			local function hash_string(data)
				assert(type(data) == "string")
				local hash = _FNV_offset_basis
				for i = 1, #data do
					hash = bit.bxor(hash, data:byte(i))
					hash = hash * _FNV_prime
				end
				return hash
			end

			local function alloc_rpc_channel(id_table)
				if type(id_table) == "number" then
					return id_table % 32
				end
				local hash = hash_string(id_table.namespace)
				hash = bit.bxor(hash, id_table.id + 0x9e3779b9 + bit.lshift(hash, 6) + bit.rshift(hash, 2))
				return hash % 32
			end

			local mod_namespace_id_channel = {}
			local function get_mod_channel(id_table)
				mod_namespace_id_channel[id_table.namespace] = mod_namespace_id_channel[id_table.namespace] or {}
				local mod_namespace = mod_namespace_id_channel[id_table.namespace]
				if mod_namespace[id_table.id] == nil then
					mod_namespace[id_table.id] = alloc_rpc_channel(id_table)
				end
				return mod_namespace[id_table.id]
			end

			net_mt.alloc_rpc_channel = alloc_rpc_channel

			function net_mt:SendRPCToServer2(code, packetPriority, reliability, channel, ...)
				c_packetPriority[0] = packetPriority or default_packetPriority
				c_reliability[0] = reliability or default_reliability
				c_channel[0] = channel or alloc_rpc_channel(code)
				injector.DS_LUAJIT_SetNextRpcInfo(c_packetPriority, c_reliability, c_channel)
				return old_SendRPCToServer(self, code, ...)
			end

			function net_mt:SendRPCToClient2(code, packetPriority, reliability, channel, ...)
				c_packetPriority[0] = packetPriority or default_packetPriority
				c_reliability[0] = reliability or default_reliability
				c_channel[0] = channel or alloc_rpc_channel(code)
				injector.DS_LUAJIT_SetNextRpcInfo(c_packetPriority, c_reliability, c_channel)
				return old_SendRPCToClient(self, code, ...)
			end

			function net_mt:SendRPCToShard2(code, packetPriority, reliability, channel, ...)
				c_packetPriority[0] = packetPriority or default_packetPriority
				c_reliability[0] = reliability or default_reliability
				c_channel[0] = channel or alloc_rpc_channel(code)
				injector.DS_LUAJIT_SetNextRpcInfo(c_packetPriority, c_reliability, c_channel)
				return old_SendRPCToShard(self, code, ...)
			end

			function net_mt:SendModRPCToServer2(id_table, packetPriority, reliability, channel, ...)
				c_packetPriority[0] = packetPriority or default_packetPriority
				c_reliability[0] = reliability or default_reliability
				c_channel[0] = channel or get_mod_channel(id_table)
				injector.DS_LUAJIT_SetNextRpcInfo(c_packetPriority, c_reliability, c_channel)
				return old_SendModRPCToServer(self, id_table.namespace, id_table.id, ...)
			end

			function net_mt:SendModRPCToClient2(id_table, packetPriority, reliability, channel, ...)
				c_packetPriority[0] = packetPriority or default_packetPriority
				c_reliability[0] = reliability or default_reliability
				c_channel[0] = channel or get_mod_channel(id_table)
				injector.DS_LUAJIT_SetNextRpcInfo(c_packetPriority, c_reliability, c_channel)
				return old_SendModRPCToClient(self, id_table.namespace, id_table.id, ...)
			end

			function net_mt:SendModRPCToShard2(id_table, packetPriority, reliability, channel, ...)
				c_packetPriority[0] = packetPriority or default_packetPriority
				c_reliability[0] = reliability or default_reliability
				c_channel[0] = channel or get_mod_channel(id_table)
				injector.DS_LUAJIT_SetNextRpcInfo(c_packetPriority, c_reliability, c_channel)
				return old_SendModRPCToShard(self, id_table.namespace, id_table.id, ...)
			end

			if GetModConfigData("NetworkOpt") and false then
				function net_mt:SendRPCToServer(code, ...)
					c_channel[0] = alloc_rpc_channel(code);
					injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
					return old_SendRPCToServer(self, code, ...)
				end

				function net_mt:SendRPCToClient(code, ...)
					c_channel[0] = alloc_rpc_channel(code);
					injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
					return old_SendRPCToClient(self, code, ...)
				end

				function net_mt:SendRPCToShard(code, ...)
					c_channel[0] = alloc_rpc_channel(code);
					injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
					return old_SendRPCToShard(self, code, ...)
				end

				function net_mt:SendModRPCToServer(id_table, ...)
					c_channel[0] = get_mod_channel(id_table)
					injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
					return old_SendModRPCToServer(self, id_table.namespace, id_table.id, ...)
				end

				function net_mt:SendModRPCToClient(id_table, ...)
					c_channel[0] = get_mod_channel(id_table);
					injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
					return old_SendModRPCToClient(self, id_table.namespace, id_table.id, ...)
				end

				function net_mt:SendModRPCToShard(id_table, ...)
					c_channel[0] = get_mod_channel(id_table);
					injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
					return old_SendModRPCToShard(self, id_table.namespace, id_table.id, ...)
				end
			end
		end


		if GetModConfigData("NetworkOptEntity") then
			local old_SpawnPrefab = SpawnPrefab
			function SpawnPrefab(...)
				local inst = old_SpawnPrefab(...)
				if inst and inst.Network and not inst.NetworkExtension then
					inst.NetworkExtension = injector.DS_LUAJIT_EntityNetWorkExtension_Register(inst.Network,
						inst.Network:GetNetworkID())
				end
				return inst
			end
		end
	end

	local function ReloadSim()
		print("[luajit] need restart")
		scheduler:ExecuteInTime(0, function()
			c_reset()
		end)
	end

	function _M:AlwaysLoad(injector, VersionMissMatch)
		local workshop_dir_root = self.workshop_dir_root
		AddGamePostInit(function()
			local PopupDialogScreen = require "screens/popupdialog"

			if should_show_dig() then
				if VersionMissMatch then
					local function update_mod()
						return injector.DS_LUAJIT_update(self.workshop_dir_root, 0) == 1
					end

					local btns = {}
					local version_info = translate({
						zh = "\n 模组版本:" .. modinfo.version .. " 模块版本:" .. version,
						en = "\n Mod version:" .. modinfo.version .. " Module version:" .. version
					})
					local content = translate({
						zh = [[当前luajit模组有更新,是否要执行更新?]] .. version_info,
						en = "The current luajit mod has been updated, do you want to execute the update?" ..
							version_info
					})
					if jit.os == "Windows" then
						btns[#btns + 1] = {
							text = STRINGS.UI.MAINSCREEN.RESTART,
							cb = function()
								update_mod()
							end
						}
					else
						content = translate({
							zh = [[当前luajit模组有更新,需要重新执行install.sh]] .. version_info,
							en = "The current luajit mod has been updated, should execute install.sh again" ..
								version_info
						})
					end

					btns[#btns + 1] = { text = STRINGS.UI.MAINSCREEN.CANCEL, cb = function() TheFrontEnd:PopScreen() end }
					TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.RESTART_TITLE, content,
						btns))
				end
			end

			-- motify ModConfigurationScreen

			local luajit_config_screen_ctor = function(self, client_config)
				local function uninstall_mod()
					if jit.os == "Windows" then
						injector.DS_LUAJIT_update(workshop_dir_root, 1)
					else
						TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.MODFAILTITLE, translate({
								zh = "当前操作系统不支持卸载luajit模组\n麻烦手动删除",
								en =
								"The current operating system does not support uninstalling the luajit mod\nPlease manually delete"
							}),
							{
								{ text = STRINGS.UI.MAINSCREEN.OK, cb = function() TheFrontEnd:PopScreen() end }
							}))
					end
				end

				local actions = self.dialog.actions
				if actions then
					self.uninstall = actions:AddItem(translate({ en = "uninstall mod", zh = "卸载模组" }),
						function()
							TheFrontEnd:PushScreen(PopupDialogScreen(STRINGS.UI.MODSSCREEN.RESTART_TITLE, translate({
									zh = "是否要卸载luajit模组?",
									en = "Are you sure you want to uninstall the luajit mod?"
								}),
								{
									{ text = STRINGS.UI.MAINSCREEN.RESTART, cb = function() uninstall_mod() end },
									{ text = STRINGS.UI.MAINSCREEN.CANCEL,  cb = function() TheFrontEnd:PopScreen() end }
								}))
						end)
					local sizeX, sizeY = actions:GetSize()
					local buttons_len = actions:GetNumberOfItems()
					local button_spacing
					-- 1,2,3,4 buttons can be big at 210,420,630,840 widths.
					local space_per_button = sizeX / buttons_len
					local has_space_for_big_buttons = space_per_button > 209
					if has_space_for_big_buttons then
						button_spacing = 320
					else
						button_spacing = 230
					end
					local button_height = -30 -- cover bottom crown
					actions:SetPosition(-(button_spacing * (buttons_len - 1)) / 2, button_height)
				end
			end
			local ModConfigurationScreen = KnownModIndex:IsModEnabledAny("workshop-3317960157") and
				require "widgets/remi_newmodconfigurationscreen" or require "screens/redux/modconfigurationscreen"
			local old_ctor = ModConfigurationScreen._ctor
			ModConfigurationScreen._ctor = function(self, _modname, client_config, ...)
				old_ctor(self, _modname, client_config, ...)
				if _modname == modname and jit.os == "Windows" then
					luajit_config_screen_ctor(self, client_config)
				end
			end
		end)
	end

	function _M:Main()
		local ffi = require 'ffi'
		local injector, JitModInjector = LoadFFI()
		self:GetModVersion(injector, ffi)
		local VersionMissMatch = Version2Number(modinfo.version) < Version2Number(self.so_version)
		self:AlwaysLoad(injector, VersionMissMatch)
		if VersionMissMatch then
			return
		end
		self:GetModMainPath(injector, ffi)
		HookGetModConfigData()
		HookGameVersionUI()
		ForceJitOpt()
		EnabledJIT()
		ForceDisableTailCall()

		local EncryptedModManager = self:GetEncryptedModManager()
		self.SlowTailCallModList = EncryptedModManager.EncryptedMods
		self:SlowTailCall()


		luajit_config:WriteConfig(self.modmain_path)

		EnableProfiler(injector)
		EnableTracy(injector)

		HookKleiloadlua(EnableFrostxxMods and EncryptedModManager.frostxxMods or {}, injector)

		NetWorkOpt(injector)
		if GetModConfigData("TargetRenderFPS") then
			local targetfps = GetModConfigData("TargetRenderFPS")
			if injector.DS_LUAJIT_set_target_fps(targetfps, 1) > 0 then
				print("[luajit]", "Reset fps by SetNetbookMode", targetfps)
				TheSim:SetNetbookMode(false)
			end
		end

		-- if GetModConfigData("ClientNetWorkTick") then
		-- 	local targetfps = GetModConfigData("ClientNetWorkTick")
		-- 	injector.DS_LUAJIT_replace_network_tick(targetfps, targetfps * 1.5, true)
		-- end
		-- if GetModConfigData("ServerNetWorkTick") then
		-- 	local targetfps = GetModConfigData("ServerNetWorkTick")
		-- 	injector.DS_LUAJIT_replace_network_tick(targetfps, 0, false)
		-- end


		if GetModConfigData("DisableForceFullGC") ~= 0 then
			injector.DS_LUAJIT_disable_fullgc(tonumber(GetModConfigData("DisableForceFullGC")))
		end

		if GetModConfigData("EnableFrameGC") then
			injector.DS_LUAJIT_replace_profiler_api()
			injector.DS_LUAJIT_enable_framegc(true)

			local old_OnSimPaused = _G.OnSimPaused
			local old_OnSimUnpaused = _G.OnSimUnpaused
			if old_OnSimPaused and old_OnSimUnpaused then
				_G.OnSimPaused = function(...)
					injector.DS_LUAJIT_enable_framegc(false)
					old_OnSimPaused(...)
				end

				_G.OnSimUnpaused = function(...)
					injector.DS_LUAJIT_enable_framegc(true)
					old_OnSimUnpaused(...)
				end
			end
		end
		inject_server_only_mod()
	end

	if hasluajit then
		_M:Main()
	else
		_M:NoJitMain()
	end
end

local env = _G.getfenv(main)
_G.setfenv(main, _G.setmetatable({}, {
	__index = function(t, k)
		return env[k] or _G[k]
	end
}))
main()
