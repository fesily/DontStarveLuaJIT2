// DontStarveInjector.cpp : Defines the exported functions for the DLL application.
//

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_NONSTDC_NO_WARNINGS
#include <windows.h>
#include "DontStarveInjector.h"
#include <string>
#include <vector>
#include <algorithm>
#include <charconv>
#include <fstream>
#include <iostream>
#include <lua.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/msvc_sink.h>
#if USE_LISTENER
#include <frida-gum.h>
#endif
#include "config.hpp"
#include "../signatures_server.hpp"
#include "../signatures_client.hpp"
#include "../missfunc.h"
#include "inlinehook.hpp"
#include "LuaModule.hpp"
#include "module.hpp"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

G_NORETURN void showError(const std::string_view &msg)
{
	MessageBoxA(NULL, msg.data(), "error!", 0);
	std::exit(1);
}

static const char *luajitModuleName =
#if ONLY_LUA51
	"Lua51";
#else
	"Lua51DS";
#endif
static HMODULE hluajitModule;
#include "api_listener.hpp"

#if USE_FAKE_API
extern std::unordered_map<std::string_view, void *> lua_fake_apis;

#include <lua.hpp>
void *GetLuaJitAddress(const char *name)
{
	char buf[64];
	snprintf(buf, 64, "fake_%s", name);
	return lua_fake_apis[name];
}
#else
#define GetLuaJitAddress(name) GetProcAddress(hluajitModule, name)
#endif
#pragma region Attach

#if USE_LISTENER
static GumInterceptor *interceptor;
#endif

#if !ONLY_LUA51
static void *lua_newstate_hooker(void *, void *ud)
{
	auto L = luaL_newstate();
	char buf[64];
	snprintf(buf, 64, "luaL_newstate:%p\n", L);
	OutputDebugStringA(buf);
	return L;
}
#if USE_FAKE_API
extern lua_State *map_handler(lua_State *L);
#endif
void lua_setfield_fake(lua_State *L, int idx, const char *k)
{
#if USE_FAKE_API
	L = map_handler(L);
#endif
	if (lua_gettop(L) == 0)
		lua_pushnil(L);
	lua_setfield(L, idx, k);
}
#endif

#if USE_LISTENER
GumInvocationListener *listener;
static gboolean PrintCallCb(const GumExportDetails *details,
							gpointer user_data)
{
	gum_interceptor_attach(interceptor, (void *)details->address, listener, (void *)details->name);
	return true;
}
#endif

static void *get_luajit_address(const std::string_view &name)
{
	void *replacer = GetLuaJitAddress(name.data());
	assert(replacer != nullptr);
#if !ONLY_LUA51
	if (name == "lua_newstate"sv)
	{
		// TODO 2.1 delete this
		replacer = &lua_newstate_hooker;
	}
	else if (name == "lua_setfield"sv)
	{
		replacer = &lua_setfield_fake;
	}
#endif
	return replacer;
}

using ListExports_t = std::vector<std::pair<std::string, GumAddress>>;
static bool ListLuaFuncCb(const ExportDetails *details,
						  void *user_data)
{
	if (missfuncs.find(details->name) != missfuncs.end())
	{
		return true;
	}
#if USE_GAME_IO
	if (details->name == "luaL_openlibs"sv || details->name == "luaopen_io"sv)
	{
		return true;
	}
#endif
	auto &exports = *(ListExports_t *)user_data;
	exports.emplace_back(details->name, (GumAddress)details->address);
	return true;
}

static void voidFunc()
{
}

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Signatures, version, funcs);

static std::string get_signatures_filename(bool isClient)
{
	return "sigantures_"s + (isClient ? "client" : "server");
}

static void read_from_signatures(bool isClient)
{
	auto &sigantures = isClient ? signatures_client : signatures_server;
	std::ifstream sf(get_signatures_filename(isClient));
	if (!sf.is_open())
		return;
	nlohmann::json j;
	sf >> j;
	auto new_one = j.get<decltype(signatures_client)>();
	if (new_one.version > sigantures.version)
	{
		sigantures.funcs = std::move(new_one.funcs);
	}
}

static intptr_t current_version = []() -> intptr_t
{
	auto version_fp = fopen("../version.txt", "r");
	if (!version_fp)
		return -1;
	char buf[128];
	auto readed = fread(buf, sizeof(char), sizeof(buf) / sizeof(char), version_fp);
	fclose(version_fp);
	if (readed <= 0)
		return -1;
	intptr_t version;
	auto ret = std::from_chars(buf, buf + readed, version);
	if (ret.ec != std::errc{})
		return -1;
	return version;
}();

static void update_signatures(bool isClient)
{
	auto &signatures = isClient ? signatures_client : signatures_server;
	assert(current_version != signatures.version);
	signatures.version = current_version;
	std::ofstream sf(get_signatures_filename(isClient));
	nlohmann::json j;
	nlohmann::to_json(j, signatures);
	sf << j;
}

static void ReplaceLuaModule(bool isClient)
{
	HMODULE hmain = GetModuleHandle(NULL);
	char filename[255];
	memset(filename, 0, 255);
	GetModuleFileNameA(hmain, filename, 255);
	const char *lua51_name = "lua51";
	HMODULE h51 = LoadLibraryA(lua51_name);
	hluajitModule = LoadLibraryA(luajitModuleName);
	if (luaModuleSignature.scan(filename) == NULL)
	{
		spdlog::error("can't find luamodule base address");
		return;
	}
	ListExports_t exports;
	module_enumerate_exports(h51, ListLuaFuncCb, &exports);
	std::sort(exports.begin(), exports.end(), [](auto &l, auto &r)
			  { return l.second > r.second; });

	read_from_signatures(isClient);

	auto &signatures = isClient ? signatures_client : signatures_server;
	auto &funcs = signatures.funcs;
	std::string errormsg;

	for (auto &[name, address] : exports)
	{
		if (!funcs.contains(name))
		{
			errormsg += name + ";";
		}
	}
	if (!errormsg.empty())
		showError(errormsg.c_str());

	if (current_version != signatures.version)
	{
		spdlog::warn("try fix all signatures");
		auto hMain = GetModuleHandle(NULL);
		// fix all signatures
		for (size_t i = 0; i < exports.size(); i++)
		{
			auto &[name, _] = exports[i];
			auto original = GetProcAddress(h51, name.c_str());
			auto old_offset = GPOINTER_TO_INT(funcs[name]);
			void *target = GSIZE_TO_POINTER(luaModuleSignature.target_address + old_offset);
			auto target1 = fix_func_address_by_signature(target, hMain, original, h51, nullptr);
			if (!target1)
			{
				spdlog::error("func[{}] can't fix address, wait for mod update", name);
				return;
			}
			if (target1 == target)
				continue;
			auto new_offset = (intptr_t)target1 - (intptr_t)luaModuleSignature.target_address;
			spdlog::info("update signatures [{}]: {} to {}", name, old_offset, new_offset);
			funcs[name] = new_offset;
		}
		update_signatures(isClient);
	}

	std::list<uint8_t *> hookeds;
	for (auto &[name, _] : exports)
	{
		auto target = (uint8_t *)GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(funcs[name]));
		auto replacer = (uint8_t *)get_luajit_address(name);
		if (!Hook(target, replacer))
		{
			spdlog::error("replace {} failed", name);
			break;
		}
		hookeds.emplace_back(target);
		spdlog::info("replace {}: {} to {}", name, (void *)target, (void *)replacer);
	}

	if (hookeds.size() != exports.size())
	{
		for (auto target : hookeds)
		{
			ResetHook(target);
		}
		spdlog::info("reset all hook");
		return;
	}

#if DEBUG_GETSIZE_PATCH
	if (luaRegisterDebugGetsizeSignature.scan(filename))
	{
#if DEBUG_GETSIZE_PATCH == 1
		auto code = std::to_array<uint8_t>({0x48, 0xc7, 0xc2, 0, 0, 0, 0, 0x90});
		HookWriteCode((uint8_t *)luaRegisterDebugGetsizeSignature.target_address, code.data(), code.size());
#else
		Hook((uint8_t *)luaRegisterDebugGetsizeSignature.target_address, (uint8_t *)&voidFunc);
#endif
	}
#endif

#if REPLACE_IO
	extern void init_luajit_io(HMODULE hluajitModule);
	init_luajit_io(hluajitModule);
#endif

#if USE_LISTENER
	listener = (GumInvocationListener *)g_object_new(EXAMPLE_TYPE_LISTENER, NULL);
	gum_module_enumerate_exports(target_module_name, PrintCallCb, NULL);
#endif
	FreeLibrary(h51);
}

#pragma endregion Attach

extern "C" __declspec(dllexport) void Inject(bool isClient)
{
	gum_init();
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("", std::make_shared<spdlog::sinks::msvc_sink_st>()));
#if USE_LISTENER
	interceptor = gum_interceptor_obtain();
#endif
	ReplaceLuaModule(isClient);
#if 0
	RedirectOpenGLEntries();
#endif
}
