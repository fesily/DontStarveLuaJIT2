// DontStarveInjector.cpp : Defines the exported functions for the DLL application.
//

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_NONSTDC_NO_WARNINGS
#include <string>
#include <algorithm>

#include <windows.h>

#include <lua.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/msvc_sink.h>
#if USE_LISTENER
#include <frida-gum.h>
#endif
#include "config.hpp"
#include "inlinehook.hpp"
#include "module.hpp"
#include "LuaModule.hpp"
#include "DontStarveSignature.hpp"
#include "SignatureJson.hpp"

#include "../missfunc.h"

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

static void voidFunc()
{
}

static std::string getMainPath()
{
	HMODULE hmain = GetModuleHandle(NULL);
	char filename[MAX_PATH];
	GetModuleFileNameA(hmain, filename, MAX_PATH);
	return filename;
}

static void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports)
{
	hluajitModule = LoadLibraryA(luajitModuleName);

	std::list<uint8_t *> hookeds;
	for (auto &[name, _] : exports)
	{
		auto offset = signatures.funcs.at(name);
		auto target = (uint8_t *)GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
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
	if (luaRegisterDebugGetsizeSignature.scan(mainPath.c_str()))
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
}

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

template <typename T>
static std::expected<ListExports_t, std::string> get_signatures(Signatures &signatures, uintptr_t targetLuaModuleBase, T &&updated)
{
	HMODULE h51 = LoadLibraryA(lua51_name);
	ListExports_t exports;
	module_enumerate_exports(h51, ListLuaFuncCb, &exports);
	std::sort(exports.begin(), exports.end(), [](auto &l, auto &r)
			  { return l.second > r.second; });

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
	{
		FreeLibrary(h51);
		return std::unexpected(errormsg);
	}
	if (SignatureJson::current_version() != signatures.version)
	{
		errormsg = update_signatures(signatures, targetLuaModuleBase, exports);
		if (!errormsg.empty())
		{
			FreeLibrary(h51);
			return std::unexpected(errormsg);
		}
		signatures.version = SignatureJson::current_version();
		updated(signatures);
	}
	FreeLibrary(h51);
	return exports;
}

#pragma endregion Attach

extern "C" __declspec(dllexport) void Inject(bool isClient)
{
	gum_init();
	spdlog::set_default_logger(std::make_shared<spdlog::logger>("", std::make_shared<spdlog::sinks::msvc_sink_st>()));
#if USE_LISTENER
	interceptor = gum_interceptor_obtain();
#endif

	auto mainPath = getMainPath();
	if (luaModuleSignature.scan(mainPath.c_str()) == NULL)
	{
		spdlog::error("can't find luamodule base address");
		return;
	}
	SignatureJson json(isClient);
	auto signatures = json.read_from_signatures().value();

	auto res = get_signatures(signatures, luaModuleSignature.target_address, [&json](auto &v)
							  { json.update_signatures(v); });
	if (!res)
	{
		showError(res.error());
		return;
	}
	auto &exports = res.value();
	ReplaceLuaModule(mainPath, signatures, exports);
#if 0
	RedirectOpenGLEntries();
#endif
}
