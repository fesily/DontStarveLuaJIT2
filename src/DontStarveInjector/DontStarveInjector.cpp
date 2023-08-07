// DontStarveInjector.cpp : Defines the exported functions for the DLL application.
//

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_NONSTDC_NO_WARNINGS
#include <windows.h>
#include "DontStarveInjector.h"
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <cassert>
#include <TCHAR.h>
#include <ImageHlp.h>
#include <list>
#include <stdio.h>
#include <array>
#include <atomic>
#include <TlHelp32.h>
#pragma comment(lib, "dbghelp.lib")
#include <lua.hpp>

#if USE_LISTENER
#include <frida-gum.h>
#endif
#include "config.hpp"
#include "../signatures.hpp"
#include "../missfunc.h"
#include "inlinehook.hpp"
#include "LuaModule.hpp"
#include "module.hpp"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

G_NORETURN void showError(const char *msg)
{
	MessageBoxA(NULL, msg, "error!", 0);
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

static bool ReplaceLuaFunc(const ExportDetails *details)
{
	auto iter = signatures.funcs.find(details->name);
	if (iter == signatures.funcs.end())
	{
		std::string msg = std::string("can't find signature:") + details->name;
		showError(msg.c_str());
		return false;
	}
	void *replacer = GetLuaJitAddress(details->name);
	assert(replacer != nullptr);
#if !ONLY_LUA51
	if (details->name == "lua_newstate"sv)
	{
		// TODO 2.1 delete this
		replacer = &lua_newstate_hooker;
	}
	if (details->name == "lua_setfield"sv)
	{
		replacer = &lua_setfield_fake;
	}
#endif
	void *target = GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(iter->second));

	if (!Hook((uint8_t *)target, (uint8_t *)replacer))
	{
		std::string msg = std::string("replace error:") + details->name;
		showError(msg.c_str());
		return false;
	}
	
	char buf[255];
	snprintf(buf, 255, "replace %s: %p\n", details->name, target);
	OutputDebugStringA(buf);
	return true;
}

static bool ReplaceLuaFuncCb(const ExportDetails *details,
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
	ReplaceLuaFunc(details);
	return true;
}

void voidFunc()
{
}

static void ReplaceLuaModule()
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
		showError("can't find luamodule base address");
	}
	module_enumerate_exports(h51, ReplaceLuaFuncCb, NULL);

#if DEBUG_GETSIZE_PATCH
	if (luaRegisterDebugGetsizeSignature.scan(filename))
	{
#if DEBUG_GETSIZE_PATCH == 1
		auto code = std::to_array<uint8_t>({0x48, 0xc7, 0xc2, 0, 0, 0, 0, 0x90});
		HookWriteCode((uint8_t *)luaRegisterDebugGetsizeSignature.target_address, code);
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

extern "C" __declspec(dllexport) void Inject()
{
	gum_init();
#if USE_LISTENER
	interceptor = gum_interceptor_obtain();
#endif
	ReplaceLuaModule();
#if 0
	RedirectOpenGLEntries();
#endif
}
