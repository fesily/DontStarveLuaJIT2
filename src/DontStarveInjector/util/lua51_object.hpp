#pragma once
#include "config/InjectorHostConfig.hpp"
#include <lua.h>

DS_INJECTOR_CXX_API void lua51_setallocf(lua_State *L, lua_Alloc f, void *ud);
DS_INJECTOR_CXX_API lua_Alloc lua51_getallocf(lua_State *L, void **ud);
DS_INJECTOR_CXX_API int lua51_sethook(lua_State *L, lua_Hook hook, int mask, int count);
DS_INJECTOR_CXX_API int lua51_gethookcount(lua_State *L);
DS_INJECTOR_CXX_API const char* lua51_getlocal(lua_State *L, const lua_Debug *ar, int n);
DS_INJECTOR_CXX_API const char* lua51_setlocal(lua_State *L, const lua_Debug *ar, int n);