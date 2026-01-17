#pragma once
#include <lua.h>

void lua51_setallocf(lua_State *L, lua_Alloc f, void *ud);
lua_Alloc lua51_getallocf(lua_State *L, void **ud);
int lua51_sethook(lua_State *L, lua_Hook hook, int mask, int count);
int lua51_gethookcount(lua_State *L);
const char* lua51_getlocal(lua_State *L, const lua_Debug *ar, int n);
const char* lua51_setlocal(lua_State *L, const lua_Debug *ar, int n);