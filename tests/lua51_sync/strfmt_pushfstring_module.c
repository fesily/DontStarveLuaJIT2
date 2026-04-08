#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#endif

typedef struct lua_State lua_State;

typedef void (*lua_createtable_fn)(lua_State *L, int narr, int nrec);
typedef void (*lua_pushstring_fn)(lua_State *L, const char *s);
typedef const char *(*lua_pushfstring_fn)(lua_State *L, const char *fmt, ...);
typedef void (*lua_setfield_fn)(lua_State *L, int idx, const char *k);

typedef struct LuaApi {
  lua_createtable_fn createtable;
  lua_pushstring_fn pushstring;
  lua_pushfstring_fn pushfstring;
  lua_setfield_fn setfield;
} LuaApi;

static LuaApi lua_api;
static int lua_api_initialized;
static int lua_api_ready;

#ifdef _WIN32
static int resolve_symbol(HMODULE module)
{
  if (module == NULL)
    return 0;
  if (lua_api.createtable == NULL)
    lua_api.createtable = (lua_createtable_fn)GetProcAddress(module, "lua_createtable");
  if (lua_api.pushstring == NULL)
    lua_api.pushstring = (lua_pushstring_fn)GetProcAddress(module, "lua_pushstring");
  if (lua_api.pushfstring == NULL)
    lua_api.pushfstring = (lua_pushfstring_fn)GetProcAddress(module, "lua_pushfstring");
  if (lua_api.setfield == NULL)
    lua_api.setfield = (lua_setfield_fn)GetProcAddress(module, "lua_setfield");
  return lua_api.createtable != NULL && lua_api.pushstring != NULL &&
         lua_api.pushfstring != NULL && lua_api.setfield != NULL;
}

static int resolve_lua_api(void)
{
  static const char *const module_names[] = {
    "lua51DS.dll",
    "lua51Original.dll",
    "lua51.dll"
  };
  size_t i;

  if (lua_api_initialized)
    return lua_api_ready;

  lua_api_initialized = 1;
  lua_api_ready = resolve_symbol(GetModuleHandleA(NULL));
  for (i = 0; !lua_api_ready && i < sizeof(module_names) / sizeof(module_names[0]); i++)
    lua_api_ready = resolve_symbol(GetModuleHandleA(module_names[i]));
  return lua_api_ready;
}
#else
static int resolve_lua_api(void)
{
  return 0;
}
#endif

static void set_string_field(lua_State *L, const char *field, const char *value)
{
  lua_api.pushstring(L, value);
  lua_api.setfield(L, -2, field);
}

#ifdef _WIN32
__declspec(dllexport)
#endif
int luaopen_strfmt_pushfstring_module(lua_State *L)
{
  if (!resolve_lua_api())
    return 0;

  lua_api.createtable(L, 0, 6);
  lua_api.pushfstring(L, "%y", "unused");
  lua_api.setfield(L, -2, "plain_invalid");
  lua_api.pushfstring(L, "[%?]", "unused");
  lua_api.setfield(L, -2, "wrapped_invalid");
  lua_api.pushfstring(L, "%08y", "unused");
  lua_api.setfield(L, -2, "width_invalid");
  lua_api.pushfstring(L, "%.2y", "unused");
  lua_api.setfield(L, -2, "precision_invalid");
  lua_api.pushfstring(L, "%-6y", "unused");
  lua_api.setfield(L, -2, "left_invalid");
#ifndef _WIN32
  set_string_field(L, "platform", "unsupported");
#else
  set_string_field(L, "platform", "windows");
#endif
  return 1;
}