/*
** $Id: lua.h,v 1.218.1.5 2008/08/06 13:30:12 roberto Exp $
** Lua - An Extensible Extension Language
** Lua.org, PUC-Rio, Brazil (http://www.lua.org)
** See Copyright Notice at the end of this file
*/
#include "config.hpp"
#if USE_FAKE_API
#include <stddef.h>
#include <array>
#include <type_traits>
#include <unordered_map>
#include <string_view>
using namespace std::literals;
#define LUA_BUILD_AS_DLL 1
#define LUA_LIB 1
#include <lua.hpp>

static int currentAddress = 0;
static lua_State *maxAddress = (lua_State *)4096;

typedef struct lua_State lua_State;

static std::array<lua_State *, 4096> handler;

lua_State *map_handler(lua_State *L)
{
  if (L > maxAddress)
    return L;
  return handler[(int)L];
}

lua_State *create_handler(lua_State *L)
{
  if (L > maxAddress)
  {
    currentAddress++;
    handler[currentAddress] = L;
    return (lua_State *)currentAddress;
  }
  return L;
}

template <typename T>
constexpr auto is_lua_state_v = std::is_same_v<T, lua_State *>;

template <typename T>
auto transform_args(T arg)
{
  if constexpr (is_lua_state_v<T>)
  {
    return map_handler(arg);
  }
  else
  {
    return arg;
  }
}

template <typename _Sub, typename _Fn>
struct caller_impl;

template <typename _Sub, typename _Ret, typename... _Args>
struct caller_impl<_Sub, _Ret (*)(_Args...)>
{
  static _Ret call(_Args... args)
  {
    if constexpr (is_lua_state_v<_Ret>)
    {
      return create_handler(_Sub::func_ref(transform_args(args)...));
    }
    else
    {
      return _Sub::func_ref(transform_args(args)...);
    }
  }
};

template <typename _Sub, typename _Ret, typename _T1>
struct caller_impl<_Sub, _Ret (*)(_T1, ...)>
{
  static _Ret call(_T1 t1, ...)
  {
    va_list vargs;
    va_start(vargs, t1);
    if constexpr (is_lua_state_v<_Ret>)
    {
      auto res = create_handler(_Sub::func_ref(transform_args(t1), vargs));
      va_end(vargs);
      return res;
    }
    else
    {
      auto res = _Sub::func_ref(transform_args(t1), vargs);
      va_end(vargs);
      return res;
    }
  }
};

template <typename _Sub, typename _Ret, typename _T1, typename _T2>
struct caller_impl<_Sub, _Ret (*)(_T1, _T2, ...)>
{

  static _Ret call(_T1 t1, _T2 t2, ...)
  {
    va_list vargs;
    va_start(vargs, t2);
    if constexpr (is_lua_state_v<_Ret>)
    {
      auto res = create_handler(_Sub::func_ref(transform_args(t1), transform_args(t2), vargs));
      va_end(vargs);
      return res;
    }
    else
    {
      auto res = _Sub::func_ref(transform_args(t1), transform_args(t2), vargs);
      va_end(vargs);
      return res;
    }
  }
};

template <auto _Fn>
struct forward_caller;

template <auto _Fn>
struct forward_caller : caller_impl<forward_caller<_Fn>, decltype(_Fn)>
{
  constexpr static auto func_ref = _Fn;
};

#define FAKE_API_NAME(name) #name##sv
#define FAKE_API(name)                              \
  {                                                 \
    FAKE_API_NAME(name), forward_caller<name>::call \
  }

std::unordered_map<std::string_view, void *> lua_fake_apis = {
    /*
    ** state manipulation
    */
    FAKE_API(lua_newstate),
    FAKE_API(lua_close),
    FAKE_API(lua_newthread),

    FAKE_API(lua_atpanic),

    /*
    ** basic stack manipulation
    */
    FAKE_API(lua_gettop),
    FAKE_API(lua_settop),
    FAKE_API(lua_pushvalue),
    FAKE_API(lua_remove),
    FAKE_API(lua_insert),
    FAKE_API(lua_replace),
    FAKE_API(lua_checkstack),

    FAKE_API(lua_xmove),

    /*
    ** access functions (stack -> C)
    */

    FAKE_API(lua_isnumber),
    FAKE_API(lua_isstring),
    FAKE_API(lua_iscfunction),
    FAKE_API(lua_isuserdata),
    FAKE_API(lua_type),
    FAKE_API(lua_typename),

    FAKE_API(lua_equal),
    FAKE_API(lua_rawequal),
    FAKE_API(lua_lessthan),

    FAKE_API(lua_tonumber),
    FAKE_API(lua_tointeger),
    FAKE_API(lua_toboolean),
    FAKE_API(lua_tolstring),
    FAKE_API(lua_objlen),
    FAKE_API(lua_tocfunction),
    FAKE_API(lua_touserdata),
    FAKE_API(lua_tothread),
    FAKE_API(lua_topointer),

    /*
    ** push functions (C -> stack)
    */
    FAKE_API(lua_pushnil),
    FAKE_API(lua_pushnumber),
    FAKE_API(lua_pushinteger),
    FAKE_API(lua_pushlstring),
    FAKE_API(lua_pushstring),
    FAKE_API(lua_pushvfstring),
    FAKE_API(lua_pushfstring),

    FAKE_API(lua_pushcclosure),
    FAKE_API(lua_pushboolean),
    FAKE_API(lua_pushlightuserdata),
    FAKE_API(lua_pushthread),

    /*
    ** get functions (Lua -> stack)
    */
    FAKE_API(lua_gettable),
    FAKE_API(lua_getfield),
    FAKE_API(lua_rawget),
    FAKE_API(lua_rawgeti),
    FAKE_API(lua_createtable),
    FAKE_API(lua_newuserdata),
    FAKE_API(lua_getmetatable),
    FAKE_API(lua_getfenv),

    /*
    ** set functions (stack -> Lua)
    */
    FAKE_API(lua_settable),
    FAKE_API(lua_setfield),
    FAKE_API(lua_rawset),
    FAKE_API(lua_rawseti),
    FAKE_API(lua_setmetatable),
    FAKE_API(lua_setfenv),

    /*
    ** `load' and `call' functions (load and run Lua code)
    */
    FAKE_API(lua_call),
    FAKE_API(lua_pcall),
    FAKE_API(lua_cpcall),
    FAKE_API(lua_load),

    FAKE_API(lua_dump),

    /*
    ** coroutine functions
    */
    FAKE_API(lua_yield),
    FAKE_API(lua_resume),
    FAKE_API(lua_status),

    /*
    ** garbage-collection function and options
    */

    FAKE_API(lua_gc),

    /*
    ** miscellaneous functions
    */

    FAKE_API(lua_error),

    FAKE_API(lua_next),

    FAKE_API(lua_concat),

    FAKE_API(lua_getallocf),
    FAKE_API(lua_setallocf),

    /*
    ** {======================================================================
    ** Debug API
    ** =======================================================================
    */

    FAKE_API(lua_getstack),
    FAKE_API(lua_getinfo),
    FAKE_API(lua_getlocal),
    FAKE_API(lua_setlocal),
    FAKE_API(lua_getupvalue),
    FAKE_API(lua_setupvalue),

    FAKE_API(lua_sethook),
    FAKE_API(lua_gethook),
    FAKE_API(lua_gethookmask),
    FAKE_API(lua_gethookcount),

    FAKE_API(luaL_openlib),
    FAKE_API(luaL_register),
    FAKE_API(luaL_getmetafield),
    FAKE_API(luaL_callmeta),
    FAKE_API(luaL_typerror),
    FAKE_API(luaL_argerror),
    FAKE_API(luaL_checklstring),
    FAKE_API(luaL_optlstring),
    FAKE_API(luaL_checknumber),
    FAKE_API(luaL_optnumber),

    FAKE_API(luaL_checkinteger),
    FAKE_API(luaL_optinteger),

    FAKE_API(luaL_checkboolean),
    FAKE_API(luaL_optboolean),

    FAKE_API(luaL_checkstack),
    FAKE_API(luaL_checktype),
    FAKE_API(luaL_checkany),

    FAKE_API(luaL_newmetatable),
    FAKE_API(luaL_checkudata),

    FAKE_API(luaL_where),
    FAKE_API(luaL_error),

    FAKE_API(luaL_checkoption),

    FAKE_API(luaL_ref),
    FAKE_API(luaL_unref),

    FAKE_API(luaL_loadfile),
    FAKE_API(luaL_loadbuffer),
    FAKE_API(luaL_loadstring),
#if !ONLY_LUA51
    FAKE_API(luaL_newstate),
#endif
    FAKE_API(luaL_gsub),

    FAKE_API(luaL_findtable),

#if !ONLY_LUA51
    /* From Lua 5.2. */
    FAKE_API(luaL_fileresult),
    FAKE_API(luaL_execresult),
    FAKE_API(luaL_loadfilex),
    FAKE_API(luaL_loadbufferx),
    FAKE_API(luaL_traceback),
#endif

    /*
    ** {======================================================
    ** Generic Buffer manipulation
    ** =======================================================
    */

    FAKE_API(luaL_buffinit),
    FAKE_API(luaL_prepbuffer),
    FAKE_API(luaL_addlstring),
    FAKE_API(luaL_addstring),
    FAKE_API(luaL_addvalue),
    FAKE_API(luaL_pushresult),

    FAKE_API(luaopen_base),
    FAKE_API(luaopen_math),
    FAKE_API(luaopen_string),
    FAKE_API(luaopen_table),
    FAKE_API(luaopen_io),
    FAKE_API(luaopen_os),
    FAKE_API(luaopen_package),
    FAKE_API(luaopen_debug),
#if !ONLY_LUA51
    FAKE_API(luaopen_bit),
    FAKE_API(luaopen_jit),
    FAKE_API(luaopen_ffi),
#endif

    FAKE_API(luaL_openlibs),
};

#endif