
#include "lstate.h"
#include "lobject.h"
#include <stdint.h>

int64_t sub_7FF7D069AAE0(TValue *a1, int calc_proto, int calc_upvalue)
{

  union Closure* cl = clvalue(a1);
  if ( cl->c.isC )
    return 16 * cl->c.nupvalues + 40;
  int64_t v5 = 0;
  int64_t v6 = calc_upvalue ? 40 * cl->c.nupvalues : 0;
  if ( calc_proto )
  {
    Proto * f = cl->l.p;
    v5 = 4
       * (f->sizecode
        + f->sizelineinfo
        + 2 * (f->sizeupvalues + f->sizep + 2 * (f->sizek + f->sizelocvars))
        + 30);
  }
  return v6 + v5 + 8 * cl->c.nupvalues + 40;
}

int64_t sub_7FF7D069AB60(lua_State *L)
{
  int calc_upvalue = 1; // r15d
  int64_t result; // rax
  int calc_proto = 0; // [rsp+60h] [rbp+8h]
  size_t len = 0; // [rsp+68h] [rbp+10h] BYREF
  TValue * base = L->base;
  char Buf[8];
  const char * options = luaL_optlstring(L, 2, Buf, &len);
  
  int use_v = 1;
  for ( size_t v5 = 0; v5 < len; ++v5 )
  {
    switch ( options[v5] )
    {
      case 'P':
        calc_proto = 0;
        break;
      case 'U':
        calc_upvalue = 0;
        break;
      case 'V':
        use_v = 0;
        break;
      case 'p':
        calc_proto = 1;
        break;
      case 'u':
        calc_upvalue = 1;
        break;
      case 'v':
        use_v = 1;
        break;
      default:
       luaL_error(L, "unknown option for 'getsize': %c", (unsigned int)options[v5]);
    }
  }
  switch ( lua_type(L, 1) )
  {
    case LUA_TNIL:
      lua_pushinteger(L, 0);
      result = 1;
      break;
    case LUA_TBOOLEAN:
      lua_pushinteger(L, use_v != 0 ? 4 : 0);
      result = 1;
      break;
    case LUA_TLIGHTUSERDATA:
    case LUA_TNUMBER:
      lua_pushinteger(L, use_v != 0 ? 8 : 0);
      result = 1;
      break;
    case LUA_TSTRING:
      lua_pushinteger(L, tsvalue(base)->len + 25);
      result = 1;
      break;
    case LUA_TTABLE:
    {
      unsigned int v2 = 0;
      Table* tt = hvalue(base);
       if ( tt->node != (Node *)lua_lua_touserdata(L, lua_upvalueindex(1)) )
        v2 = 1 << tt->lsizenode;
      int sizearray = tt->sizearray;
      lua_lua_pushinteger(L, 16 * (sizearray + 4) + 40 * v2);
      lua_lua_pushinteger(L, sizearray);
      lua_lua_pushinteger(L, v2);
      result = 3;
      break;
    }

    case LUA_TFUNCTION:
    {
      int64_t v10 = sub_7FF7D069AAE0(base, calc_proto, calc_upvalue);
      lua_pushinteger(L, v10);
      
      result = 1;
      break;
    }
    case LUA_TUSERDATA:
      lua_pushinteger(L, uvalue(base)->len + 40);
      result = 1;
      break;
    case LUA_TTHREAD:
    {
      lua_State* th = thvalue(base);
      lua_pushinteger(L, 16 * th->stacksize + 8 * (5 * th->size_ci + 25));
      result = 1;
      break;
    }
  
    default:
      result = 0;
      break;
  }
  return result;
}


void register_debug_getsize(lua_State *a1)
{
  lua_getfield(a1, -10002, "debug");
  lua_createtable(a1, 0, 0);
  lua_pushlightuserdata(a1, a1->base[1].value.gc->cl.c.f);
  lua_pushcclosure(a1, sub_7FF7D069AB60, 1);
  lua_setfield(a1, 1, "getsize");
  lua_settop(a1, -2);
}
