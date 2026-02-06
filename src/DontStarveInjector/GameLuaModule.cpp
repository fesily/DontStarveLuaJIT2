#include "config.hpp"
#include <cstdint>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <optional>
#include <slikenet/PacketPriority.h>

#ifndef _WIN32
#include <errno.h>
#endif

#define luaL_addlstring GameDbg_luaL_addlstring
#define luaL_addstring GameDbg_luaL_addstring
#define luaL_addvalue GameDbg_luaL_addvalue
#define luaL_argerror GameDbg_luaL_argerror
#define luaL_buffinit GameDbg_luaL_buffinit
#define luaL_callmeta GameDbg_luaL_callmeta
#define luaL_checkany GameDbg_luaL_checkany
#define luaL_checkinteger GameDbg_luaL_checkinteger
#define luaL_checklstring GameDbg_luaL_checklstring
#define luaL_checknumber GameDbg_luaL_checknumber
#define luaL_checkoption GameDbg_luaL_checkoption
#define luaL_checkstack GameDbg_luaL_checkstack
#define luaL_checktype GameDbg_luaL_checktype
#define luaL_checkudata GameDbg_luaL_checkudata
#define luaL_error GameDbg_luaL_error
#define luaL_execresult GameDbg_luaL_execresult
#define luaL_fileresult GameDbg_luaL_fileresult
#define luaL_findtable GameDbg_luaL_findtable
#define luaL_getmetafield GameDbg_luaL_getmetafield
#define luaL_gsub GameDbg_luaL_gsub
#define luaL_loadbufferx GameDbg_luaL_loadbufferx
#define luaL_loadfile GameDbg_luaL_loadfile
#define luaL_loadfilex GameDbg_luaL_loadfilex
#define luaL_loadstring GameDbg_luaL_loadstring
#define luaL_newmetatable GameDbg_luaL_newmetatable
#define luaL_newstate GameDbg_luaL_newstate
#define luaL_optinteger GameDbg_luaL_optinteger
#define luaL_optlstring GameDbg_luaL_optlstring
#define luaL_optnumber GameDbg_luaL_optnumber
#define luaL_pushresult GameDbg_luaL_pushresult
#define luaL_ref GameDbg_luaL_ref
#define luaL_setfuncs GameDbg_luaL_setfuncs
#define luaL_setmetatable GameDbg_luaL_setmetatable
#define luaL_testudata GameDbg_luaL_testudata
#define luaL_traceback GameDbg_luaL_traceback
#define luaL_typerror GameDbg_luaL_typerror
#define luaL_unref GameDbg_luaL_unref
#define luaL_where GameDbg_luaL_where
#define lua_absindex GameDbg_lua_absindex
#define lua_arith GameDbg_lua_arith
#define lua_atpanic GameDbg_lua_atpanic
#define lua_checkstack GameDbg_lua_checkstack
#define lua_close GameDbg_lua_close
#define lua_compare GameDbg_lua_compare
#define lua_concat GameDbg_lua_concat
#define lua_copy GameDbg_lua_copy
#define lua_createtable GameDbg_lua_createtable
#define lua_dump GameDbg_lua_dump
#define lua_error GameDbg_lua_error
#define lua_gc GameDbg_lua_gc
#define lua_getallocf GameDbg_lua_getallocf
#define lua_getfield GameDbg_lua_getfield

#define lua_gethook GameDbg_lua_gethook
#define lua_gethookcount GameDbg_lua_gethookcount
#define lua_gethookmask GameDbg_lua_gethookmask
#define lua_getinfo GameDbg_lua_getinfo
#define lua_getlocal GameDbg_lua_getlocal
#define lua_getmetatable GameDbg_lua_getmetatable
#define lua_getstack GameDbg_lua_getstack
#define lua_gettable GameDbg_lua_gettable
#define lua_gettop GameDbg_lua_gettop
#define lua_getupvalue GameDbg_lua_getupvalue
#define lua_iscfunction GameDbg_lua_iscfunction
#define lua_isnumber GameDbg_lua_isnumber
#define lua_isstring GameDbg_lua_isstring
#define lua_isuserdata GameDbg_lua_isuserdata
#define lua_isyieldable GameDbg_lua_isyieldable
#define lua_len GameDbg_lua_len
#define lua_newstate GameDbg_lua_newstate
#define lua_newthread GameDbg_lua_newthread
#define lua_newuserdata GameDbg_lua_newuserdata
#define lua_next GameDbg_lua_next
#define lua_pushboolean GameDbg_lua_pushboolean
#define lua_pushcclosure GameDbg_lua_pushcclosure
#define lua_pushfstring GameDbg_lua_pushfstring
#define lua_pushinteger GameDbg_lua_pushinteger
#define lua_pushlightuserdata GameDbg_lua_pushlightuserdata
#define lua_pushlstring GameDbg_lua_pushlstring
#define lua_pushnil GameDbg_lua_pushnil
#define lua_pushnumber GameDbg_lua_pushnumber
#define lua_pushstring GameDbg_lua_pushstring
#define lua_pushthread GameDbg_lua_pushthread
#define lua_pushvalue GameDbg_lua_pushvalue
#define lua_pushvfstring GameDbg_lua_pushvfstring
#define lua_rawequal GameDbg_lua_rawequal
#define lua_rawget GameDbg_lua_rawget
#define lua_rawgeti GameDbg_lua_rawgeti

#define lua_rawset GameDbg_lua_rawset
#define lua_rawseti GameDbg_lua_rawseti
#define lua_replace GameDbg_lua_replace

#define lua_setallocf GameDbg_lua_setallocf
#define lua_setfield GameDbg_lua_setfield
#define lua_remove GameDbg_lua_remove
#define lua_getfenv GameDbg_lua_getfenv
#define lua_setfenv GameDbg_lua_setfenv
#define luaL_register GameDbg_luaL_register
#define lua_objlen GameDbg_lua_objlen
#define lua_call GameDbg_lua_call
#define lua_pcall GameDbg_lua_pcall
#define lua_cpcall GameDbg_lua_cpcall
#define luaL_loadbuffer GameDbg_luaL_loadbuffer
#define lua_insert GameDbg_lua_insert
#define lua_equal GameDbg_lua_equal
#define lua_lessthan GameDbg_lua_lessthan
#define lua_load GameDbg_lua_load
#define lua_sethook GameDbg_lua_sethook
#define lua_setlocal GameDbg_lua_setlocal
#define lua_setmetatable GameDbg_lua_setmetatable
#define lua_settable GameDbg_lua_settable
#define lua_settop GameDbg_lua_settop
#define lua_setupvalue GameDbg_lua_setupvalue
#define lua_status GameDbg_lua_status
#define lua_toboolean GameDbg_lua_toboolean
#define lua_tocfunction GameDbg_lua_tocfunction
#define lua_tointegerx GameDbg_lua_tointegerx
#define lua_tolstring GameDbg_lua_tolstring
#define lua_tonumber GameDbg_lua_tonumber
#define lua_tonumberx GameDbg_lua_tonumberx
#define lua_topointer GameDbg_lua_topointer
#define lua_tothread GameDbg_lua_tothread
#define lua_touserdata GameDbg_lua_touserdata
#define lua_type GameDbg_lua_type
#define lua_typename GameDbg_lua_typename
#define lua_upvalueid GameDbg_lua_upvalueid
#define lua_upvaluejoin GameDbg_lua_upvaluejoin
#define lua_version GameDbg_lua_version
#define lua_xmove GameDbg_lua_xmove
#define lua_yield GameDbg_lua_yield
#define luaopen_base GameDbg_luaopen_base
#define luaopen_debug GameDbg_luaopen_debug
#define luaopen_io GameDbg_luaopen_io
#define luaopen_math GameDbg_luaopen_math
#define luaopen_os GameDbg_luaopen_os
#define luaopen_package GameDbg_luaopen_package
#define luaopen_string GameDbg_luaopen_string
#define luaopen_table GameDbg_luaopen_table

#include <lua.hpp>

DONTSTARVEINJECTOR_API int lua_absindex(lua_State *L, int idx);

#define COMPAT53_API static inline

#define COMPAT53_CONCAT_HELPER(a, b) a##b
#define COMPAT53_CONCAT(a, b) COMPAT53_CONCAT_HELPER(a, b)



/* declarations for Lua 5.1 */
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM == 501

/* XXX not implemented:
* lua_arith (new operators)
* lua_upvalueid
* lua_upvaluejoin
* lua_version
* lua_yieldk
*/

#ifndef LUA_OK
#  define LUA_OK 0
#endif
#ifndef LUA_OPADD
#  define LUA_OPADD 0
#endif
#ifndef LUA_OPSUB
#  define LUA_OPSUB 1
#endif
#ifndef LUA_OPMUL
#  define LUA_OPMUL 2
#endif
#ifndef LUA_OPDIV
#  define LUA_OPDIV 3
#endif
#ifndef LUA_OPMOD
#  define LUA_OPMOD 4
#endif
#ifndef LUA_OPPOW
#  define LUA_OPPOW 5
#endif
#ifndef LUA_OPUNM
#  define LUA_OPUNM 6
#endif
#ifndef LUA_OPEQ
#  define LUA_OPEQ 0
#endif
#ifndef LUA_OPLT
#  define LUA_OPLT 1
#endif
#ifndef LUA_OPLE
#  define LUA_OPLE 2
#endif

/* LuaJIT/Lua 5.1 does not have the updated
* error codes for thread status/function returns (but some patched versions do)
* define it only if it's not found
*/
#if !defined(LUA_ERRGCMM)
/* Use + 2 because in some versions of Lua (Lua 5.1)
* LUA_ERRFILE is defined as (LUA_ERRERR+1)
* so we need to avoid it (LuaJIT might have something at this
* integer value too)
*/
#  define LUA_ERRGCMM (LUA_ERRERR + 2)
#endif /* LUA_ERRGCMM define */

#if !defined(MOONJIT_VERSION)
typedef size_t lua_Unsigned;
#endif

typedef struct luaL_Buffer_53 {
	luaL_Buffer b; /* make incorrect code crash! */
	char *ptr;
	size_t nelems;
	size_t capacity;
	lua_State *L2;
} luaL_Buffer_53;
#define luaL_Buffer luaL_Buffer_53

/* In PUC-Rio 5.1, userdata is a simple FILE*
* In LuaJIT, it's a struct where the first member is a FILE*
* We can't support the `closef` member
*/
typedef struct luaL_Stream {
	FILE *f;
} luaL_Stream;

COMPAT53_API void lua_arith(lua_State *L, int op);

COMPAT53_API int lua_compare(lua_State *L, int idx1, int idx2, int op);

#define lua_getuservalue(L, i) \
  (lua_getfenv((L), (i)), lua_type((L), -1))
#define lua_setuservalue(L, i) \
  (luaL_checktype((L), -1, LUA_TTABLE), lua_setfenv((L), (i)))

COMPAT53_API void lua_len(lua_State *L, int i);

#undef lua_pushstring
#define lua_pushstring(L, s) \
  (GameDbg_lua_pushstring((L), (s)), lua_tostring((L), -1))

#undef lua_pushlstring
#define lua_pushlstring(L, s, len) \
  ((((len) == 0) ? GameDbg_lua_pushlstring((L), "", 0) : GameDbg_lua_pushlstring((L), (s), (len))), lua_tostring((L), -1))

#ifndef luaL_newlibtable
#  define luaL_newlibtable(L, l) \
  (lua_createtable((L), 0, sizeof((l))/sizeof(*(l))-1))
#endif
#ifndef luaL_newlib
#  define luaL_newlib(L, l) \
  (luaL_newlibtable((L), (l)), luaL_register((L), NULL, (l)))
#endif

#ifndef lua_pushglobaltable
#  define lua_pushglobaltable(L) \
  lua_pushvalue((L), LUA_GLOBALSINDEX)
#endif
#define lua_rawgetp COMPAT53_CONCAT(COMPAT53_PREFIX, _rawgetp)
COMPAT53_API int lua_rawgetp(lua_State *L, int i, const void *p);

#define lua_rawsetp COMPAT53_CONCAT(COMPAT53_PREFIX, _rawsetp)
COMPAT53_API void lua_rawsetp(lua_State *L, int i, const void *p);

#define lua_rawlen(L, i) lua_objlen((L), (i))

#define lua_tointeger(L, i) lua_tointegerx((L), (i), NULL)

#define luaL_checkversion COMPAT53_CONCAT(COMPAT53_PREFIX, L_checkversion)
COMPAT53_API void luaL_checkversion(lua_State *L);

#undef luaL_getsubtable
#define luaL_getsubtable COMPAT53_CONCAT(COMPAT53_PREFIX, L_getsubtable)
COMPAT53_API int luaL_getsubtable(lua_State* L, int i, const char *name);

#undef luaL_len
#define luaL_len COMPAT53_CONCAT(COMPAT53_PREFIX, L_len)
COMPAT53_API lua_Integer luaL_len(lua_State *L, int i);

#undef luaL_setfuncs
#define luaL_setfuncs COMPAT53_CONCAT(COMPAT53_PREFIX, L_setfuncs)
COMPAT53_API void luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup);

#undef luaL_setmetatable
#define luaL_setmetatable COMPAT53_CONCAT(COMPAT53_PREFIX, L_setmetatable)
COMPAT53_API void luaL_setmetatable(lua_State *L, const char *tname);

#undef luaL_testudata
#define luaL_testudata COMPAT53_CONCAT(COMPAT53_PREFIX, L_testudata)
COMPAT53_API void *luaL_testudata(lua_State *L, int i, const char *tname);

#undef luaL_traceback
#define luaL_traceback COMPAT53_CONCAT(COMPAT53_PREFIX, L_traceback)
COMPAT53_API void luaL_traceback(lua_State *L, lua_State *L1, const char *msg, int level);

#undef luaL_fileresult
#define luaL_fileresult COMPAT53_CONCAT(COMPAT53_PREFIX, L_fileresult)
COMPAT53_API int luaL_fileresult(lua_State *L, int stat, const char *fname);

#undef luaL_execresult
#define luaL_execresult COMPAT53_CONCAT(COMPAT53_PREFIX, L_execresult)
COMPAT53_API int luaL_execresult(lua_State *L, int stat);

#define lua_callk(L, na, nr, ctx, cont) \
  ((void)(ctx), (void)(cont), lua_call((L), (na), (nr)))
#define lua_pcallk(L, na, nr, err, ctx, cont) \
  ((void)(ctx), (void)(cont), lua_pcall((L), (na), (nr), (err)))

#define lua_resume(L, from, nargs) \
  ((void)(from), GameDbg_lua_resume((L), (nargs)))

#undef luaL_buffinit
#define luaL_buffinit COMPAT53_CONCAT(COMPAT53_PREFIX, _buffinit_53)
COMPAT53_API void luaL_buffinit(lua_State *L, luaL_Buffer_53 *B);

#undef luaL_prepbuffsize
#define luaL_prepbuffsize COMPAT53_CONCAT(COMPAT53_PREFIX, _prepbufsize_53)
COMPAT53_API char *luaL_prepbuffsize(luaL_Buffer_53 *B, size_t s);

#undef luaL_addlstring
#define luaL_addlstring COMPAT53_CONCAT(COMPAT53_PREFIX, _addlstring_53)
COMPAT53_API void luaL_addlstring(luaL_Buffer_53 *B, const char *s, size_t l);

#undef luaL_addvalue
#define luaL_addvalue COMPAT53_CONCAT(COMPAT53_PREFIX, _addvalue_53)
COMPAT53_API void luaL_addvalue(luaL_Buffer_53 *B);

#undef luaL_pushresult
#define luaL_pushresult COMPAT53_CONCAT(COMPAT53_PREFIX, _pushresult_53)
COMPAT53_API void luaL_pushresult(luaL_Buffer_53 *B);

#undef luaL_buffinitsize
#define luaL_buffinitsize(L, B, s) \
  (luaL_buffinit((L), (B)), luaL_prepbuffsize((B), (s)))

#undef luaL_prepbuffer
#define luaL_prepbuffer(B) \
  luaL_prepbuffsize((B), LUAL_BUFFERSIZE)

#undef luaL_addchar
#define luaL_addchar(B, c) \
  ((void)((B)->nelems < (B)->capacity || luaL_prepbuffsize((B), 1)), \
   ((B)->ptr[(B)->nelems++] = (c)))

#undef luaL_addsize
#define luaL_addsize(B, s) \
  ((B)->nelems += (s))

#undef luaL_addstring
#define luaL_addstring(B, s) \
  luaL_addlstring((B), (s), strlen((s)))

#undef luaL_pushresultsize
#define luaL_pushresultsize(B, s) \
  (luaL_addsize((B), (s)), luaL_pushresult((B)))

#if defined(LUA_COMPAT_APIINTCASTS)
#define lua_pushunsigned(L, n) \
  lua_pushinteger((L), (lua_Integer)(n))
#define lua_tounsignedx(L, i, is) \
  ((lua_Unsigned)lua_tointegerx((L), (i), (is)))
#define lua_tounsigned(L, i) \
  lua_tounsignedx((L), (i), NULL)
#define luaL_checkunsigned(L, a) \
  ((lua_Unsigned)luaL_checkinteger((L), (a)))
#define luaL_optunsigned(L, a, d) \
  ((lua_Unsigned)luaL_optinteger((L), (a), (lua_Integer)(d)))
#endif

#endif /* Lua 5.1 only */



/* declarations for Lua 5.1 and 5.2 */
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM <= 502

typedef int lua_KContext;

typedef int(*lua_KFunction)(lua_State *L, int status, lua_KContext ctx);

#undef lua_dump
#define lua_dump(L, w, d, s) \
  ((void)(s), GameDbg_lua_dump((L), (w), (d)))

#undef lua_getfield
#define lua_getfield(L, i, k) \
  (GameDbg_lua_getfield((L), (i), (k)), lua_type((L), -1))

#undef lua_gettable
#define lua_gettable(L, i) \
  (GameDbg_lua_gettable((L), (i)), lua_type((L), -1))

#define lua_geti COMPAT53_CONCAT(COMPAT53_PREFIX, _geti)
COMPAT53_API int lua_geti(lua_State *L, int index, lua_Integer i);

#define lua_isinteger COMPAT53_CONCAT(COMPAT53_PREFIX, _isinteger)
COMPAT53_API int lua_isinteger(lua_State *L, int index);

#define lua_numbertointeger(n, p) \
  ((*(p) = (lua_Integer)(n)), 1)

#undef lua_rawget
#define lua_rawget(L, i) \
  (GameDbg_lua_rawget((L), (i)), lua_type((L), -1))

#undef lua_rawgeti
#define lua_rawgeti(L, i, n) \
  (GameDbg_lua_rawgeti((L), (i), (n)), lua_type((L), -1))

#define lua_rotate COMPAT53_CONCAT(COMPAT53_PREFIX, _rotate)
COMPAT53_API void lua_rotate(lua_State *L, int idx, int n);

#define lua_seti COMPAT53_CONCAT(COMPAT53_PREFIX, _seti)
COMPAT53_API void lua_seti(lua_State *L, int index, lua_Integer i);

#define lua_stringtonumber COMPAT53_CONCAT(COMPAT53_PREFIX, _stringtonumber)
COMPAT53_API size_t lua_stringtonumber(lua_State *L, const char *s);

#define luaL_tolstring COMPAT53_CONCAT(COMPAT53_PREFIX, L_tolstring)
COMPAT53_API const char *luaL_tolstring(lua_State *L, int idx, size_t *len);

#undef luaL_getmetafield
#define luaL_getmetafield(L, o, e) \
  (GameDbg_luaL_getmetafield((L), (o), (e)) ? lua_type((L), -1) : LUA_TNIL)

#undef luaL_newmetatable
#define luaL_newmetatable(L, tn) \
  (GameDbg_luaL_newmetatable((L), (tn)) ? (lua_pushstring((L), (tn)), lua_setfield((L), -2, "__name"), 1) : 0)

#define luaL_requiref COMPAT53_CONCAT(COMPAT53_PREFIX, L_requiref_53)
COMPAT53_API void luaL_requiref(lua_State *L, const char *modname,
	lua_CFunction openf, int glb);

#endif /* Lua 5.1 and Lua 5.2 */


/* definitions for Lua 5.1 only */
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM == 501

#ifndef COMPAT53_FOPEN_NO_LOCK
#if defined(_MSC_VER)
#define COMPAT53_FOPEN_NO_LOCK 1
#else /* otherwise */
#define COMPAT53_FOPEN_NO_LOCK 0
#endif /* VC++ only so far */
#endif /* No-lock fopen_s usage if possible */

#if defined(_MSC_VER) && COMPAT53_FOPEN_NO_LOCK
#include <share.h>
#endif /* VC++ _fsopen for share-allowed file read */

#ifndef COMPAT53_HAVE_STRERROR_R
#if defined(__GLIBC__) || defined(_POSIX_VERSION) || defined(__APPLE__) || (!defined(__MINGW32__) && defined(__GNUC__) && (__GNUC__ < 6))
#define COMPAT53_HAVE_STRERROR_R 1
#else /* none of the defines matched: define to 0 */
#define COMPAT53_HAVE_STRERROR_R 0
#endif /* have strerror_r of some form */
#endif /* strerror_r */

#ifndef COMPAT53_HAVE_STRERROR_S
#if defined(_MSC_VER) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || (defined(__STDC_LIB_EXT1__) && __STDC_LIB_EXT1__)
#define COMPAT53_HAVE_STRERROR_S 1
#else /* not VC++ or C11 */
#define COMPAT53_HAVE_STRERROR_S 0
#endif /* strerror_s from VC++ or C11 */
#endif /* strerror_s */

#ifndef COMPAT53_LUA_FILE_BUFFER_SIZE
#define COMPAT53_LUA_FILE_BUFFER_SIZE 4096
#endif /* Lua File Buffer Size */


static char* compat53_strerror(int en, char* buff, size_t sz) {
#if COMPAT53_HAVE_STRERROR_R
	/* use strerror_r here, because it's available on these specific platforms */
	if (sz > 0) {
		buff[0] = '\0';
		/* we don't care whether the GNU version or the XSI version is used: */
		if (strerror_r(en, buff, sz)) {
			/* Yes, we really DO want to ignore the return value!
			 * GCC makes that extra hard, not even a (void) cast will do. */
		}
		if (buff[0] == '\0') {
			/* Buffer is unchanged, so we probably have called GNU strerror_r which
			 * returned a static constant string. Chances are that strerror will
			 * return the same static constant string and therefore be thread-safe. */
			return strerror(en);
		}
	}
	return buff; /* sz is 0 *or* strerror_r wrote into the buffer */
#elif COMPAT53_HAVE_STRERROR_S
	/* for MSVC and other C11 implementations, use strerror_s since it's
	 * provided by default by the libraries */
	strerror_s(buff, sz, en);
	return buff;
#else
	/* fallback, but strerror is not guaranteed to be threadsafe due to modifying
	 * errno itself and some impls not locking a static buffer for it ... but most
	 * known systems have threadsafe errno: this might only change if the locale
	 * is changed out from under someone while this function is being called */
	(void)buff;
	(void)sz;
	return strerror(en);
#endif
}


static void compat53_call_lua(lua_State* L, char const code[], size_t len, int nargs, int nret) {
	lua_rawgetp(L, LUA_REGISTRYINDEX, (void*)code);
	if (lua_type(L, -1) != LUA_TFUNCTION) {
		lua_pop(L, 1);
		if (luaL_loadbuffer(L, code, len, "=none"))
			lua_error(L);
		lua_pushvalue(L, -1);
		lua_rawsetp(L, LUA_REGISTRYINDEX, (void*)code);
	}
	lua_insert(L, -nargs - 1);
	lua_call(L, nargs, nret);
}


COMPAT53_API void lua_arith(lua_State* L, int op) {
	static const char compat53_arith_code[]
	     = "local op,a,b=...\n"
	       "if op==0 then return a+b\n"
	       "elseif op==1 then return a-b\n"
	       "elseif op==2 then return a*b\n"
	       "elseif op==3 then return a/b\n"
	       "elseif op==4 then return a%b\n"
	       "elseif op==5 then return a^b\n"
	       "elseif op==6 then return -a\n"
	       "end\n";

	if (op < LUA_OPADD || op > LUA_OPUNM)
		luaL_error(L, "invalid 'op' argument for lua_arith");
	luaL_checkstack(L, 5, "not enough stack slots");
	if (op == LUA_OPUNM)
		lua_pushvalue(L, -1);
	lua_pushnumber(L, op);
	lua_insert(L, -3);
	compat53_call_lua(L, compat53_arith_code, sizeof(compat53_arith_code) - 1, 3, 1);
}


COMPAT53_API int lua_compare(lua_State* L, int idx1, int idx2, int op) {
	static const char compat53_compare_code[]
	     = "local a,b=...\n"
	       "return a<=b\n";

	int result = 0;
	switch (op) {
	case LUA_OPEQ:
		return lua_equal(L, idx1, idx2);
	case LUA_OPLT:
		return lua_lessthan(L, idx1, idx2);
	case LUA_OPLE:
		luaL_checkstack(L, 5, "not enough stack slots");
		idx1 = lua_absindex(L, idx1);
		idx2 = lua_absindex(L, idx2);
		lua_pushvalue(L, idx1);
		lua_pushvalue(L, idx2);
		compat53_call_lua(L, compat53_compare_code, sizeof(compat53_compare_code) - 1, 2, 1);
		result = lua_toboolean(L, -1);
		lua_pop(L, 1);
		return result;
	default:
		luaL_error(L, "invalid 'op' argument for lua_compare");
	}
	return 0;
}



COMPAT53_API void lua_len(lua_State* L, int i) {
	switch (lua_type(L, i)) {
	case LUA_TSTRING:
		lua_pushnumber(L, (lua_Number)lua_objlen(L, i));
		break;
	case LUA_TTABLE:
		if (!luaL_callmeta(L, i, "__len"))
			lua_pushnumber(L, (lua_Number)lua_objlen(L, i));
		break;
	case LUA_TUSERDATA:
		if (luaL_callmeta(L, i, "__len"))
			break;
		/* FALLTHROUGH */
	default:
		luaL_error(L, "attempt to get length of a %s value", lua_typename(L, lua_type(L, i)));
	}
}


COMPAT53_API int lua_rawgetp(lua_State* L, int i, const void* p) {
	int abs_i = lua_absindex(L, i);
	lua_pushlightuserdata(L, (void*)p);
	lua_rawget(L, abs_i);
	return lua_type(L, -1);
}

COMPAT53_API void lua_rawsetp(lua_State* L, int i, const void* p) {
	int abs_i = lua_absindex(L, i);
	luaL_checkstack(L, 1, "not enough stack slots");
	lua_pushlightuserdata(L, (void*)p);
	lua_insert(L, -2);
	lua_rawset(L, abs_i);
}

COMPAT53_API void luaL_checkversion(lua_State* L) {
	(void)L;
}


COMPAT53_API int luaL_getsubtable(lua_State* L, int i, const char* name) {
	int abs_i = lua_absindex(L, i);
	luaL_checkstack(L, 3, "not enough stack slots");
	lua_pushstring(L, name);
	lua_gettable(L, abs_i);
	if (lua_istable(L, -1))
		return 1;
	lua_pop(L, 1);
	lua_newtable(L);
	lua_pushstring(L, name);
	lua_pushvalue(L, -2);
	lua_settable(L, abs_i);
	return 0;
}


COMPAT53_API lua_Integer luaL_len(lua_State* L, int i) {
	lua_Integer res = 0;
	int isnum = 0;
	luaL_checkstack(L, 1, "not enough stack slots");
	lua_len(L, i);
	res = lua_tointegerx(L, -1, &isnum);
	lua_pop(L, 1);
	if (!isnum)
		luaL_error(L, "object length is not an integer");
	return res;
}


COMPAT53_API void luaL_setfuncs(lua_State* L, const luaL_Reg* l, int nup) {
	luaL_checkstack(L, nup + 1, "too many upvalues");
	for (; l->name != NULL; l++) { /* fill the table with given functions */
		int i;
		lua_pushstring(L, l->name);
		for (i = 0; i < nup; i++) /* copy upvalues to the top */
			lua_pushvalue(L, -(nup + 1));
		lua_pushcclosure(L, l->func, nup); /* closure with those upvalues */
		lua_settable(L, -(nup + 3));       /* table must be below the upvalues, the name and the closure */
	}
	lua_pop(L, nup); /* remove upvalues */
}


static int compat53_countlevels(lua_State* L) {
	lua_Debug ar;
	int li = 1, le = 1;
	/* find an upper bound */
	while (lua_getstack(L, le, &ar)) {
		li = le;
		le *= 2;
	}
	/* do a binary search */
	while (li < le) {
		int m = (li + le) / 2;
		if (lua_getstack(L, m, &ar))
			li = m + 1;
		else
			le = m;
	}
	return le - 1;
}

static int compat53_findfield(lua_State* L, int objidx, int level) {
	if (level == 0 || !lua_istable(L, -1))
		return 0;                               /* not found */
	lua_pushnil(L);                              /* start 'next' loop */
	while (lua_next(L, -2)) {                    /* for each pair in table */
		if (lua_type(L, -2) == LUA_TSTRING) {   /* ignore non-string keys */
			if (lua_rawequal(L, objidx, -1)) { /* found object? */
				lua_pop(L, 1);                /* remove value (but keep name) */
				return 1;
			}
			else if (compat53_findfield(L, objidx, level - 1)) { /* try recursively */
				lua_remove(L, -2);                              /* remove table (but keep name) */
				lua_pushliteral(L, ".");
				lua_insert(L, -2); /* place '.' between the two names */
				lua_concat(L, 3);
				return 1;
			}
		}
		lua_pop(L, 1); /* remove value */
	}
	return 0; /* not found */
}

static int compat53_pushglobalfuncname(lua_State* L, lua_Debug* ar) {
	int top = lua_gettop(L);
	lua_getinfo(L, "f", ar); /* push function */
	lua_pushvalue(L, LUA_GLOBALSINDEX);
	if (compat53_findfield(L, top + 1, 2)) {
		lua_copy(L, -1, top + 1); /* move name to proper place */
		lua_pop(L, 2);            /* remove pushed values */
		return 1;
	}
	else {
		lua_settop(L, top); /* remove function and global table */
		return 0;
	}
}

static void compat53_pushfuncname(lua_State* L, lua_Debug* ar) {
	if (*ar->namewhat != '\0') /* is there a name? */
		lua_pushfstring(L, "function " LUA_QS, ar->name);
	else if (*ar->what == 'm') /* main? */
		lua_pushliteral(L, "main chunk");
	else if (*ar->what == 'C') {
		if (compat53_pushglobalfuncname(L, ar)) {
			lua_pushfstring(L, "function " LUA_QS, lua_tostring(L, -1));
			lua_remove(L, -2); /* remove name */
		}
		else
			lua_pushliteral(L, "?");
	}
	else
		lua_pushfstring(L, "function <%s:%d>", ar->short_src, ar->linedefined);
}

#define COMPAT53_LEVELS1 12 /* size of the first part of the stack */
#define COMPAT53_LEVELS2 10 /* size of the second part of the stack */

COMPAT53_API void luaL_traceback(lua_State* L, lua_State* L1, const char* msg, int level) {
	lua_Debug ar;
	int top = lua_gettop(L);
	int numlevels = compat53_countlevels(L1);
	int mark = (numlevels > COMPAT53_LEVELS1 + COMPAT53_LEVELS2) ? COMPAT53_LEVELS1 : 0;
	if (msg)
		lua_pushfstring(L, "%s\n", msg);
	lua_pushliteral(L, "stack traceback:");
	while (lua_getstack(L1, level++, &ar)) {
		if (level == mark) {                       /* too many levels? */
			lua_pushliteral(L, "\n\t...");        /* add a '...' */
			level = numlevels - COMPAT53_LEVELS2; /* and skip to last ones */
		}
		else {
			lua_getinfo(L1, "Slnt", &ar);
			lua_pushfstring(L, "\n\t%s:", ar.short_src);
			if (ar.currentline > 0)
				lua_pushfstring(L, "%d:", ar.currentline);
			lua_pushliteral(L, " in ");
			compat53_pushfuncname(L, &ar);
			lua_concat(L, lua_gettop(L) - top);
		}
	}
	lua_concat(L, lua_gettop(L) - top);
}


COMPAT53_API int luaL_fileresult(lua_State* L, int stat, const char* fname) {
	const char* serr = NULL;
	int en = errno; /* calls to Lua API may change this value */
	char buf[512] = { 0 };
	if (stat) {
		lua_pushboolean(L, 1);
		return 1;
	}
	else {
		lua_pushnil(L);
		serr = compat53_strerror(en, buf, sizeof(buf));
		if (fname)
			lua_pushfstring(L, "%s: %s", fname, serr);
		else
			lua_pushstring(L, serr);
		lua_pushnumber(L, (lua_Number)en);
		return 3;
	}
}


static int compat53_checkmode(lua_State* L, const char* mode, const char* modename, int err) {
	if (mode && strchr(mode, modename[0]) == NULL) {
		lua_pushfstring(L, "attempt to load a %s chunk (mode is '%s')", modename, mode);
		return err;
	}
	return LUA_OK;
}


typedef struct {
	lua_Reader reader;
	void* ud;
	int has_peeked_data;
	const char* peeked_data;
	size_t peeked_data_size;
} compat53_reader_data;


static const char* compat53_reader(lua_State* L, void* ud, size_t* size) {
	compat53_reader_data* data = (compat53_reader_data*)ud;
	if (data->has_peeked_data) {
		data->has_peeked_data = 0;
		*size = data->peeked_data_size;
		return data->peeked_data;
	}
	else
		return data->reader(L, data->ud, size);
}


COMPAT53_API int lua_load(lua_State* L, lua_Reader reader, void* data, const char* source, const char* mode) {
	int status = LUA_OK;
	compat53_reader_data compat53_data = { reader, data, 1, 0, 0 };
	compat53_data.peeked_data = reader(L, data, &(compat53_data.peeked_data_size));
	if (compat53_data.peeked_data && compat53_data.peeked_data_size && compat53_data.peeked_data[0] == LUA_SIGNATURE[0]) /* binary file? */
		status = compat53_checkmode(L, mode, "binary", LUA_ERRSYNTAX);
	else
		status = compat53_checkmode(L, mode, "text", LUA_ERRSYNTAX);
	if (status != LUA_OK)
		return status;
		/* we need to call the original 5.1 version of lua_load! */
	return GameDbg_lua_load(L, compat53_reader, &compat53_data, source);
}


typedef struct {
	int n;                                    /* number of pre-read characters */
	FILE* f;                                  /* file being read */
	char buff[COMPAT53_LUA_FILE_BUFFER_SIZE]; /* area for reading file */
} compat53_LoadF;


static const char* compat53_getF(lua_State* L, void* ud, size_t* size) {
	compat53_LoadF* lf = (compat53_LoadF*)ud;
	(void)L;            /* not used */
	if (lf->n > 0) {    /* are there pre-read characters to be read? */
		*size = lf->n; /* return them (chars already in buffer) */
		lf->n = 0;     /* no more pre-read characters */
	}
	else { /* read a block from file */
		  /* 'fread' can return > 0 *and* set the EOF flag. If next call to
		  'compat53_getF' called 'fread', it might still wait for user input.
		  The next check avoids this problem. */
		if (feof(lf->f))
			return NULL;
		*size = fread(lf->buff, 1, sizeof(lf->buff), lf->f); /* read block */
	}
	return lf->buff;
}


static int compat53_errfile(lua_State* L, const char* what, int fnameindex) {
	char buf[512] = { 0 };
	const char* serr = compat53_strerror(errno, buf, sizeof(buf));
	const char* filename = lua_tostring(L, fnameindex) + 1;
	lua_pushfstring(L, "cannot %s %s: %s", what, filename, serr);
	lua_remove(L, fnameindex);
	return LUA_ERRFILE;
}


static int compat53_skipBOM(compat53_LoadF* lf) {
	const char* p = "\xEF\xBB\xBF"; /* UTF-8 BOM mark */
	int c;
	lf->n = 0;
	do {
		c = getc(lf->f);
		if (c == EOF || c != *(const unsigned char*)p++)
			return c;
		lf->buff[lf->n++] = (char)c; /* to be read by the parser */
	} while (*p != '\0');
	lf->n = 0;          /* prefix matched; discard it */
	return getc(lf->f); /* return next character */
}


/*
** reads the first character of file 'f' and skips an optional BOM mark
** in its beginning plus its first line if it starts with '#'. Returns
** true if it skipped the first line.  In any case, '*cp' has the
** first "valid" character of the file (after the optional BOM and
** a first-line comment).
*/
static int compat53_skipcomment(compat53_LoadF* lf, int* cp) {
	int c = *cp = compat53_skipBOM(lf);
	if (c == '#') { /* first line is a comment (Unix exec. file)? */
		do {       /* skip first line */
			c = getc(lf->f);
		} while (c != EOF && c != '\n');
		*cp = getc(lf->f); /* skip end-of-line, if present */
		return 1;          /* there was a comment */
	}
	else
		return 0; /* no comment */
}



#if !defined(l_inspectstat) \
     && (defined(unix) || defined(__unix) || defined(__unix__) || defined(__TOS_AIX__) || defined(_SYSTYPE_BSD) || (defined(__APPLE__) && defined(__MACH__)))
/* some form of unix; check feature macros in unistd.h for details */
#include <unistd.h>
/* check posix version; the relevant include files and macros probably
 * were available before 2001, but I'm not sure */
#if defined(_POSIX_VERSION) && _POSIX_VERSION >= 200112L
#include <sys/wait.h>
#define l_inspectstat(stat, what)   \
	if (WIFEXITED(stat)) {         \
		stat = WEXITSTATUS(stat); \
	}                              \
	else if (WIFSIGNALED(stat)) {  \
		stat = WTERMSIG(stat);    \
		what = "signal";          \
	}
#endif
#endif

/* provide default (no-op) version */
#if !defined(l_inspectstat)
#define l_inspectstat(stat, what) ((void)0)
#endif


COMPAT53_API int luaL_execresult(lua_State* L, int stat) {
	const char* what = "exit";
	if (stat == -1)
		return luaL_fileresult(L, 0, NULL);
	else {
		l_inspectstat(stat, what);
		if (*what == 'e' && stat == 0)
			lua_pushboolean(L, 1);
		else
			lua_pushnil(L);
		lua_pushstring(L, what);
		lua_pushinteger(L, stat);
		return 3;
	}
}


COMPAT53_API void luaL_buffinit(lua_State* L, luaL_Buffer_53* B) {
	/* make it crash if used via pointer to a 5.1-style luaL_Buffer */
	B->b.p = NULL;
	B->b.L = NULL;
	B->b.lvl = 0;
	/* reuse the buffer from the 5.1-style luaL_Buffer though! */
	B->ptr = B->b.buffer;
	B->capacity = LUAL_BUFFERSIZE;
	B->nelems = 0;
	B->L2 = L;
}


COMPAT53_API char* luaL_prepbuffsize(luaL_Buffer_53* B, size_t s) {
	if (B->capacity - B->nelems < s) { /* needs to grow */
		char* newptr = NULL;
		size_t newcap = B->capacity * 2;
		if (newcap - B->nelems < s)
			newcap = B->nelems + s;
		if (newcap < B->capacity) /* overflow */
			luaL_error(B->L2, "buffer too large");
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM >= 504
		newptr = (char*)lua_newuserdatauv(B->L2, newcap, 0);
#else
		newptr = (char*)lua_newuserdata(B->L2, newcap);
#endif
		memcpy(newptr, B->ptr, B->nelems);
		if (B->ptr != B->b.buffer)
			lua_replace(B->L2, -2); /* remove old buffer */
		B->ptr = newptr;
		B->capacity = newcap;
	}
	return B->ptr + B->nelems;
}


COMPAT53_API void luaL_addlstring(luaL_Buffer_53* B, const char* s, size_t l) {
	memcpy(luaL_prepbuffsize(B, l), s, l);
	luaL_addsize(B, l);
}


COMPAT53_API void luaL_addvalue(luaL_Buffer_53* B) {
	size_t len = 0;
	const char* s = lua_tolstring(B->L2, -1, &len);
	if (!s)
		luaL_error(B->L2, "cannot convert value to string");
	if (B->ptr != B->b.buffer)
		lua_insert(B->L2, -2); /* userdata buffer must be at stack top */
	luaL_addlstring(B, s, len);
	lua_remove(B->L2, B->ptr != B->b.buffer ? -2 : -1);
}


void luaL_pushresult(luaL_Buffer_53* B) {
	lua_pushlstring(B->L2, B->ptr, B->nelems);
	if (B->ptr != B->b.buffer)
		lua_replace(B->L2, -2); /* remove userdata buffer */
}


#endif /* Lua 5.1 */



/* definitions for Lua 5.1 and Lua 5.2 */
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM <= 502


COMPAT53_API int lua_geti(lua_State* L, int index, lua_Integer i) {
	index = lua_absindex(L, index);
	lua_pushinteger(L, i);
	lua_gettable(L, index);
	return lua_type(L, -1);
}


COMPAT53_API int lua_isinteger(lua_State* L, int index) {
	if (lua_type(L, index) == LUA_TNUMBER) {
		lua_Number n = lua_tonumber(L, index);
		lua_Integer i = lua_tointeger(L, index);
		if (i == n)
			return 1;
	}
	return 0;
}


static void compat53_reverse(lua_State* L, int a, int b) {
	for (; a < b; ++a, --b) {
		lua_pushvalue(L, a);
		lua_pushvalue(L, b);
		lua_replace(L, a);
		lua_replace(L, b);
	}
}


COMPAT53_API void lua_rotate(lua_State* L, int idx, int n) {
	int n_elems = 0;
	idx = lua_absindex(L, idx);
	n_elems = lua_gettop(L) - idx + 1;
	if (n < 0)
		n += n_elems;
	if (n > 0 && n < n_elems) {
		luaL_checkstack(L, 2, "not enough stack slots available");
		n = n_elems - n;
		compat53_reverse(L, idx, idx + n - 1);
		compat53_reverse(L, idx + n, idx + n_elems - 1);
		compat53_reverse(L, idx, idx + n_elems - 1);
	}
}


COMPAT53_API void lua_seti(lua_State* L, int index, lua_Integer i) {
	luaL_checkstack(L, 1, "not enough stack slots available");
	index = lua_absindex(L, index);
	lua_pushinteger(L, i);
	lua_insert(L, -2);
	lua_settable(L, index);
}


#if !defined(lua_str2number)
#define lua_str2number(s, p) strtod((s), (p))
#endif

COMPAT53_API size_t lua_stringtonumber(lua_State* L, const char* s) {
	char* endptr;
	lua_Number n = lua_str2number(s, &endptr);
	if (endptr != s) {
		while (*endptr != '\0' && isspace((unsigned char)*endptr))
			++endptr;
		if (*endptr == '\0') {
			lua_pushnumber(L, n);
			return endptr - s + 1;
		}
	}
	return 0;
}


COMPAT53_API const char* luaL_tolstring(lua_State* L, int idx, size_t* len) {
	if (!luaL_callmeta(L, idx, "__tostring")) {
		int t = lua_type(L, idx), tt = 0;
		char const* name = NULL;
		switch (t) {
		case LUA_TNIL:
			lua_pushliteral(L, "nil");
			break;
		case LUA_TSTRING:
		case LUA_TNUMBER:
			lua_pushvalue(L, idx);
			break;
		case LUA_TBOOLEAN:
			if (lua_toboolean(L, idx))
				lua_pushliteral(L, "true");
			else
				lua_pushliteral(L, "false");
			break;
		default:
			tt = luaL_getmetafield(L, idx, "__name");
			name = (tt == LUA_TSTRING) ? lua_tostring(L, -1) : lua_typename(L, t);
			lua_pushfstring(L, "%s: %p", name, lua_topointer(L, idx));
			if (tt != LUA_TNIL)
				lua_replace(L, -2);
			break;
		}
	}
	else {
		if (!lua_isstring(L, -1))
			luaL_error(L, "'__tostring' must return a string");
	}
	return lua_tolstring(L, -1, len);
}


COMPAT53_API void luaL_requiref(lua_State* L, const char* modname, lua_CFunction openf, int glb) {
	luaL_checkstack(L, 3, "not enough stack slots available");
	luaL_getsubtable(L, LUA_REGISTRYINDEX, "_LOADED");
	if (lua_getfield(L, -1, modname) == LUA_TNIL) {
		lua_pop(L, 1);
		lua_pushcfunction(L, openf);
		lua_pushstring(L, modname);
		lua_call(L, 1, 1);
		lua_pushvalue(L, -1);
		lua_setfield(L, -3, modname);
	}
	if (glb) {
		lua_pushvalue(L, -1);
		lua_setglobal(L, modname);
	}
	lua_replace(L, -2);
}


#endif /* Lua 5.1 and 5.2 */


#define SOL_NO_COMPAT 1

#include <sol/sol.hpp>


DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_get_workshop_dir();
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_disable_fullgc(int mb);
DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_Fengxun_Decrypt(const char *filename) noexcept;
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_set_vm_type(int type, const char *moduleName);
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_replace_network_tick(char upload_tick, char download_tick, bool isclient);
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_set_target_fps(int fps, int tt);
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_update(const char *mod_directory, int tt);
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_replace_profiler_api();
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_enable_tracy(int en);
DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_get_mod_version();
DONTSTARVEINJECTOR_GAME_API void *DS_LUAJIT_EntityNetWorkExtension_Register(void *networkComponentLuaProxyPtr, int64_t networkid);
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_SetNextRpcInfo(std::optional<PacketPriority> packetPriority, std::optional<PacketReliability> reliability, std::optional<char> orderingChannel);
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_enable_framegc(bool enable);
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_enable_profiler(int en);

// export DONTSTARVEINJECTOR_GAME_API functions to lua module
int luaopen_GameInjector(lua_State* L) {
    sol::state_view lua(L);
    sol::table module = lua.create_table();

    module.set_function("DS_LUAJIT_get_workshop_dir", &DS_LUAJIT_get_workshop_dir);
    module.set_function("DS_LUAJIT_disable_fullgc", &DS_LUAJIT_disable_fullgc);
    module.set_function("DS_LUAJIT_Fengxun_Decrypt", &DS_LUAJIT_Fengxun_Decrypt);
    module.set_function("DS_LUAJIT_set_vm_type", &DS_LUAJIT_set_vm_type);
    module.set_function("DS_LUAJIT_replace_network_tick", &DS_LUAJIT_replace_network_tick);
    module.set_function("DS_LUAJIT_set_target_fps", &DS_LUAJIT_set_target_fps);
    module.set_function("DS_LUAJIT_update", &DS_LUAJIT_update);
    module.set_function("DS_LUAJIT_replace_profiler_api", &DS_LUAJIT_replace_profiler_api);
    module.set_function("DS_LUAJIT_enable_tracy", &DS_LUAJIT_enable_tracy);
    module.set_function("DS_LUAJIT_get_mod_version", &DS_LUAJIT_get_mod_version);
    module.set_function("DS_LUAJIT_EntityNetWorkExtension_Register", &DS_LUAJIT_EntityNetWorkExtension_Register);
    module.set_function("DS_LUAJIT_SetNextRpcInfo", &DS_LUAJIT_SetNextRpcInfo);
    module.set_function("DS_LUAJIT_enable_framegc", &DS_LUAJIT_enable_framegc);
    //module.set_function("enable_profiler", &DS_LUAJIT_enable_profiler);

    lua["GameInjector"] = module;
    return 1;
}