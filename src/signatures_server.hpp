#ifndef SIGNATURES_server_H
#define SIGNATURES_server_H
#include <unordered_map>
#include <string>
#include <cstdint>
using namespace std::literals;
#ifndef SIGNATURES_DEF
#define SIGNATURES_DEF
struct Signatures {
	intptr_t version;
	std::unordered_map<std::string, intptr_t> funcs;
};
#endif
static Signatures signatures_server = 
{
570654
,
	{
	{"luaL_addlstring"s, 7424},
	{"luaL_addvalue"s, 7664},
	{"luaL_argerror"s, 9168},
	{"luaL_buffinit"s, 7856},
	{"luaL_callmeta"s, 6720},
	{"luaL_checkany"s, 9808},
	{"luaL_checkboolean"s, 10432},
	{"luaL_checkinteger"s, 10352},
	{"luaL_checklstring"s, 9872},
	{"luaL_checknumber"s, 10144},
	{"luaL_checkoption"s, 12256},
	{"luaL_checkstack"s, 6528},
	{"luaL_checktype"s, 9744},
	{"luaL_checkudata"s, 9552},
	{"luaL_error"s, 6304},
	{"luaL_findtable"s, 6848},
	{"luaL_getmetafield"s, 6592},
	{"luaL_gsub"s, 11136},
	{"luaL_loadbuffer"s, 9040},
	{"luaL_loadstring"s, 9088},
	{"luaL_newmetatable"s, 6400},
	{"luaL_openlib"s, 10752},
	{"luaL_openlibs"s, 24352},
	{"luaL_optboolean"s, 10560},
	{"luaL_optinteger"s, 10640},
	{"luaL_optlstring"s, 10016},
	{"luaL_optnumber"s, 10240},
	{"luaL_prepbuffer"s, 7328},
	{"luaL_pushresult"s, 7584},
	{"luaL_ref"s, 7888},
	{"luaL_register"s, 12448},
	{"luaL_unref"s, 8096},
	{"luaL_where"s, 6160},
	{"lua_atpanic"s, 480},
	{"lua_call"s, 4560},
	{"lua_checkstack"s, 208},
	{"lua_close"s, 25888},
	{"lua_concat"s, 5504},
	{"lua_createtable"s, 3440},
	{"lua_dump"s, 4880},
	{"lua_equal"s, 1456},
	{"lua_error"s, 5424},
	{"lua_gc"s, 4976},
	{"lua_getfenv"s, 3648},
	{"lua_getfield"s, 3200},
	{"lua_getinfo"s, 16800},
	{"lua_getmetatable"s, 3552},
	{"lua_getstack"s, 12608},
	{"lua_gettable"s, 3152},
	{"lua_gettop"s, 592},
	{"lua_getupvalue"s, 5792},
	{"lua_insert"s, 784},
	{"lua_iscfunction"s, 1216},
	{"lua_isnumber"s, 1264},
	{"lua_isstring"s, 1312},
	{"lua_lessthan"s, 1552},
	{"lua_load"s, 4800},
	{"lua_newstate"s, 25408},
	{"lua_newthread"s, 512},
	{"lua_newuserdata"s, 5664},
	{"lua_next"s, 5440},
	{"lua_objlen"s, 1968},
	{"lua_pcall"s, 4656},
	{"lua_pushboolean"s, 3040},
	{"lua_pushcclosure"s, 2816},
	{"lua_pushfstring"s, 2736},
	{"lua_pushinteger"s, 2416},
	{"lua_pushlightuserdata"s, 3072},
	{"lua_pushlstring"s, 2448},
	{"lua_pushnil"s, 2352},
	{"lua_pushnumber"s, 2384},
	{"lua_pushstring"s, 2560},
	{"lua_pushthread"s, 3104},
	{"lua_pushvalue"s, 1088},
	{"lua_pushvfstring"s, 2640},
	{"lua_rawequal"s, 1376},
	{"lua_rawget"s, 3312},
	{"lua_rawgeti"s, 3376},
	{"lua_rawset"s, 3952},
	{"lua_rawseti"s, 4080},
	{"lua_remove"s, 704},
	{"lua_replace"s, 880},
	{"lua_resume"s, 30016},
	{"lua_setfenv"s, 4400},
	{"lua_setfield"s, 3824},
	{"lua_setmetatable"s, 4208},
	{"lua_settable"s, 3776},
	{"lua_settop"s, 608},
	{"lua_setupvalue"s, 5936},
	{"lua_status"s, 4960},
	{"lua_toboolean"s, 1744},
	{"lua_tocfunction"s, 2096},
	{"lua_tointeger"s, 1696},
	{"lua_tolstring"s, 1792},
	{"lua_tonumber"s, 1632},
	{"lua_topointer"s, 2240},
	{"lua_tothread"s, 2208},
	{"lua_touserdata"s, 2144},
	{"lua_type"s, 1136},
	{"lua_typename"s, 1184},
	{"lua_xmove"s, 368},
	{"lua_yield"s, 28272},
}};
#endif
