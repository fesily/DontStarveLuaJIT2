#pragma once
#include "config.hpp"
namespace dontstarveinjector::lua_debugger_helper
{
/* \\berif Launch Mode
 * Initialize lua_debugger.so
 * Lua VM initialization debugger
 * Replace Main.lua with debugger (for loop hook)
 * 
 * \\berif Attach mode
 * Initialize lua_debugger.so
 * Replace Main.lua for init debugger (start debugger)
 */
#ifdef ENABLE_LUA_DEBUGGER
    void initialize_lua_debugger();
#else
#define initialize_lua_debugger() (void)0
#endif
} // namespace dontstarveinjector::util::lua_debugger_helper