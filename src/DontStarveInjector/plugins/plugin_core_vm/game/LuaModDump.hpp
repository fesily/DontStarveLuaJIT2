#pragma once
// game/LuaModDump.hpp — streamed source dump shared by the active Lua contexts.
#include <lua.hpp>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace ds::core_vm::detail {

// Per-lua_load-call state. The reader forwards the caller's reader and writes every
// piece straight to disk; a parser error / OOM leaves the partial ".partN" file.
struct LuaModDumpCall {
    lua_Reader reader = nullptr;
    void *data = nullptr;
    const char *chunkname = nullptr;
    std::ofstream part;
    std::filesystem::path part_path;
    std::size_t call_bytes = 0;
    bool started = false;
    bool continuation = false;
};

// Reads dump_lua_mods once (env/cmdline) and resets the dump tree once per process.
bool LuaModDumpEnabled();
const std::vector<std::string> &LuaModDumpModNames();
bool LuaModDumpShouldDump(const char *chunkname);

// lua_Reader that writes each piece immediately; keeps the partial file on failure.
const char *LuaModDumpReader(lua_State *L, void *ud, size_t *sz);

} // namespace ds::core_vm::detail
