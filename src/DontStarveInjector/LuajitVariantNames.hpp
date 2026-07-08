#pragma once
#include "GameLuaType.hpp"

// ---------------------------------------------------------------------------
// Centralized LuaJIT variant library-name mapping.
//
// This descriptor table is the single source of truth for the runtime
// library *base name* associated with each GameLuaType that loads a shared
// library.  Future LuaJIT variants add a row here instead of scattering
// new string literals through GameLua.cpp.
//
// The base names (e.g. "lua51DS") are combined with platform-specific
// SHARED_LIBRARY_PRE / SHARED_LIBRARY_EXT macros at the call site to
// produce the full platform filename (e.g. "liblua51DS.so").
//
// GameLuaType::game and ::unknown do not load a shared library and have
// no entry in the table; GetLuajitVariantBaseName returns nullptr for them.
// ---------------------------------------------------------------------------

struct LuajitVariantNameEntry {
    GameLuaType type;
    const char *baseName;
};

inline constexpr LuajitVariantNameEntry LuajitVariantNameTable[] = {
    {GameLuaType::jit,     "lua51DS"},
    {GameLuaType::jit_gen, "lua51DS_gengc"},
    {GameLuaType::_51,     "lua51Original"},
};

// Returns the library base name for a given type, or nullptr if the type
// does not load a shared library.
inline constexpr const char *GetLuajitVariantBaseName(GameLuaType type) {
    for (const auto &entry : LuajitVariantNameTable) {
        if (entry.type == type)
            return entry.baseName;
    }
    return nullptr;
}
