// Test-only PUC Lua 5.1 reference oracle. See puc_dump_reference.hpp.
//
// This TU is the only place that includes the PUC 5.1 headers; the host loads
// LuaJIT dynamically and therefore must not see them.

#include "puc_dump_reference.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}

namespace {

void set_err(char *err, size_t cap, const char *text) {
    if (err == nullptr || cap == 0) {
        return;
    }
    if (text == nullptr) {
        text = "";
    }
    size_t n = std::strlen(text);
    if (n >= cap) {
        n = cap - 1;
    }
    std::memcpy(err, text, n);
    err[n] = '\0';
}

int write_all(lua_State *, const void *p, size_t size, void *ud) {
    auto *out = static_cast<std::vector<char> *>(ud);
    try {
        const auto *first = static_cast<const char *>(p);
        out->insert(out->end(), first, first + size);
    } catch (...) {
        return 1;
    }
    return 0;
}

/* PUC 5.1 string.dump has no strip argument: lua_dump always writes the debug
** info, so this oracle always calls it the same way the engine does. */
int dump_value(lua_State *L, std::vector<char> &out) {
    return lua_dump(L, write_all, &out);
}

} // namespace

extern "C" int ds_ref_dump(const char *source, size_t source_len, const char *chunkname,
                           int result_index, void **out_data, size_t *out_size,
                           char *err, size_t err_cap) {
    if (out_data == nullptr || out_size == nullptr) {
        return 0;
    }
    *out_data = nullptr;
    *out_size = 0;
    if (source == nullptr) {
        set_err(err, err_cap, "no source");
        return 0;
    }
    lua_State *L = luaL_newstate();
    if (L == nullptr) {
        set_err(err, err_cap, "cannot create PUC state");
        return 0;
    }
    if (luaL_loadbuffer(L, source, source_len, chunkname != nullptr ? chunkname : "?") != 0) {
        set_err(err, err_cap, lua_tostring(L, -1));
        lua_close(L);
        return 0;
    }
    if (result_index == 0) {
        /* Dump the loaded chunk itself without running it: the root prototype is a
        ** legitimate dump target and must never be executed to obtain it. */
        std::vector<char> bytes;
        const int status = dump_value(L, bytes);
        lua_close(L);
        if (status != 0) {
            set_err(err, err_cap, "lua_dump failed");
            return 0;
        }
        auto *owned = static_cast<char *>(std::malloc(bytes.size() ? bytes.size() : 1));
        if (owned == nullptr) {
            set_err(err, err_cap, "out of memory");
            return 0;
        }
        if (!bytes.empty()) {
            std::memcpy(owned, bytes.data(), bytes.size());
        }
        *out_data = owned;
        *out_size = bytes.size();
        return 1;
    }
    if (lua_pcall(L, 0, LUA_MULTRET, 0) != 0) {
        set_err(err, err_cap, lua_tostring(L, -1));
        lua_close(L);
        return 0;
    }
    const int results = lua_gettop(L);
    if (result_index < 1 || result_index > results) {
        char msg[128];
        std::snprintf(msg, sizeof(msg), "fixture returned %d value(s), wanted #%d", results,
                      result_index);
        set_err(err, err_cap, msg);
        lua_close(L);
        return 0;
    }
    lua_pushvalue(L, result_index);
    std::vector<char> bytes;
    const int status = dump_value(L, bytes);
    lua_close(L);
    if (status != 0) {
        set_err(err, err_cap, "lua_dump failed");
        return 0;
    }
    auto *owned = static_cast<char *>(std::malloc(bytes.size() ? bytes.size() : 1));
    if (owned == nullptr) {
        set_err(err, err_cap, "out of memory");
        return 0;
    }
    if (!bytes.empty()) {
        std::memcpy(owned, bytes.data(), bytes.size());
    }
    *out_data = owned;
    *out_size = bytes.size();
    return 1;
}

extern "C" void ds_ref_free(void *data) { std::free(data); }

extern "C" int ds_ref_execute(const void *data, size_t size, double arg, double *out,
                              char *err, size_t err_cap) {
    if (data == nullptr) {
        set_err(err, err_cap, "no bytecode");
        return 0;
    }
    lua_State *L = luaL_newstate();
    if (L == nullptr) {
        set_err(err, err_cap, "cannot create PUC state");
        return 0;
    }
    if (luaL_loadbuffer(L, static_cast<const char *>(data), size, "=puc_reference") != 0) {
        set_err(err, err_cap, lua_tostring(L, -1));
        lua_close(L);
        return 0;
    }
    /* A dumped function loads as that very function in Lua 5.1: call it once
    ** with the argument under test, not through a zero-argument prologue. */
    lua_pushnumber(L, arg);
    if (lua_pcall(L, 1, 1, 0) != 0) {
        set_err(err, err_cap, lua_tostring(L, -1));
        lua_close(L);
        return 0;
    }
    if (lua_type(L, -1) != LUA_TNUMBER) {
        set_err(err, err_cap, "reference call did not return a number");
        lua_close(L);
        return 0;
    }
    if (out != nullptr) {
        *out = lua_tonumber(L, -1);
    }
    lua_close(L);
    return 1;
}
