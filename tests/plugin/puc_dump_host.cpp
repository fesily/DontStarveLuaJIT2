// tests/plugin/puc_dump_host.cpp
//
// Dual-VM host for the PUC 5.1 string.dump proof.
//
// It links the production dump service (ds_puc51_dump) but loads the VM under
// test at runtime, by absolute path, with RTLD_NOW|RTLD_LOCAL (LoadLibraryW on
// Windows) and resolves every lua_* entry point from that handle. Nothing is
// linked against LuaJIT and no lua_* symbol is taken from the process:
//   * the host's own PUC 5.1 (src/lua51original, hidden visibility) must never
//     answer a call meant for the loaded VM;
//   * the same host binary drives the default VM, the arena-GC VM, the no-JIT
//     VM and the macro-off (native-only) VM, so the build matrix is one binary.
//
// Modes (all require --vm):
//   --vm <library> --self-test      prototype mapping, byte-exactness, GC,
//                                   error branches, copy-stage OOM
//   --vm <library> --script <file> [-- args...]
//                                   run a Lua file with a real PUC bridge and
//                                   `arg` set (used by the Lua spec)
//   --vm <library> --expect-native  the library must have no bridge slot and
//                                   keep native LuaJIT string.dump/lua_dump
//
// Exit codes: 0 PASS, 1 FAIL.

#include "puc_dump_reference.hpp"

#include "core/LuaPucDumpService.hpp"
#include "lua_ds_pucdump.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

// ---------------------------------------------------------------------------
// Lua 5.1 ABI, resolved per loaded VM
// ---------------------------------------------------------------------------

constexpr int kRegistryIndex = -10000;
constexpr int kRegistry2Index = -11000;  /* LUA_REGISTRYINDEX2 (luajit/src/lua.h) */
constexpr int kGlobalsIndex = -10002;
constexpr int kGcCollect = 2;
constexpr int kGcCount = 3;
constexpr int kGcCountB = 4;
constexpr int kMultiRet = -1;
constexpr int kTNil = 0;
constexpr int kTBoolean = 1;
constexpr int kTNumber = 3;
constexpr int kTString = 4;
constexpr int kTTable = 5;
constexpr int kTFunction = 6;
constexpr int kTLightUserdata = 2;
constexpr int kTThread = 8;

using lua_State = void;
using lua_Number = double;
using lua_CFunction = int (*)(lua_State *);
using lua_Writer = int (*)(lua_State *, const void *, size_t, void *);

struct Api {
    lua_State *(*newstate)(void *(*)(void *, void *, size_t, size_t), void *);
    lua_State *(*L_newstate)();
    void (*close)(lua_State *);
    void (*L_openlibs)(lua_State *);
    int (*L_loadbuffer)(lua_State *, const char *, size_t, const char *);
    int (*pcall)(lua_State *, int, int, int);
    void (*settop)(lua_State *, int);
    int (*gettop)(lua_State *);
    void (*pushvalue)(lua_State *, int);
    void (*remove)(lua_State *, int);
    void (*insert)(lua_State *, int);
    void (*replace)(lua_State *, int);
    void (*pushnil)(lua_State *);
    void (*pushnumber)(lua_State *, lua_Number);
    void (*pushstring)(lua_State *, const char *);
    void (*pushcclosure)(lua_State *, lua_CFunction, int);
    const char *(*tolstring)(lua_State *, int, size_t *);
    lua_Number (*tonumber)(lua_State *, int);
    int (*type)(lua_State *, int);
    void (*getfield)(lua_State *, int, const char *);
    void (*setfield)(lua_State *, int, const char *);
    void (*rawget)(lua_State *, int);
    void (*rawset)(lua_State *, int);
    int (*next)(lua_State *, int);
    void (*pushlightuserdata)(lua_State *, void *);
    void *(*touserdata)(lua_State *, int);
    void (*rawseti)(lua_State *, int, int);
    void (*createtable)(lua_State *, int, int);
    int (*gc)(lua_State *, int, int);
    int (*dump)(lua_State *, lua_Writer, void *);
};

Api A{};

struct Vm {
    void *handle = nullptr;
    void **bridge_slot = nullptr;
    /* lua_ds_allow_lj_bytecode: per-state opt-out from LJ_DS_REJECT_BINARY_CHUNKS.
    ** Without it a bridged VM cannot load the bytecode it just dumped. */
    void (*allow_lj_bytecode)(lua_State *, int) = nullptr;
};

void *open_library(const std::string &path) {
#ifdef _WIN32
    const int wide_len = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring wide(static_cast<size_t>(wide_len > 0 ? wide_len : 1), L'\0');
    if (wide_len > 0) {
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wide.data(), wide_len);
    }
    return reinterpret_cast<void *>(LoadLibraryW(wide.c_str()));
#else
    return dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
#endif
}

void *find_symbol(void *handle, const char *name) {
#ifdef _WIN32
    return reinterpret_cast<void *>(GetProcAddress(static_cast<HMODULE>(handle), name));
#else
    return dlsym(handle, name);
#endif
}

std::string library_error() {
#ifdef _WIN32
    return "LoadLibraryW failed, error " + std::to_string(static_cast<unsigned>(GetLastError()));
#else
    const char *e = dlerror();
    return e != nullptr ? e : "dlopen failed";
#endif
}

template <class Fn>
bool resolve(void *handle, const char *name, Fn *out) {
    void *sym = find_symbol(handle, name);
    if (sym == nullptr) {
        std::fprintf(stderr, "[puc-dump-host] missing VM symbol: %s\n", name);
        return false;
    }
    *out = reinterpret_cast<Fn>(sym);
    return true;
}

bool resolve_api(void *handle) {
    bool ok = true;
    ok &= resolve(handle, "lua_newstate", &A.newstate);
    ok &= resolve(handle, "luaL_newstate", &A.L_newstate);
    ok &= resolve(handle, "lua_close", &A.close);
    ok &= resolve(handle, "luaL_openlibs", &A.L_openlibs);
    ok &= resolve(handle, "luaL_loadbuffer", &A.L_loadbuffer);
    ok &= resolve(handle, "lua_pcall", &A.pcall);
    ok &= resolve(handle, "lua_settop", &A.settop);
    ok &= resolve(handle, "lua_gettop", &A.gettop);
    ok &= resolve(handle, "lua_pushvalue", &A.pushvalue);
    ok &= resolve(handle, "lua_remove", &A.remove);
    ok &= resolve(handle, "lua_insert", &A.insert);
    ok &= resolve(handle, "lua_replace", &A.replace);
    ok &= resolve(handle, "lua_pushnil", &A.pushnil);
    ok &= resolve(handle, "lua_pushnumber", &A.pushnumber);
    ok &= resolve(handle, "lua_pushstring", &A.pushstring);
    ok &= resolve(handle, "lua_pushcclosure", &A.pushcclosure);
    ok &= resolve(handle, "lua_tolstring", &A.tolstring);
    ok &= resolve(handle, "lua_tonumber", &A.tonumber);
    ok &= resolve(handle, "lua_type", &A.type);
    ok &= resolve(handle, "lua_getfield", &A.getfield);
    /* lua_setglobal/getglobal/pushcfunction are macros in 5.1: use the functions
    ** they expand to, since only real exports are resolvable from the handle. */
    ok &= resolve(handle, "lua_setfield", &A.setfield);
    ok &= resolve(handle, "lua_rawget", &A.rawget);
    ok &= resolve(handle, "lua_rawset", &A.rawset);
    ok &= resolve(handle, "lua_next", &A.next);
    ok &= resolve(handle, "lua_pushlightuserdata", &A.pushlightuserdata);
    ok &= resolve(handle, "lua_touserdata", &A.touserdata);
    ok &= resolve(handle, "lua_rawseti", &A.rawseti);
    ok &= resolve(handle, "lua_createtable", &A.createtable);
    ok &= resolve(handle, "lua_gc", &A.gc);
    ok &= resolve(handle, "lua_dump", &A.dump);
    return ok;
}

// ---------------------------------------------------------------------------
// Bridge service, release counting and the controlled allocator
// ---------------------------------------------------------------------------

int g_release_count = 0;
void *g_pending_owner = nullptr;
void (*g_pending_release)(void *) = nullptr;
bool g_arm_oom = false;

struct AllocCtl {
    bool fail_next = false;
    long calls = 0;
};

AllocCtl *g_alloc = nullptr;
void **g_bridge = nullptr;

void counting_release(void *owner) {
    ++g_release_count;
    if (g_pending_release != nullptr && owner == g_pending_owner) {
        g_pending_release(owner);
    }
}

int counting_dump(const lua_DsPucDumpRequest *request, lua_DsPucDumpResult *result) {
    const int ok = ds::puc51::Dump(request, result);
    if (ok != 0) {
        g_pending_owner = result->owner;
        g_pending_release = result->release;
        result->release = &counting_release;
        if (g_arm_oom && g_alloc != nullptr) {
            /* Fail the very next VM allocation: that is the string copy of the
            ** bytes this call just produced, not the service's own buffering. */
            g_arm_oom = false;
            g_alloc->fail_next = true;
        }
    }
    return ok;
}

void *test_alloc(void *ud, void *ptr, size_t /*osize*/, size_t nsize) {
    auto *ctl = static_cast<AllocCtl *>(ud);
    ++ctl->calls;
    if (nsize == 0) {
        std::free(ptr);
        return nullptr;
    }
    if (ctl->fail_next) {
        ctl->fail_next = false;
        return nullptr;
    }
    return std::realloc(ptr, nsize);
}

// ---------------------------------------------------------------------------
// Result plumbing
// ---------------------------------------------------------------------------

struct DumpResult {
    bool ok = false;
    std::string bytes;
    std::string error;
};

long vm_bytes(lua_State *L) {
    return A.gc(L, kGcCount, 0) * 1024L + A.gc(L, kGcCountB, 0);
}

void collect(lua_State *L, int rounds = 3) {
    for (int i = 0; i < rounds; ++i) {
        A.gc(L, kGcCollect, 0);
    }
}

/* Calls jit.puc_dump_clear(); -1 when the function is not there (build without
** the jit library, or a VM that predates it). The cleanup is a Lua entry point,
** not a C API, so it is reached exactly the way a mod reaches it. */
double call_puc_dump_clear(lua_State *L) {
    const int base = A.gettop(L);
    A.getfield(L, kGlobalsIndex, "jit");
    if (A.type(L, -1) != kTTable) {
        A.settop(L, base);
        return -1.0;
    }
    A.getfield(L, -1, "puc_dump_clear");
    A.remove(L, -2);
    if (A.type(L, -1) != kTFunction) {
        A.settop(L, base);
        return -1.0;
    }
    if (A.pcall(L, 0, 1, 0) != 0) {
        A.settop(L, base);
        return -1.0;
    }
    const double n = A.tonumber(L, -1);
    A.settop(L, base);
    return n;
}

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const char *label) {
    ++g_checks;
    if (condition) {
        return;
    }
    ++g_failures;
    std::fprintf(stderr, "[self-test] FAIL: %s\n", label);
}

void check_contains(const std::string &haystack, const char *needle, const char *label) {
    ++g_checks;
    if (haystack.find(needle) != std::string::npos) {
        return;
    }
    ++g_failures;
    std::fprintf(stderr, "[self-test] FAIL: %s (wanted \"%s\" in \"%s\")\n", label, needle,
                 haystack.c_str());
}

void check_absent(const std::string &haystack, const char *needle, const char *label) {
    ++g_checks;
    if (haystack.find(needle) == std::string::npos) {
        return;
    }
    ++g_failures;
    std::fprintf(stderr, "[self-test] FAIL: %s (found \"%s\" in \"%s\")\n", label, needle,
                 haystack.c_str());
}

bool is_puc_dump(const std::string &bytes) {
    return bytes.size() > 5 && static_cast<unsigned char>(bytes[0]) == 0x1b &&
           bytes.compare(1, 3, "Lua") == 0;
}

std::string lua_string_at(lua_State *L, int idx) {
    size_t n = 0;
    const char *p = A.tolstring(L, idx, &n);
    return p != nullptr ? std::string(p, n) : std::string();
}

/* LUA_REGISTRYINDEX2 is the per-state private root: a normal C API pseudo-index, exactly like
** LUA_REGISTRYINDEX, and not reachable through the public registry at all.
*/
bool push_private_root(lua_State *L) {
    const int base = A.gettop(L);
    A.pushvalue(L, kRegistry2Index);
    if (A.type(L, -1) != kTTable) {
        std::fprintf(stderr, "[self-test] LUA_REGISTRYINDEX2 is not a table\n");
        A.settop(L, base);
        return false;
    }
    return true;
}

// Calls string.dump on the value at `idx`; leaves the stack unchanged.
DumpResult dump_at(lua_State *L, int idx, const char *mode) {
    DumpResult out;
    const int base = A.gettop(L);
    A.pushvalue(L, idx);
    A.getfield(L, kGlobalsIndex, "string");
    A.getfield(L, -1, "dump");
    A.remove(L, -2);  /* string table */
    A.insert(L, -2);  /* dump, fn */
    if (mode != nullptr) {
        A.pushstring(L, mode);
    }
    const int status = A.pcall(L, mode != nullptr ? 2 : 1, 1, 0);
    if (status == 0) {
        out.ok = true;
        out.bytes = lua_string_at(L, -1);
    } else {
        out.error = lua_string_at(L, -1);
    }
    A.settop(L, base);
    return out;
}

// Dumps the value at `idx` through lua_dump (C API) instead of string.dump.
DumpResult dump_c_api(lua_State *L, int idx) {
    DumpResult out;
    struct Sink {
        std::string bytes;
    } sink;
    const int base = A.gettop(L);
    A.pushvalue(L, idx);
    const int status = A.dump(L, [](lua_State *, const void *p, size_t size, void *ud) {
        auto *s = static_cast<Sink *>(ud);
        s->bytes.append(static_cast<const char *>(p), size);
        return 0;
    }, &sink);
    A.settop(L, base);
    out.ok = status == 0;
    out.bytes = std::move(sink.bytes);
    return out;
}

bool load_source(lua_State *L, const std::string &source, const char *chunkname) {
    if (A.L_loadbuffer(L, source.data(), source.size(), chunkname) != 0) {
        const std::string err = lua_string_at(L, -1);
        std::fprintf(stderr, "[self-test] compile failed (%s): %s\n", chunkname, err.c_str());
        A.settop(L, 0);
        return false;
    }
    return true;
}

// Calls the function at `idx` (which must be a positive index) with no arguments.
bool call_at(lua_State *L, int idx, int nresults) {
    A.pushvalue(L, idx);
    if (A.pcall(L, 0, nresults, 0) != 0) {
        const std::string err = lua_string_at(L, -1);
        std::fprintf(stderr, "[self-test] call failed: %s\n", err.c_str());
        A.settop(L, 0);
        return false;
    }
    return true;
}

std::string reference_bytes(const std::string &source, const char *chunkname, int result_index,
                            int strip, std::string &error) {
    void *data = nullptr;
    size_t size = 0;
    char err[512] = {0};
    if (ds_ref_dump(source.data(), source.size(), chunkname, result_index, strip, &data, &size, err,
                    sizeof(err)) == 0) {
        error = err;
        return std::string();
    }
    std::string out(static_cast<const char *>(data), size);
    ds_ref_free(data);
    return out;
}

// One end-to-end pair: compile+run `source` in the VM, dump the requested result
// through the mod path, and compare with the PUC reference dump of the same text.
// result_index 0 dumps the root chunk instead of a returned value.
void check_pair(lua_State *L, const char *label, const std::string &source,
                const char *chunkname, int result_index, const char *mode = nullptr) {
    A.settop(L, 0);
    if (!load_source(L, source, chunkname)) {
        check(false, label);
        return;
    }
    int target = 1;
    if (result_index != 0) {
        if (!call_at(L, 1, kMultiRet)) {
            check(false, label);
            return;
        }
        target = 1 + result_index;  /* results start after the chunk itself */
        if (A.gettop(L) < target) {
            std::fprintf(stderr, "[self-test] %s: only %d result(s)\n", label, A.gettop(L) - 1);
            check(false, label);
            return;
        }
    }
    const int strip = (mode != nullptr && std::strchr(mode, 's') != nullptr) ? 1 : 0;
    std::string ref_error;
    const std::string expected = reference_bytes(source, chunkname, result_index, strip, ref_error);
    if (expected.empty()) {
        std::fprintf(stderr, "[self-test] reference dump failed for %s: %s\n", label,
                     ref_error.c_str());
        check(false, label);
        return;
    }
    const DumpResult got = dump_at(L, target, mode);
    if (!got.ok) {
        std::fprintf(stderr, "[self-test] mod dump failed for %s: %s\n", label, got.error.c_str());
        check(false, label);
        return;
    }
    if (got.bytes != expected) {
        std::fprintf(stderr, "[self-test] %s: %zu bytes differ from the reference (%zu)\n", label,
                     got.bytes.size(), expected.size());
        check(false, label);
        return;
    }
    check(true, label);
    A.settop(L, 0);
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

void check_native_baseline(lua_State *L) {
    A.settop(L, 0);
    const std::string source = "return function(n) return n + 7 end";
    if (!load_source(L, source, "=native_baseline") || !call_at(L, 1, 1)) {
        check(false, "native baseline compiles and runs");
        return;
    }
    const DumpResult dumped = dump_at(L, 2, nullptr);
    check(dumped.ok, "baseline dumps");
    /* While the host bridge exists every Lua function dumps real PUC 5.1 bytecode, exactly
    ** like stock PUC 5.1. Native LuaJIT bytes are the host-off case, covered by
    ** --expect-native. */
    check(is_puc_dump(dumped.bytes), "baseline dump is PUC 5.1 bytecode while the bridge exists");

    /* The C API must keep the LuaJIT format too. */
    struct Sink {
        std::string bytes;
    } sink;
    const int base = A.gettop(L);
    A.pushvalue(L, 2);
    const int status = A.dump(L, [](lua_State *, const void *p, size_t size, void *ud) {
        auto *s = static_cast<Sink *>(ud);
        s->bytes.append(static_cast<const char *>(p), size);
        return 0;
    }, &sink);
    A.settop(L, base);
    check(status == 0 && sink.bytes.size() > 3 &&
              static_cast<unsigned char>(sink.bytes[0]) == 0x1b && sink.bytes[1] == 'L' &&
              sink.bytes[2] == 'J',
          "lua_dump keeps the LuaJIT format");
    A.settop(L, 0);
}

void check_exact_bytes(lua_State *L) {
    const std::string source = "return function(n) return n + 7 end";
    const char *chunkname = "=puc_dump_dynamic";
    check_pair(L, "mod dump equals the PUC reference byte for byte", source, chunkname, 1);

    /* The bytes must be real Lua 5.1 bytecode: run them in a PUC state. */
    A.settop(L, 0);
    if (!load_source(L, source, chunkname) || !call_at(L, 1, 1)) {
        check(false, "reference execution of the dump");
        return;
    }
    const DumpResult got = dump_at(L, 2, nullptr);
    double value = 0.0;
    char err[512] = {0};
    const int ran = got.ok ? ds_ref_execute(got.bytes.data(), got.bytes.size(), 5.0, &value, err,
                                            sizeof(err))
                           : 0;
    if (ran == 0) {
        std::fprintf(stderr, "[self-test] PUC execution failed: %s\n", err);
    }
    check(ran == 1 && value == 12.0, "dumped bytes execute as Lua 5.1 (f(5) == 12)");
    A.settop(L, 0);
}

void check_identity_edges(lua_State *L) {
    const char *two = "return function() return 11 end, function() return 22 end";
    check_pair(L, "two same-line closures: first", two, "=same_line", 1);
    check_pair(L, "two same-line closures: second", two, "=same_line", 2);
    check_pair(L, "multi-level nested function",
               "return (function() return function() return 99 end end)()", "=nested", 1);
    check_pair(L, "same-line local function definitions",
               "local a = function() return 1 end local b = function() return 2 end return a, b",
               "=same_line_defs", 2);
    /* Two different compiles sharing one chunkname must not cross-map. */
    check_pair(L, "same chunkname, first source", "return function() return 1001 end", "=twice", 1);
    check_pair(L, "same chunkname, second source", "return function() return 2002 end", "=twice", 1);
    check_pair(L, "parameters", "return function(a, b) return a - b end", "=params", 1);
    check_pair(L, "self method", "return function(t) return t:value() end", "=method", 1);
    check_pair(L, "vararg function", "return function(...) return ... end", "=vararg", 1);
    check_pair(L, "captured upvalue", "local a = 5\nreturn function() return a end", "=upval", 1);
    check_pair(L, "root chunk (never executed)", "return 1", "=root", 0);
    check_pair(L, "empty source", "", "=empty", 0);
    /* A root chunk that must not run: the service only ever compiles. */
    check_pair(L, "root chunk with a runtime error in its body",
               "error('must not execute')\nreturn function() return 1 end", "=poison", 0);
    /* Strict mode strips the debug info; byte-for-byte with the reference. */
    check_pair(L, "strip mode matches the reference", "return function(n) return n + 7 end",
               "=strip", 1, "s");
}

void check_reader_paths(lua_State *L) {
    /* Text assembled in Lua, compiled and dumped in one call chain. */
    const std::string assembled = "return function(n) return n * 3 end";
    A.settop(L, 0);
    const std::string build =
        "local parts = {'return function(n) ', 'return n * 3 end'}\n"
        "return loadstring(table.concat(parts), '=puc_dump_dynamic')";
    if (!load_source(L, build, "=builder") || !call_at(L, 1, 1)) {
        check(false, "dynamic source compiles");
        return;
    }
    if (!call_at(L, 2, 1)) { /* run the assembled chunk -> inner function */
        check(false, "dynamic source runs");
        return;
    }
    const DumpResult got = dump_at(L, 3, nullptr);
    std::string ref_error;
    const std::string expected = reference_bytes(assembled, "=puc_dump_dynamic", 1, 0, ref_error);
    check(got.ok && !expected.empty() && got.bytes == expected,
          "dynamically assembled source dumps identically");
    A.settop(L, 0);

    /* 1-byte reader chunks, with the reader call count compared to a run without
    ** the bridge: the capture layer must not add or reorder reader calls. */
    const std::string text = "local t = 1\nreturn function() return t + 41 end\n";
    const std::string driver =
        "local text = ... \n"
        "local i, calls = 0, 0\n"
        "local chunk = assert(load(function()\n"
        "  calls = calls + 1\n"
        "  i = i + 1\n"
        "  if i > #text then return nil end\n"
        "  return text:sub(i, i)\n"
        "end, '=one_byte'))\n"
        "return chunk, calls\n";

    auto run_one_byte = [&](bool with_bridge, int *calls_out, std::string *bytes_out) {
        A.settop(L, 0);
        if (!load_source(L, driver, "=one_byte_driver")) {
            return false;
        }
        A.pushstring(L, text.c_str());
        if (A.pcall(L, 1, 2, 0) != 0) {
            A.settop(L, 0);
            return false;
        }
        /* L: 1 = chunk, 2 = calls */
        *calls_out = static_cast<int>(A.tonumber(L, 2));
        if (!call_at(L, 1, 1)) { /* run the assembled chunk -> inner function */
            return false;
        }
        /* L: 1 = chunk, 2 = calls, 3 = inner */
        if (!with_bridge) {
            A.settop(L, 0);
            return true;
        }
        const DumpResult got = dump_at(L, 3, nullptr);
        if (got.ok) {
            *bytes_out = got.bytes;
        }
        A.settop(L, 0);
        return got.ok;
    };

    int calls_with = 0;
    std::string bytes;
    const bool with_bridge = run_one_byte(true, &calls_with, &bytes);
    int calls_without = 0;
    std::string ignored;
    void *saved = *g_bridge;
    *g_bridge = nullptr;
    const bool without_bridge = run_one_byte(false, &calls_without, &ignored);
    *g_bridge = saved;
    std::string reader_ref_error;
    const std::string reader_expected = reference_bytes(text, "=one_byte", 1, 0, reader_ref_error);
    check(with_bridge && without_bridge, "one-byte reader compiles both ways");
    check(calls_with == calls_without, "capture does not change the reader call count");
    check(!bytes.empty() && bytes == reader_expected,
          "one-byte reader dump matches the reference");

    /* A reader that compiles another chunk must not share capture state. */
    A.settop(L, 0);
    const std::string nested_driver =
        "local inner_text = 'return function() return 3 end'\n"
        "local parts = {'return function() return 9 end', nil}\n"
        "local nested\n"
        "local i = 0\n"
        "local function reader()\n"
        "  if i == 0 then nested = loadstring(inner_text, '=nested') end\n"
        "  i = i + 1\n"
        "  return parts[i]\n"
        "end\n"
        "local outer = assert(load(reader, '=outer'))\n"
        "return outer, nested\n";
    if (!load_source(L, nested_driver, "=nested_driver") || !call_at(L, 1, 2)) {
        check(false, "nested-load driver runs");
        return;
    }
    const DumpResult outer = dump_at(L, 2, nullptr);
    const DumpResult nested = dump_at(L, 3, nullptr);
    std::string outer_error;
    std::string nested_error;
    const std::string outer_expected =
        reference_bytes("return function() return 9 end", "=outer", 0, 0, outer_error);
    const std::string nested_expected =
        reference_bytes("return function() return 3 end", "=nested", 0, 0, nested_error);
    check(outer.ok && outer.bytes == outer_expected, "outer chunk captured across a nested load");
    check(nested.ok && nested.bytes == nested_expected, "nested load captured independently");
    A.settop(L, 0);
}

void check_gc_retention(lua_State *L) {
    /* Only the innermost closure survives: the compile's source lives with the
    ** prototype tree, not with the root closure. */
    const std::string source =
        "local captured = 20\n"
        "return (function() return function() return captured + 1 end end)()";
    A.settop(L, 0);
    if (!load_source(L, source, "=gc_retain") || !call_at(L, 1, 1)) {
        check(false, "gc retention fixture runs");
        return;
    }
    /* L: 1 = chunk, 2 = inner closure. Keep only the closure. */
    A.pushvalue(L, 2);
    A.replace(L, 1);
    A.settop(L, 1);
    for (int i = 0; i < 3; ++i) {
        A.gc(L, kGcCollect, 0);
    }
    for (int i = 0; i < 400; ++i) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "gc-churn-%032d-padpadpad", i);
        A.pushstring(L, buf);
        A.settop(L, 1);
    }
    A.gc(L, kGcCollect, 0);
    const DumpResult got = dump_at(L, 1, nullptr);
    std::string ref_error;
    const std::string expected = reference_bytes(source, "=gc_retain", 1, 0, ref_error);
    check(got.ok && !expected.empty() && got.bytes == expected,
          "nested closure still dumps after churn and full GC");
    A.settop(L, 0);

    /* Dropping every closure must let the VM reclaim the captured sources. */
    for (int i = 0; i < 3; ++i) {
        A.gc(L, kGcCollect, 0);
    }
    const long baseline = A.gc(L, kGcCount, 0) * 1024L + A.gc(L, kGcCountB, 0);
    {
        std::string big = "return function() return 1 end\n";
        big.reserve(200 * 1024);
        for (int i = 0; i < 4000; ++i) {
            big += "-- filler line to enlarge the captured source\n";
        }
        if (load_source(L, big, "=gc_big")) {
            A.settop(L, 0);
        }
    }
    for (int i = 0; i < 4; ++i) {
        A.gc(L, kGcCollect, 0);
    }
    const long after = A.gc(L, kGcCount, 0) * 1024L + A.gc(L, kGcCountB, 0);
    check(after - baseline < 64 * 1024, "dropped compiles release their captured source");
}

void check_error_branches(lua_State *L, Vm &vm) {
    const std::string source = "return function(n) return n + 7 end";

    /* 1. A bytecode-reloaded prototype has no source identity. */
    A.settop(L, 0);
    if (!load_source(L, source, "=reload") || !call_at(L, 1, 1)) {
        check(false, "reload fixture compiles");
        return;
    }
    /* lua_dump keeps the LuaJIT format even with the bridge installed, so it is the
    ** bytecode source here; the bridged string.dump would hand back PUC bytes that
    ** this VM refuses to reload (LJ_DS_REJECT_BINARY_CHUNKS). */
    const DumpResult native = dump_c_api(L, 2);
    check(native.ok, "lua_dump produces the reload fixture's bytecode");
    A.settop(L, 0);
    if (!native.ok) {
        return;
    }
    const bool allowed = vm.allow_lj_bytecode != nullptr;
    if (allowed) {
        vm.allow_lj_bytecode(L, 1);
    }
    const bool reloaded_ok = load_source(L, native.bytes, "=reload_bc");
    if (allowed) {
        vm.allow_lj_bytecode(L, 0);
    }
    if (!reloaded_ok) {
        check(false, "VM reloads its own LuaJIT bytecode with the switch on");
        A.settop(L, 0);
        return;
    }
    check(allowed, "lua_ds_allow_lj_bytecode available for the reload fixture");
    const DumpResult reloaded = dump_at(L, 1, nullptr);
    check(!reloaded.ok, "bytecode reload has no source to convert");
    check_contains(reloaded.error, "source unavailable", "bytecode reload error text");
    A.settop(L, 0);

    /* 2. Source the PUC 5.1 parser rejects (goto is 5.2+). */
    const std::string goto_source = "return function() goto done ::done:: return 1 end";
    A.settop(L, 0);
    if (load_source(L, goto_source, "=goto")) {
        const DumpResult rejected = dump_at(L, 1, nullptr);
        check(!rejected.ok, "PUC-incompatible source is reported, not faked");
        check_contains(rejected.error, "PUC 5.1 string.dump failed",
                       "PUC-incompatible source error text");
        check_contains(rejected.error, "PUC compilation failed",
                       "PUC-incompatible source names the compiler");
    }
    A.settop(L, 0);

    /* 3. Prototype identity mismatches are rejected by the service itself. */
    {
        const std::string text = "return function(n) return n + 7 end";
        lua_DsPucDumpRequest request{};
        request.source = text.data();
        request.source_len = text.size();
        request.chunkname = "=mismatch";
        request.node_index = 0;
        request.node_count = 2;
        request.numparams = 0;
        request.is_vararg = 1;
        request.child_count = 1;
        lua_DsPucDumpResult result{};
        check(ds::puc51::Dump(&request, &result) == 1, "service accepts the root identity");
        check(result.data != nullptr && result.size > 0 && result.release != nullptr,
              "service transfers an owned buffer");
        if (result.release != nullptr) {
            result.release(result.owner);
        }
        lua_DsPucDumpRequest wrong_count = request;
        wrong_count.node_count = 3;
        lua_DsPucDumpResult count_result{};
        check(ds::puc51::Dump(&wrong_count, &count_result) == 0,
              "service rejects a wrong node count");
        check_contains(count_result.error, "prototype mismatch", "node count error text");
        lua_DsPucDumpRequest wrong_shape = request;
        wrong_shape.child_count = 0;
        lua_DsPucDumpResult shape_result{};
        check(ds::puc51::Dump(&wrong_shape, &shape_result) == 0, "service rejects a wrong shape");
        check_contains(shape_result.error, "prototype mismatch", "shape error text");
        lua_DsPucDumpRequest out_of_range = request;
        out_of_range.node_index = 9;
        lua_DsPucDumpResult range_result{};
        check(ds::puc51::Dump(&out_of_range, &range_result) == 0,
              "service rejects an out-of-range node index");
        lua_DsPucDumpRequest bytecode = request;
        bytecode.source = "\x1bLJ\x02";
        bytecode.source_len = 4;
        lua_DsPucDumpResult bc_result{};
        check(ds::puc51::Dump(&bytecode, &bc_result) == 0, "service rejects bytecode input");
        check_contains(bc_result.error, "bytecode", "bytecode rejection text");
    }

    /* 4. An unbridged slot reports bridge unavailable and leaves the state usable. */
    A.settop(L, 0);
    if (!load_source(L, source, "=nobridge") || !call_at(L, 1, 1)) {
        check(false, "no-bridge fixture compiles");
        return;
    }
    void *saved = *vm.bridge_slot;
    *vm.bridge_slot = nullptr;
    const DumpResult unbridged = dump_at(L, 2, nullptr);
    *vm.bridge_slot = saved;
    check(!unbridged.ok, "missing bridge fails instead of faking bytecode");
    check_contains(unbridged.error, "bridge unavailable", "missing bridge error text");
    A.settop(L, 0);
    double plain = 0.0;
    const bool usable = load_source(L, "return 6 * 7", "=usable") && call_at(L, 1, 1);
    if (usable) {
        plain = A.tonumber(L, 2);
    }
    check(usable && plain == 42.0, "state still runs ordinary Lua after a dump error");
    A.settop(L, 0);

    /* 5. Mod PUC bytecode is not loadable by the LuaJIT VM, and non-function
    ** arguments keep the original LuaJIT error. */
    A.settop(L, 0);
    if (!load_source(L, source, "=nocross") || !call_at(L, 1, 1)) {
        check(false, "cross-load fixture compiles");
        return;
    }
    const DumpResult puc = dump_at(L, 2, nullptr);
    A.settop(L, 0);
    check(puc.ok && puc.bytes.size() > 3, "mod dump produced for the cross-load check");
    if (puc.ok && !puc.bytes.empty()) {
        const int cross = A.L_loadbuffer(L, puc.bytes.data(), puc.bytes.size(), "=cross");
        check(cross != 0, "LuaJIT refuses PUC bytecode (no interop promised)");
        A.settop(L, 0);
    }

    A.getfield(L, kGlobalsIndex, "print");
    const DumpResult cfunc = dump_at(L, 1, nullptr);
    check(!cfunc.ok, "dumping a C function still fails");
    check_contains(cfunc.error, "unable to dump given function", "C function keeps its error");
    check_absent(cfunc.error, "PUC 5.1", "C function error is not a PUC error");
    A.settop(L, 0);
}

void check_copy_oom(Vm &vm) {
    /* A dedicated state with a controlled allocator, so the OOM lands exactly on
    ** the VM's string copy of an already-successful service result. */
    AllocCtl ctl;
    g_alloc = &ctl;
    lua_State *L = A.newstate(&test_alloc, &ctl);
    g_alloc = nullptr;
    if (L == nullptr) {
        check(false, "controlled-allocator state");
        return;
    }
    A.L_openlibs(L);
    A.settop(L, 0);
    /* The dumped bytes must be big enough that the VM's copy needs memory from
    ** the allocator in BOTH GC builds: the classic GC always asks, but the arena
    ** GC serves small objects from bump space and only asks for a new block when
    ** the object is huge (>= ArenaHugeThreshold). A ~700 KiB constant clears that
    ** threshold, so arming the allocator is deterministic instead of racy. */
    std::string source = "return function() return \"";
    source.append(700 * 1024, 'x');
    source += "\" end";
    if (A.L_loadbuffer(L, source.data(), source.size(), "=oom") != 0) {
        check(false, "OOM fixture compiles");
        A.close(L);
        return;
    }
    if (A.pcall(L, 0, 1, 0) != 0) {
        check(false, "OOM fixture runs");
        A.close(L);
        return;
    }
    /* lua_pcall consumed the chunk: index 1 is the function with the huge
    ** constant, which is what makes the dump itself large. */
    void *saved = *vm.bridge_slot;
    *vm.bridge_slot = reinterpret_cast<void *>(&counting_dump);

    g_release_count = 0;
    g_alloc = &ctl;
    g_arm_oom = true;
    const DumpResult failed = dump_at(L, 1, nullptr);
    g_alloc = nullptr;
    g_arm_oom = false;
    /* The arm is consumed only if the copy really went through lua_Alloc. The
    ** arena GC reserves huge blocks (and whole arenas) with the OS, so a copied
    ** string can bypass the allocator entirely there; report that instead of
    ** pretending the injection happened. */
    const bool injected = !ctl.fail_next;
    ctl.fail_next = false;
    if (injected) {
        check(!failed.ok, "copy-stage OOM surfaces as an error");
        check_contains(failed.error, "memory", "copy-stage OOM error text");
    } else {
        std::printf("[self-test] note: this GC serves the copied string outside lua_Alloc; "
                    "copy-stage OOM not injectable here\n");
        check(failed.ok, "copy succeeds when the allocator cannot reach it");
    }
    check(g_release_count == 1, "host buffer released exactly once on the copy path");

    /* Disarmed, the same state dumps again and still releases exactly once. */
    A.settop(L, 0);
    A.L_loadbuffer(L, source.data(), source.size(), "=oom");
    A.pcall(L, 0, 1, 0);
    g_release_count = 0;
    const DumpResult ok = dump_at(L, 1, nullptr);
    check(ok.ok, "dump works again after the OOM");
    check(g_release_count == 1, "host buffer released exactly once on success");

    *vm.bridge_slot = saved;
    A.close(L);
}

void check_clear_entry(lua_State *L) {
    const double probe = call_puc_dump_clear(L);
    check(probe >= 0.0, "jit.puc_dump_clear is available");
    const std::string source = "return function(n) return n + 7 end";
    A.settop(L, 0);
    if (!load_source(L, source, "=clear") || !call_at(L, 1, 1)) {
        check(false, "clear fixture compiles");
        return;
    }
    const DumpResult before = dump_at(L, 2, nullptr);
    check(before.ok && before.bytes.size() > 6, "dump works before the clear");

    const double cleared = call_puc_dump_clear(L);
    check(cleared >= 1.0, "clear reports the prototypes it dropped");
    const DumpResult after = dump_at(L, 2, nullptr);
    check(!after.ok, "dump after the clear reports a failure, not fake bytes");
    check_contains(after.error, "source unavailable", "cleared source error text");

    /* Capture keeps working: a later compile brings its own source. */
    A.settop(L, 0);
    if (!load_source(L, source, "=clear_again") || !call_at(L, 1, 1)) {
        check(false, "post-clear fixture compiles");
        return;
    }
    const DumpResult again = dump_at(L, 2, nullptr);
    check(again.ok && again.bytes.size() > 6, "a later compile captures its source again");
    A.settop(L, 0);

    /* The point of the entry point: a reachable closure no longer pins the whole
    ** chunk text. Keep the closure, drop the text, and watch the memory return. */
    std::string big = "return function() return 1 end\n";
    big.reserve(200 * 1024);
    for (int i = 0; i < 4000; ++i) {
        big += "-- filler line that only the saved source would keep\n";
    }
    A.settop(L, 0);
    collect(L);
    const long baseline = vm_bytes(L);
    if (!load_source(L, big, "=clear_big") || !call_at(L, 1, 1)) {
        check(false, "big fixture compiles");
        return;
    }
    /* Stack: 1 = the chunk's returned closure, kept alive across the clear. */
    collect(L);
    const long pinned = vm_bytes(L);
    check(pinned - baseline > 64 * 1024, "the saved source is what pins the memory");
    const double cleared_big = call_puc_dump_clear(L);
    collect(L);
    const long released = vm_bytes(L);
    check(cleared_big >= 0.0, "clear ran with a live closure");
    check(released - baseline < 64 * 1024, "a cleared compile releases its text with the closure alive");
    A.settop(L, 0);
}

/* The private root is the only place injected state lives; the old top-level registry names
** (_VMEVENTS, a bare policy key) are gone. */
void check_private_root_layout(lua_State *L) {
    const int base = A.gettop(L);
    check(push_private_root(L), "private root reachable through the VM helper");
    A.settop(L, base);
    A.pushstring(L, "_VMEVENTS");
    A.rawget(L, kRegistryIndex);
    check(A.type(L, -1) == kTNil, "no top-level _VMEVENTS survives");
    A.settop(L, base);

    /* LUA_REGISTRYINDEX2 is a normal C API pseudo-index: rawset/rawget reach the second
    ** registry, while the public one stays untouched. */
    A.pushstring(L, "registry2_probe");
    A.pushstring(L, "value");
    A.rawset(L, kRegistry2Index);
    A.pushstring(L, "registry2_probe");
    A.rawget(L, kRegistry2Index);
    check(A.type(L, -1) == kTString, "registry2 supports rawset/rawget");
    A.settop(L, base);
    A.pushstring(L, "registry2_probe");
    A.rawget(L, kRegistryIndex);
    check(A.type(L, -1) == kTNil, "registry2 entries are not in the public registry");
    A.settop(L, base);
    A.pushstring(L, "registry2_probe");
    A.pushnil(L);
    A.rawset(L, kRegistry2Index);
}

/* One Lua scene for the shared private services: the C-function proxies (allow / replace /
** return with a nil hole / deny), the trace event anchor (jit.attach) and the profiler
** anchors (jit.profile start -> hot loop -> callback -> stop). The host then checks that the
** profiler anchors are gone and that a GC cycle after all of it is still clean. */
void check_private_root_runtime(lua_State *L) {
    const char *scene = R"LUA(
local function fail(fmt, ...) error(string.format(fmt, ...), 0) end

-- trace events: register, trigger by compiling a trace, unbind
local traces = 0
local function onc(what) traces = traces + 1 end
jit.attach(onc, "trace")
local function hot(n)
    local s = 0
    for i = 1, n do s = s + i end
    return s
end
for _ = 1, 200 do hot(1000) end
jit.attach(onc)
if traces == 0 then fail("jit.attach never fired") end

-- profiler anchors: start, run, stop
local okp, profile = pcall(require, "jit.profile")
if okp and type(profile) == "table" and type(profile.start) == "function" then
    local samples = 0
    profile.start("i", function(thread, count, vmstate) samples = samples + 1 end)
    -- Sampling is time based: keep the thread busy long enough for several ticks.
    local x, deadline = 0, os.clock() + 0.3
    while os.clock() < deadline do x = x + 1 end
    profile.stop()
    if samples == 0 then fail("profiler callback never ran") end
end

-- the anchors and the ledger are all garbage after that
collectgarbage("collect")
collectgarbage("collect")
if hot(10) ~= 55 then fail("hot() broke after GC") end
return "ok"
)LUA";
    const int base = A.gettop(L);
    if (!load_source(L, scene, "=private_root_runtime")) {
        check(false, "private root runtime scene compiles");
        A.settop(L, base);
        return;
    }
    if (call_at(L, 1, 1)) {
        const std::string result = lua_string_at(L, -1);
        check(result == "ok", "private root runtime scene");
        if (result != "ok") {
            std::fprintf(stderr, "[self-test] scene result: %s\n", result.c_str());
        }
    } else {
        check(false, "private root runtime scene ran");
    }
    A.settop(L, base);

    // profile.stop() must have cleared the strong thread/function anchors (fixed C keys, so the
    // check is "no thread value remains in the root").
    check(push_private_root(L), "root reachable after the scene");
    A.pushnil(L);
    while (A.next(L, -2) != 0) {
        if (A.type(L, -1) == kTThread) {
            check(false, "profile thread anchor survived profile.stop");
        }
        A.settop(L, A.gettop(L) - 1);
    }
    A.settop(L, base);
}

int run_self_test(Vm &vm) {
    lua_State *L = A.L_newstate();
    if (L == nullptr) {
        std::fprintf(stderr, "[self-test] cannot create a VM state\n");
        return 1;
    }
    A.L_openlibs(L);

    check_native_baseline(L);
    check_private_root_layout(L);
    check_private_root_runtime(L);
    check_exact_bytes(L);
    check_identity_edges(L);
    check_reader_paths(L);
    check_gc_retention(L);
    check_error_branches(L, vm);
    check_copy_oom(vm);
    check_clear_entry(L);
    A.close(L);

    std::printf("[self-test] %d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

int run_script(const std::string &path, int argc, char **argv) {
    lua_State *L = A.L_newstate();
    if (L == nullptr) {
        std::fprintf(stderr, "[puc-dump-host] cannot create a VM state\n");
        return 1;
    }
    A.L_openlibs(L);

    /* `arg` mirrors the interpreter: arg[0] is the script path, then its args. */
    A.createtable(L, argc + 1, 0);
    A.pushstring(L, path.c_str());
    A.rawseti(L, -2, 0);
    for (int i = 0; i < argc; ++i) {
        A.pushstring(L, argv[i]);
        A.rawseti(L, -2, i + 1);
    }
    A.setfield(L, kGlobalsIndex, "arg");

    FILE *fp = std::fopen(path.c_str(), "rb");
    if (fp == nullptr) {
        std::fprintf(stderr, "[puc-dump-host] cannot open %s\n", path.c_str());
        A.close(L);
        return 1;
    }
    std::string text;
    char buf[8192];
    size_t got = 0;
    while ((got = std::fread(buf, 1, sizeof(buf), fp)) > 0) {
        text.append(buf, got);
    }
    std::fclose(fp);

    if (A.L_loadbuffer(L, text.data(), text.size(), ("@" + path).c_str()) != 0) {
        std::fprintf(stderr, "[puc-dump-host] cannot compile %s: %s\n", path.c_str(),
                     lua_string_at(L, -1).c_str());
        A.close(L);
        return 1;
    }
    if (A.pcall(L, 0, 0, 0) != 0) {
        std::fprintf(stderr, "%s\n", lua_string_at(L, -1).c_str());
        A.close(L);
        return 1;
    }
    A.close(L);
    return 0;
}

int run_expect_native(Vm &vm) {
    int failures = 0;
    if (vm.bridge_slot != nullptr) {
        std::fprintf(stderr, "[expect-native] FAIL: library still exports lj_ds_puc_dump\n");
        ++failures;
    } else {
        std::printf("[expect-native] no lj_ds_puc_dump export\n");
    }
    lua_State *L = A.L_newstate();
    if (L == nullptr) {
        std::fprintf(stderr, "[expect-native] FAIL: cannot create a VM state\n");
        return 1;
    }
    A.L_openlibs(L);
    const std::string fixture = "return function(n) return n + 7 end";
    if (A.L_loadbuffer(L, fixture.data(), fixture.size(), "=native") != 0 ||
        A.pcall(L, 0, 1, 0) != 0) {
        std::fprintf(stderr, "[expect-native] FAIL: fixture does not run\n");
        A.close(L);
        return 1;
    }
    /* A compile-out VM keeps its native dump format. */
    const DumpResult dumped = dump_at(L, 1, nullptr);
    const bool lj_header = dumped.ok && dumped.bytes.size() > 3 &&
                           static_cast<unsigned char>(dumped.bytes[0]) == 0x1b &&
                           dumped.bytes[1] == 'L' && dumped.bytes[2] == 'J';
    if (!lj_header) {
        std::fprintf(stderr, "[expect-native] FAIL: the native dump format changed\n");
        ++failures;
    } else {
        std::printf("[expect-native] dump stays LuaJIT bytecode\n");
        const int loaded =
            A.L_loadbuffer(L, dumped.bytes.data(), dumped.bytes.size(), "=native_reload");
        if (loaded != 0) {
            std::fprintf(stderr, "[expect-native] FAIL: native dump does not reload: %s\n",
                         lua_string_at(L, -1).c_str());
            ++failures;
        } else {
            std::printf("[expect-native] native dump reloads\n");
        }
    }
    /* The cleanup entry point always exists on the jit table; without the capture
    ** switch there is nothing to drop and it must report exactly that. */
    const double cleared = call_puc_dump_clear(L);
    if (cleared < 0.0) {
        std::fprintf(stderr, "[expect-native] FAIL: jit.puc_dump_clear missing\n");
        ++failures;
    } else if (cleared != 0.0) {
        std::fprintf(stderr,
                     "[expect-native] FAIL: clear dropped sources without the capture switch\n");
        ++failures;
    } else {
        std::printf("[expect-native] jit.puc_dump_clear is a no-op\n");
    }
    A.close(L);
    return failures == 0 ? 0 : 1;
}

void usage() {
    std::fprintf(stderr,
                 "usage: puc_dump_host --vm <library> (--self-test | --expect-native |\n"
                 "                     --script <lua-file> [-- args...])\n");
}

} // namespace

int main(int argc, char **argv) {
    std::string vm_path;
    std::string script_path;
    bool self_test = false;
    bool expect_native = false;
    int script_argc = 0;
    char **script_argv = nullptr;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--vm" && i + 1 < argc) {
            vm_path = argv[++i];
        } else if (arg == "--script" && i + 1 < argc) {
            script_path = argv[++i];
        } else if (arg == "--self-test") {
            self_test = true;
        } else if (arg == "--expect-native") {
            expect_native = true;
        } else if (arg == "--") {
            script_argc = argc - i - 1;
            script_argv = argv + i + 1;
            break;
        } else {
            usage();
            return 1;
        }
    }
    if (vm_path.empty() || (!self_test && !expect_native && script_path.empty())) {
        usage();
        return 1;
    }

    Vm vm;
    vm.handle = open_library(vm_path);
    if (vm.handle == nullptr) {
        std::fprintf(stderr, "[puc-dump-host] cannot load %s: %s\n", vm_path.c_str(),
                     library_error().c_str());
        return 1;
    }
    if (!resolve_api(vm.handle)) {
        return 1;
    }
    vm.allow_lj_bytecode = reinterpret_cast<void (*)(lua_State *, int)>(
        find_symbol(vm.handle, "lua_ds_allow_lj_bytecode"));
    vm.bridge_slot = reinterpret_cast<void **>(find_symbol(vm.handle, "lj_ds_puc_dump"));
    g_bridge = vm.bridge_slot;
    std::printf("[puc-dump-host] vm=%s bridge=%s\n", vm_path.c_str(),
                vm.bridge_slot != nullptr ? "present" : "absent");

    if (expect_native) {
        return run_expect_native(vm);
    }
    if (vm.bridge_slot == nullptr) {
        std::fprintf(stderr, "[puc-dump-host] FAIL: %s has no lj_ds_puc_dump slot\n",
                     vm_path.c_str());
        return 1;
    }
    *vm.bridge_slot = reinterpret_cast<void *>(&ds::puc51::Dump);
    if (self_test) {
        return run_self_test(vm);
    }
    return run_script(script_path, script_argc, script_argv);
}
