// game/GameLuaContextGame.cpp — in-process game Lua context + instance
#include "game/GameLuaContextLua51.hpp"
#include "game/GameLuaInternal.hpp"
#include "game/LuaModDump.hpp"
#include "util/lua51_object.hpp"
#include "util/frida_gum_interceptor.hpp"
#include "lua_debugger_helper.hpp"
#include "config/InjectorHostConfig.hpp"
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <algorithm>
#include <vector>
#include <string>
#include <mutex>
#include <cstdlib>
#include <spdlog/fmt/std.h>
#include <spdlog/spdlog.h>
#ifdef _WIN32
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif
#include "util/PathText.hpp"

namespace {

constexpr auto kDumpOutputDir = "dumped_lua_mods/";

std::vector<std::string> g_dump_mod_names;
struct DumpSink {
    std::size_t size = 0;          // bytes in the committed main file
    std::size_t last_payload = 0;  // bytes written by the previous lua_load call
};
std::unordered_map<std::filesystem::path, DumpSink, ds::util::PathHash> g_dump_sinks;
std::mutex g_dump_mutex;
std::once_flag g_dump_init_once;
bool g_dump_enabled = false;

// The engine names file loads "../mods/<mod>/<file>" (optionally '@'-prefixed, the
// Lua chunkname convention); loads that did not come from a file pass the code block
// itself as the chunkname, which is not a usable path. Map the former under the dump
// root and sink everything else into a single thunk.lua.
std::filesystem::path ChunkDumpPath(const char *chunkname) {
    constexpr std::string_view mods_prefix = "../mods/";
    // Characters the filesystem rejects: a chunkname hitting one is not a path.
    constexpr std::string_view invalid_path_chars = "\\:*?\"<>|\r\n\t";
    std::string_view name{chunkname ? chunkname : ""};
    if (!name.empty() && name.front() == '@') name.remove_prefix(1);
    if (name.starts_with(mods_prefix)) {
        name.remove_prefix(mods_prefix.size());
        if (!name.empty() && name.find_first_of(invalid_path_chars) == std::string_view::npos) {
            auto path = std::filesystem::path{kDumpOutputDir} / std::string{name};
            if (ds::util::path_to_utf8(path).size() <= 255) {
                return path;
            }
        }
    }
    return std::filesystem::path{kDumpOutputDir} / "thunk.lua";
}

// Encrypted/obfuscated mod loaders (hercules / MyxlHttps family, e.g. workshop-3014076942)
// feed the decrypted source through lua_load in tiny slices under the file's chunkname.
// Write every slice straight to disk (no in-memory list): a parser error or an OOM kill
// then leaves everything read so far behind.
//
// Two shapes are supported:
//  - streamed: many lua_load calls of tiny payloads for one file -> append to the main
//    file slice by slice (previous payload <= stream_piece_max).
//  - fresh: a new chunk for a file -> stream into "<path>.partN" and commit it over the
//    main file at EOI only when it is at least as large as what is already there. A
//    failed parse leaves the .partN file (evidence) without destroying the previous
//    complete dump.
void WriteChunkPiece(ds::core_vm::detail::LuaModDumpCall &call, const char *data,
                     std::size_t size) {
    if (!data || size == 0) {
        return;
    }
    constexpr std::size_t stream_piece_max = 32;
    std::lock_guard guard{g_dump_mutex};
    auto output_path = ChunkDumpPath(call.chunkname);
    DumpSink &sink = g_dump_sinks[output_path];
    if (!call.started) {
        call.started = true;
        call.continuation = sink.last_payload != 0 && sink.last_payload <= stream_piece_max;
        std::filesystem::create_directories(output_path.parent_path());
        if (call.continuation) {
            // Re-sync after a previous partial (failed) append.
            std::error_code size_ec;
            auto on_disk = std::filesystem::file_size(output_path, size_ec);
            if (!size_ec) {
                sink.size = on_disk;
            }
            call.part_path = output_path;
            call.part.open(call.part_path,
                           std::ios_base::binary | std::ios_base::out | std::ios_base::app);
        } else {
            static unsigned long dump_seq = 0;
            call.part_path = output_path;
            call.part_path += ".part" + std::to_string(++dump_seq);
            call.part.open(call.part_path,
                           std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
        }
        if (!call.part) {
            spdlog::warn("Cannot open lua chunk dump file: {}", call.part_path);
            return;
        }
    }
    if (!call.part) {
        return;
    }
    call.part.write(data, static_cast<std::streamsize>(size));
    // Keep the bytes in the kernel page cache instead of the stream buffer, so an OOM
    // kill or abort still leaves everything read so far on disk.
    call.part.flush();
    call.call_bytes += size;
}

void FinishChunkDump(ds::core_vm::detail::LuaModDumpCall &call) {
    std::lock_guard guard{g_dump_mutex};
    if (!call.started) {
        return;
    }
    call.started = false;
    auto output_path = ChunkDumpPath(call.chunkname);
    if (call.part.is_open()) {
        call.part.close();
    }
    DumpSink &sink = g_dump_sinks[output_path];
    if (call.call_bytes == 0) {
        if (!call.continuation) {
            std::error_code ec;
            std::filesystem::remove(call.part_path, ec);
        }
        sink.last_payload = 0;
        return;
    }
    if (call.continuation) {
        sink.size += call.call_bytes;
    } else if (call.call_bytes >= sink.size) {
        std::error_code ec;
        std::filesystem::remove(output_path, ec);
        std::filesystem::rename(call.part_path, output_path, ec);
        if (ec) {
            spdlog::warn("Cannot commit lua chunk dump {} -> {}: {}", call.part_path,
                         output_path, ec.message());
        } else {
            sink.size = call.call_bytes;
        }
    } else {
        std::error_code ec;
        std::filesystem::remove(call.part_path, ec);
    }
    sink.last_payload = call.call_bytes;
}

void InitDumpConfig() {
    std::string raw;
    {
        InjectorConfig::EnvOrCmdOptValue dump_opts{"dump_lua_mods"};
        if (const char *value = static_cast<const char *>(dump_opts); value && *value) {
            raw = value;
        }
    }
    std::string_view sv{raw};
    size_t start = 0;
    while (start <= sv.size()) {
        size_t sep = sv.find(';', start);
        if (sep == std::string_view::npos) {
            sep = sv.size();
        }
        auto part = sv.substr(start, sep - start);
        if (!part.empty()) {
            g_dump_mod_names.emplace_back(part);
        }
        if (sep == sv.size()) {
            break;
        }
        start = sep + 1;
    }
    g_dump_enabled = !g_dump_mod_names.empty();
    if (!g_dump_enabled) {
        return;
    }
    // Reset the dump tree once per process, not per Lua state. The engine creates several
    // states and each one re-loads the mods, so wiping per state erased earlier dumps.
    std::lock_guard guard{g_dump_mutex};
    g_dump_sinks.clear();
    std::filesystem::remove_all(kDumpOutputDir);
}

} // namespace

namespace ds::core_vm::detail {

bool LuaModDumpEnabled() {
    std::call_once(g_dump_init_once, InitDumpConfig);
    return g_dump_enabled;
}

const std::vector<std::string> &LuaModDumpModNames() {
    std::call_once(g_dump_init_once, InitDumpConfig);
    return g_dump_mod_names;
}

bool LuaModDumpShouldDump(const char *chunkname) {
    if (!LuaModDumpEnabled()) {
        return false;
    }
    std::string_view name{chunkname ? chunkname : ""};
    for (const auto &modname: g_dump_mod_names) {
        if (name.find(modname) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

const char *LuaModDumpReader(lua_State *L, void *ud, size_t *sz) {
    auto *call = static_cast<LuaModDumpCall *>(ud);
    auto buf = call->reader(L, call->data, sz);
    if (buf && *sz > 0) {
        WriteChunkPiece(*call, buf, *sz);
    } else {
        FinishChunkDump(*call);
    }
    return buf;
}

} // namespace ds::core_vm::detail

struct GameLuaContextGame : GameLua51Context {
    GameLuaContextGame(GameLuaType type)
        : GameLua51Context{"<Game>", type} {
        find_export_by_name = &GameFindExportByName;
    }
    virtual ~GameLuaContextGame() = default;
    bool LoadLuaModule() override {
        // game lua module is already loaded by game
        interceptor = InjectorCtx::instance()->GetGumInterceptor();
        LuaModule = gum_process_get_main_module();
        return true;
    }
    void luaL_openlibs_hooker(lua_State *L) override {
        if (InjectorConfig::instance()->enable_lua_debugger) {
            LuaStackGuard guard(*this, L);
            auto handler = dontstarveinjector::lua_debugger_helper::initialize_lua_debugger();
            auto so_path = getenv(LUA_DEBUG_CORE_DEBUGGER);
            if (so_path) {
                void **lib = ll_register(L, so_path);
                if (lib)
                    *lib = handler;
                else {
                    spdlog::warn("Cannot register lua debugger api");
                }
                api._lua_pop(L, 1);
            } else {
                spdlog::warn("LUA_DEBUG_CORE_DEBUGGER is not set, cannot register lua debugger api");
            }
        }
        GameLua51Context::luaL_openlibs_hooker(L);
        for (const auto &modname: ds::core_vm::detail::LuaModDumpModNames()) {
            gameLuaInjectorFramework.forceEnabledLuaMod(*this, L, modname);
        }
    }


    void LoadMyLuaApi() override {
        GameLua51Context::LoadMyLuaApi();
        // The engine's own lua_setfield / lua_getfield are used directly (no interception).
        api._luaL_register = +[](lua_State *L, const char *libname, const luaL_Reg *l) {
            return GetGameLuaContext()->_luaL_openlib(L, libname, l, 0);
        };
        api._lua_setallocf = +[](lua_State *L, lua_Alloc f, void *ud) {
            return lua51_setallocf(L, f, ud);
        };
        api._lua_getallocf = +[](lua_State *L, void **ud) {
            return lua51_getallocf(L, ud);
        };
        api._lua_sethook = +[](lua_State *L, lua_Hook hook, int mask, int count) {
            return lua51_sethook(L, hook, mask, count);
        };
        api._lua_gethookcount = +[](lua_State *L) {
            return lua51_gethookcount(L);
        };
        // api._lua_gethookmask = +[](lua_State *L) {
        //     return lua51_gethookmask(L);
        // };
        api._lua_getlocal = +[](lua_State *L, const lua_Debug *ar, int n) {
            return lua51_getlocal(L, ar, n);
        };
        api._lua_setlocal = +[](lua_State *L, const lua_Debug *ar, int n) {
            return lua51_setlocal(L, ar, n);
        };
        // api._luaL_addstring = +[](luaL_Buffer *B, const char *s) {
        //     return lua51L_addstring(B, s);
        // };
        // api._luaL_loadfile = +[](lua_State *L, const char *filename) {
        //     return lua51L_loadfile(L, filename);
        // };
        // api._luaL_typerror = +[](lua_State *L, int narg, const char *tname) {
        //     return lua51L_typerror(L, narg, tname);
        // };
        // api._lua_cpcall = +[](lua_State *L, lua_CFunction func, void *ud) {
        //     return lua51_cpcall(L, func, ud);
        // };
        // api._lua_isuserdata = +[](lua_State *L, int idx) {
        //     return lua51_isuserdata(L, idx);
        // };
        // api._lua_setlevel = +[](lua_State *L, int level) {
        //     return lua51_setlevel(L, level);
        // };

        // HOOK_LUA_API(luaL_error) + [](lua_State *L, const char *fmt, ...) {
        //     auto &ctx = static_cast<GameLuaContextGame &>(GetGameLuaContext());
        //     va_list argp;
        //     va_start(argp, fmt);
        //     ctx->_luaL_where(L, 1);
        //     ctx->_lua_pushvfstring(L, fmt, argp);
        //     va_end(argp);
        //     ctx->_lua_concat(L, 2);
        //     spdlog::error("Lua Error: {}", ctx->_lua_tostring(L, -1));
        //     return ctx->_lua_error(L);
        // };
        // HOOK_LUA_API(lua_load) + [](lua_State *L, lua_Reader reader, void *data,
        //                             const char *chunkname) {
        //     auto ctx = static_cast<GameLuaContextGame *>(&GetGameLuaContext());
        //     return ctx->api._lua_load(L, reader, data, chunkname);
        // };
        if (!ds::core_vm::detail::LuaModDumpEnabled()) return;
        // game mode (engine 5.1): every buffer/file load funnels into lua_load.
        // The wrapper carries the caller's reader data (non-null for the engine's
        // lauxlib paths), so buffer/file loads are dumped too, not just reader-less ones.
        HOOK_LUA_API(lua_load) + [](lua_State *L, lua_Reader reader, void *data,
                                    const char *chunkname) {
            if (!ds::core_vm::detail::LuaModDumpShouldDump(chunkname)) {
                return (*currentCtx)->_lua_load(L, reader, data, chunkname);
            }
            // One wrapper per lua_load call. Obfuscated mod loaders re-enter lua_load while
            // this call is still draining its reader (the reader is backed by Lua), and a
            // shared/thread_local wrapper would be cleared mid-drain — losing every piece
            // but the last, which is how a dump ends up holding just the file tail. The
            // nested call builds its own wrapper and dumps its own chunk.
            ds::core_vm::detail::LuaModDumpCall call;
            call.reader = reader;
            call.data = data;  // caller's data, captured before forwarding our wrapper
            call.chunkname = chunkname;
            return (*currentCtx)->_lua_load(L, &ds::core_vm::detail::LuaModDumpReader, &call,
                                           chunkname);
        };
    }

    void **ll_register(lua_State *L, const char *path) {
        void **plib;
#define LIBPREFIX "LOADLIB: "
        api._lua_pushfstring(L, "%s%s", LIBPREFIX, path);
        api._lua_gettable(L, LUA_REGISTRYINDEX); /* check library in registry? */
        if (!api._lua_isnil(L, -1))              /* is there an entry? */
            plib = (void **) api._lua_touserdata(L, -1);
        else { /* no entry yet; create one */
            api._lua_pop(L, 1);
            plib = (void **) api._lua_newuserdata(L, sizeof(const void *));
            *plib = NULL;
            api._luaL_getmetatable(L, "_LOADLIB");
            api._lua_setmetatable(L, -2);
            api._lua_pushfstring(L, "%s%s", LIBPREFIX, path);
            api._lua_pushvalue(L, -2);
            api._lua_settable(L, LUA_REGISTRYINDEX);
        }
        return plib;
    }

    bool ReplaceApis(const Signatures &signatures, const ListExports_t &exports) override {
        (void) signatures;
        (void) exports;
        if (!interceptor) {
            interceptor = InjectorCtx::instance()->GetGumInterceptor();
        }
        for (auto &[name, newaddr]: overrideapis) {
            auto **api = name2apis.at(name);
            if (!api || *api == nullptr) {
                spdlog::error("Cannot find api pointer for {}", name);
                ResetApis(signatures, exports);
                return false;
            }
            if ((void *) *api == newaddr) {
                spdlog::info("skip replace {}: replacer equals target", name);
                continue;
            }
            // The field must hold a callable that bypasses this hook (Gum's trampoline): the
            // engine's own native entry is the very address hooked here, so forwarding through
            // the raw field would re-enter this replacement.
            const bool isVmAnchor = (name == "lua_newstate");
            void *original = nullptr;
            auto rc = ds::FastHook::Install(interceptor, *api, newaddr, (void **) &original);
            if (rc == GumReplaceReturn::GUM_REPLACE_ALREADY_REPLACED && isVmAnchor) {
                // The anchor is deliberately kept installed across VM switches: tearing it down
                // would open a window where the engine calls the native entry directly. Refresh
                // the field from the cached trampoline -- a previous VM may have left its own
                // wrapper there, which would recurse into this replacement.
                if (auto *native = ds::core_vm::detail::native_new_state()) {
                    *api = (void *) native;
                } else {
                    spdlog::error("VM anchor has no cached native trampoline");
                    ResetApis(signatures, exports);
                    return false;
                }
                spdlog::info("keep VM anchor {} hook (already installed by a previous VM)", name);
                continue;
            }
            if (rc == GumReplaceReturn::GUM_REPLACE_ALREADY_REPLACED) {
                // A previous VM left its replacement in place: drop it first, otherwise the new
                // replacement would be layered on an already patched prologue.
                if (!ds::FastHook::Revert(interceptor, *api)) {
                    spdlog::error("Cannot restore previous fast hook for {}", name);
                    ResetApis(signatures, exports);
                    return false;
                }
                rc = ds::FastHook::Install(interceptor, *api, newaddr, (void **) &original);
            }
            if (rc != GumReplaceReturn::GUM_REPLACE_OK) {
                spdlog::error("Replaced game lua api {} failed: {}", name, (int) rc);
                ResetApis(signatures, exports);
                return false;
            }
            if (!isVmAnchor) {
                // Restore API fields only after their installed entry hooks are gone.
                apiFieldOriginals.emplace_back(api, *api);
            }
            replacedTargets.push_back(*api);
            *api = original;
            if (isVmAnchor) {
                anchorTargets.push_back(*(replacedTargets.end() - 1));
                ds::core_vm::detail::set_native_new_state((ds::core_vm::detail::LuaNewStateFn) original);
            }
            spdlog::info("Replaced game lua api {}: site={} field={} to {}{}", name,
                         (void *) *(replacedTargets.end() - 1), (void *) *api, (void *) newaddr,
                         isVmAnchor ? "  [VM anchor]" : "");
        }
        return true;
    }

    void ResetApis(const Signatures &signatures, const ListExports_t &exports) override {
        GameLua51Context::ResetApis(signatures, exports);
        if (!interceptor) {
            interceptor = InjectorCtx::instance()->GetGumInterceptor();
        }
        if (!interceptor) {
            spdlog::warn("Game lua interceptor is not initialized, skip reverting game lua hooks");
            return;
        }
        if (!replacedTargets.empty()) {
            spdlog::error("Game lua api entries still hooked; retain original api fields for retry");
            return;
        }
        for (auto &[field, value]: apiFieldOriginals) {
            *field = value;
        }
        apiFieldOriginals.clear();
        replacedTargets.clear();
    }

    static GumAddress GameFindExportByName(GumModule *self, const gchar *symbol_name);
    std::unordered_map<std::string, GumAddress> exports;
    GumInterceptor *interceptor = nullptr;
};


static GameLuaContextGame gameLuaGameCtx{
        GameLuaType::game};

namespace ds::core_vm::detail {
GameLuaContextImpl *ctx_game() { return &gameLuaGameCtx; }
void NoteGameLuaExport(const std::string &name, GumAddress addr) {
    gameLuaGameCtx.exports[name] = addr;
}
void NoteGameLuaExportsForDebugSymbols() {
#if defined(WIN32) && !defined(NDEBUG)
    auto hProcess = GetCurrentProcess();
    BOOL initSuccess = SymInitialize(hProcess, NULL, TRUE);
    if (initSuccess) {
        ULONG64 moduleBase = (ULONG64) GetModuleHandleA(NULL);
        for (auto &[name, addr]: gameLuaGameCtx.exports) {
            const char *symbolName = name.c_str();
            DWORD64 symbolAddress = addr;
            DWORD symbolSize = 0;
            DWORD flags = 0;
            BOOL addSuccess = SymAddSymbol(hProcess, moduleBase, symbolName, symbolAddress, symbolSize, flags);
            if (!addSuccess) {
                spdlog::error("Failed to add symbol [{}]: {}", name, GetLastError());
            }
        }
    }
#endif
}
} // namespace ds::core_vm::detail

GumAddress GameLuaContextGame::GameFindExportByName(GumModule *self, const gchar *symbol_name) {
    GameLuaContextGame &ctx = static_cast<GameLuaContextGame &>(GetGameLuaContext());
    if (ctx.luaType != GameLuaType::game) {
        spdlog::error("GameFindExportByName: invalid lua type");
        return 0;
    }
    if (ctx.exports.empty()) {
        spdlog::error("GameFindExportByName: exports is null");
        return 0;
    }
    auto iter = ctx.exports.find({symbol_name});
    if (iter != ctx.exports.end()) {
        return iter->second;
    }
    spdlog::error("GameFindExportByName: export {} not found", symbol_name);
    return 0;
}
