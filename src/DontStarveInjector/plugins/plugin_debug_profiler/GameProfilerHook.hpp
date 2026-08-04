#pragma once
// plugin_debug_profiler — Tracy / FrameGC / profiler push-pop hooks (Task 2).
// FullGcPolicy ownership lands in Task 3; local fullgc statics are temporary.
#include "config.hpp"
#include "MemorySignature.hpp"
#include "util/inlinehook.hpp"
#include "GameLua.hpp"
#include "core/GameLuaContextResolve.hpp"
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#else
#include <dlfcn.h>
#endif
#include <frida-gum.h>
#include <list>
#include <string>
#include <filesystem>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <chrono>
#include <cstring>
#include <lua.hpp>
#ifndef DISABLE_TRACY_FUTURE
#include <tracy/TracyC.h>
#include <tracy/Tracy.hpp>
#else
#define ___tracy_emit_frame_mark(...) 0
#define ___tracy_alloc_srcloc_name(...) 0
#define ___tracy_emit_zone_begin_alloc(...) 0
#define ___tracy_emit_zone_end(...) 0
typedef uint32_t TracyCZoneCtx;
#define ZoneScopedN(...) 0
#endif
#if defined(__APPLE__)
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <unistd.h>
#include <pthread.h>
#endif

static uint64_t get_time_ns() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

struct Profiler {
    std::list<TracyCZoneCtx> ctx;
    uint64_t start_time_ns = 0;
    int stack = 0;
    lua_State *L = nullptr;
};
static thread_local Profiler profiler;

// Temporary until Task 3 merges FullGcPolicy — same-DLL statics OK.
// Do not call core.vm for fullgc in Task 2.
static int fullgc_deferred = 0;
static int fullgc_deferred_get() { return fullgc_deferred; }
static void fullgc_deferred_set(int v) { fullgc_deferred = v; }
static int fullgc_deferred_inc() { return ++fullgc_deferred; }

// Optional lua_gc entry from core.vm (soft). Used by FrameGC TryDoGC only.
static int (*ResolveLuaGcFunc())(void *L, int, int) {
    using LuaGc = int (*)(void *, int, int);
    using Getter = LuaGc *(*)();
#ifdef _WIN32
    HMODULE m = GetModuleHandleA("plugin_core_vm.dll");
    if (!m) {
        return nullptr;
    }
    auto g = reinterpret_cast<Getter>(GetProcAddress(m, "ds_core_vm_lua_gc_func_ptr"));
#else
    auto g = reinterpret_cast<Getter>(dlsym(RTLD_DEFAULT, "ds_core_vm_lua_gc_func_ptr"));
#endif
    if (!g) {
        return nullptr;
    }
    LuaGc *pp = g();
    return pp ? *pp : nullptr;
}

static int frame_gc_time_ns = 0;
static bool enable_frame_gc = false;
// Defined in ProfilerApi.cpp (non-static so enable_tracy can set it).
extern bool tracy_active;

// Injector export — avoid importing mutable frame_time_s across DLL boundary.
DONTSTARVEINJECTOR_API float DS_LUAJIT_get_frame_time_s(void);

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_enable_framegc(bool enable) {
    if (auto *ctx = ds::core_vm::TryGetGameLuaContext()) {
        if (ctx->luaType == GameLuaType::jit_gen) {
            frame_gc_time_ns = 0;
            return false;
        }
    }
    enable_frame_gc = enable;
    frame_gc_time_ns = static_cast<int>(DS_LUAJIT_get_frame_time_s() * 1e9f);
    return enable_frame_gc;
}

static thread_local std::string thread_name;
static void set_thread_name(uint32_t /*thread_id*/, const char *name) {
    thread_name = name;
#ifdef _WIN32
    SetThreadDescription(GetCurrentThread(), std::filesystem::path{thread_name}.c_str());
#elif defined(__linux__)
    pthread_setname_np(pthread_self(), thread_name.c_str());
#else
    pthread_setname_np(thread_name.c_str());
#endif
}

static int64_t hook_profiler_push(void * /*self*/, const char *zone, const char *source, int line) {
    using namespace std::literals;
    bool is_connected = tracy_active;
    auto &p = profiler;
    if ("Update"sv == zone) {
        if (frame_gc_time_ns || fullgc_deferred_get()) {
            static struct {
                std::atomic_bool vaild;
                std::mutex mtx;
                std::unordered_map<std::thread::id, int> count_map;
            } thread_id_count;
            if (!thread_id_count.vaild.load(std::memory_order_relaxed)) {
                auto tid = std::this_thread::get_id();
                std::unique_lock<std::mutex> lock(thread_id_count.mtx);
                auto &count = thread_id_count.count_map[tid];
                lock.unlock();
                count++;
                bool except = false;
                if (count >= 600 &&
                    thread_id_count.vaild.compare_exchange_strong(except, true, std::memory_order_relaxed)) {
                    set_thread_name(0, "SimUpdateThread");
                    thread_id_count.vaild.store(true, std::memory_order_relaxed);
                }
            }

            if (thread_name == "SimUpdateThread"sv) {
                p.start_time_ns = get_time_ns();
            }
        }
        if (is_connected) {
            ___tracy_emit_frame_mark(0);
        }
    }
    p.stack++;
    if (!is_connected) {
        return 0;
    }
    auto v = ___tracy_alloc_srcloc_name(line, source, strlen(source), 0, 0, zone, strlen(zone), 0);
    if (v) {
        auto k = ___tracy_emit_zone_begin_alloc(v, tracy_active);
        p.ctx.emplace_back(k);
    }
    return 0;
}

struct ProfilerHooker {

    static int64_t hook_profiler_pop(void * /*self*/) {
        auto &p = profiler;
        --p.stack;
        if (p.stack < 0) {
            p.stack = 0;
        } else if (p.stack == 0 && p.start_time_ns) {
            if (p.L) {
                /*
                    Performce one update time range
                    < 20ms: good
                    < 33ms: normal
                    >= 33ms: bad
                */
                constexpr int frame_max_time_ns = 33 * 1e6;
                constexpr int frame_good_max_time_ns = 20 * 1e6;
                auto now = get_time_ns();
                auto used_time = int(now - p.start_time_ns);
                int left_time_ns = frame_gc_time_ns - used_time;
                if (used_time > frame_max_time_ns) {
                    left_time_ns = 0;
                } else if (left_time_ns > frame_good_max_time_ns && fullgc_deferred_get() == 0) {
                    left_time_ns = 0;
                }
                p.start_time_ns = 0;
                if (left_time_ns > 0) {
                    TryDoGC(p.L, left_time_ns, now);
                }
            } else {
                p.start_time_ns = 0;
            }
        }
        if (!tracy_active) {
            return 0;
        }
        if (!profiler.ctx.empty()) {
            auto k = p.ctx.back();
            p.ctx.pop_back();
            ___tracy_emit_zone_end(k);
        }
        return 0;
    }

    static void TryDoGC(void *L, int left_time, uint64_t now) {
        auto *gctx = ds::core_vm::TryGetGameLuaContext();
        if (!gctx) {
            return;
        }
        auto luatype = gctx->luaType;
        ZoneScopedN("frame gc");
        if (luatype == GameLuaType::jit_gen) {
            return;
        }
        switch (luatype) {
        case GameLuaType::jit: {
            if (auto *gc = ResolveLuaGcFunc()) {
                gc(L, LUA_GCSTEPTIME, int(left_time * 0.8f));
            }
            if (auto *gc = ResolveLuaGcFunc()) {
                gc(L, LUA_GCSTEP2, 0);
            }
            static int lua_gccycle_count = 0;
            auto *gc = ResolveLuaGcFunc();
            auto lua_gccycle = gc ? gc(L, LUA_GCCYCLE, 0) : 0;
            if (lua_gccycle_count != lua_gccycle) {
                lua_gccycle_count = lua_gccycle;
                fullgc_deferred_inc();
                if (fullgc_deferred_get() > 2) {
                    fullgc_deferred_set(0); /* 两个周期完成，退出延迟模式 */
                }
            }
            break;
        }
        case GameLuaType::game:
            // nothing to do
            break;
        default:
            now += left_time;
            do {
                if (auto *gc = ResolveLuaGcFunc()) {
                    gc(L, LUA_GCSTEP, 0);
                }
            } while (get_time_ns() < now);
            break;
        }
    }
};

// core.vm still dllimports lua_event_notifyer from Injector; Injector forwards here.
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_profiler_lua_event_notifyer(int ev, lua_State *L) {
    switch (static_cast<LUA_EVENT>(ev)) {
    case LUA_EVENT::new_state:
        profiler.L = nullptr;
        break;
    case LUA_EVENT::close_state:
        profiler.L = nullptr;
        return;
    case LUA_EVENT::call_lua_gc:
        profiler.L = profiler.start_time_ns ? L : nullptr;
        break;
    }
}
