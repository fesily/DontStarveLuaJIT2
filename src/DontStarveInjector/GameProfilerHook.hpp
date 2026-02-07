#include "config.hpp"
#include "MemorySignature.hpp"
#include "util/inlinehook.hpp"
#include "GameLua.hpp"
#include <frida-gum.h>
#include <list>
#include <string>
#include <filesystem>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <thread>
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
#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#elif defined(__APPLE__)
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <unistd.h>
#include <fstream>
#endif

static uint64_t get_time_ns() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}
struct Profiler {
    std::list<TracyCZoneCtx> ctx;
    uint64_t start_time_ns;
    int stack;
    lua_State *L;
};
static thread_local Profiler profiler;
extern void (*lua_gc_func)(void *L, int, int);
static int frame_gc_time_ns = 0;
static bool tracy_active = 0;
extern float frame_time_s;
constexpr auto frame_gc_time_default_ns = 10 * 1e3;
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_enable_framegc(bool enable) {
    frame_gc_time_ns = enable ? frame_time_s * 1e9 : frame_gc_time_default_ns;
    return frame_gc_time_ns == frame_gc_time_default_ns;
}
static thread_local std::string thread_name;
static void set_thread_name(uint32_t thread_id, const char *name) {
    thread_name = name;
#ifdef _WIN32
    SetThreadDescription(GetCurrentThread(), std::filesystem::path{thread_name}.c_str());
#elif defined(__linux__)
    pthread_setname_np(pthread_self(), thread_name.c_str());
#else
    pthread_setname_np(thread_name.c_str());
#endif
}

static void repalce_set_thread_name() {
#ifdef _WIN32
    function_relocation::MemorySignature set_thread_name_func{"B9 88 13 6D 40", -0x24};
    if (set_thread_name_func.scan(gum_module_get_path(gum_process_get_main_module()))) {
        Hook((uint8_t *) set_thread_name_func.target_address, (uint8_t *) &set_thread_name);
    }
#endif
}

static int64_t hook_profiler_push(void *self, const char *zone, const char *source, int line) {
    using namespace std::literals;
    bool is_connected = tracy_active;
    auto &p = profiler;
    if ("Update"sv == zone) {
        if (frame_gc_time_ns) {
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
                if (count >= 600 && thread_id_count.vaild.compare_exchange_strong(except, true, std::memory_order_relaxed)) {
                    set_thread_name(0, "SimUpdateThread");
                    thread_id_count.vaild.store(true, std::memory_order_relaxed);
                }
            }

            if (thread_name == "SimUpdateThread"sv)
                p.start_time_ns = get_time_ns();
        }
        if (is_connected)
            ___tracy_emit_frame_mark(0);
    }
    p.stack++;
    if (!is_connected)
        return 0;
    auto v = ___tracy_alloc_srcloc_name(line, source, strlen(source), 0, 0, zone, strlen(zone), 0);
    if (v) {
        auto k = ___tracy_emit_zone_begin_alloc(v, tracy_active);
        p.ctx.emplace_back(k);
    }
    return 0;
}
template<typename T>
struct ProfilerHookerBase {

    static int64_t hook_profiler_pop(void *self) {
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
                constexpr float frame_max_time_ns = 33 * 1e6;
                constexpr float frame_good_max_time_ns = 20 * 1e6;
                auto &p = profiler;
                auto now = get_time_ns();
                auto used_time = float(now - p.start_time_ns);
                int left_time_ns = frame_gc_time_ns - used_time;
                if (used_time > frame_max_time_ns) {
                    left_time_ns = 0;
                } else if (left_time_ns > frame_good_max_time_ns) {
                    left_time_ns = frame_gc_time_default_ns;
                }
                p.start_time_ns = 0;
                if (left_time_ns > 0) {
                    T::GC(p.L, left_time_ns, now);
                }
            } else {
                p.start_time_ns = 0;
            }
        }
        if (!tracy_active)
            return 0;
        if (!profiler.ctx.empty()) {
            auto k = p.ctx.back();
            p.ctx.pop_back();
            ___tracy_emit_zone_end(k);
        }
        return 0;
    }
};

struct ProfilerHookerTimeLimit : ProfilerHookerBase<ProfilerHookerTimeLimit> {
    inline static void GC(void *L, int left_time, uint64_t now) {
        ZoneScopedN("frame gc");
        lua_gc_func(L, LUA_GCSTEPTIME, int(left_time * 0.8f));
        lua_gc_func(L, LUA_GCSTEP2, 0);
    }
};

struct ProfilerHookerNoTimeLimit : ProfilerHookerBase<ProfilerHookerNoTimeLimit> {
    inline static void GC(void *L, int left_time, uint64_t now) {
        now += left_time;
        ZoneScopedN("frame gc");
        do {
            lua_gc_func(L, LUA_GCSTEP, 0);
        } while (get_time_ns() < now);
    }
};


extern void gum_luajit_profiler_update_thread_id(lua_State *target_L, GumThreadId id);
void lua_event_notifyer(LUA_EVENT ev, lua_State *L) {
    switch (ev) {
        case LUA_EVENT::new_state:
            profiler.L = 0;
            break;
        case LUA_EVENT::close_state:
            profiler.L = 0;
            //gum_luajit_profiler_update_thread_id(nullptr, gum_process_get_current_thread_id());
            return;
        case LUA_EVENT::call_lua_gc:
            profiler.L = profiler.start_time_ns ? L : 0;
            break;
    }
    //gum_luajit_profiler_update_thread_id(L, gum_process_get_current_thread_id());
}
//#define profiler_lua_gc 0
#ifdef profiler_lua_gc
#include "util/InvocationListener.hpp"
struct InvocationListenerProfiler : InvocationListener {
    virtual ~InvocationListenerProfiler() {}

    virtual void on_enter(GumInvocationContext *context) {
        hook_profiler_push(0, (const char *) gum_invocation_context_get_listener_function_data(context), "", 0);
    };
    virtual void on_leave(GumInvocationContext *context) {
        hook_profiler_pop(0);
    };
};
#endif