#include "config.hpp"
#include "MemorySignature.hpp"
#include "util/inlinehook.hpp"
#include <frida-gum.h>
#include <list>
#include <string>
#include <filesystem>
#include <atomic>
#include <unordered_map>
#include <mutex>
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

static uint64_t get_time_ms() {
#ifdef _WIN32
    uint64_t ticks = __rdtsc();
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    return (ticks / freq.QuadPart) * 1000; // 时钟周期转换为毫秒
#elif defined(__APPLE__)
    // macOS (ARM): 使用 mach_absolute_time 获取高精度时间
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t ticks = mach_absolute_time();
    return (ticks * timebase.numer / timebase.denom) / 1e6; // 纳秒转换为毫秒
#elif defined(__linux__)
    // Linux (ARM): 使用 clock_gettime 获取高精度时间
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1e6; // 秒和纳秒转换为毫秒
#else
    #error "not support"
    return 0;
#endif
}
struct Profiler {
    std::list<TracyCZoneCtx> ctx;
    uint64_t start_time;
    int stack;
    lua_State* L;
};
static thread_local Profiler profiler;
extern void (* lua_gc_func)(void *L, int,int);
static float frame_gc_time = 0;
static bool tracy_active = 0;
extern "C" DONTSTARVEINJECTOR_API int DS_LUAJIT_set_frame_gc_time(int ms) {
    frame_gc_time = (float)std::min(ms, 30);
    return (int)frame_gc_time;
}
static thread_local std::string thread_name;
static void set_thread_name(uint32_t thread_id, const char* name) {
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
        Hook((uint8_t*)set_thread_name_func.target_address, (uint8_t*)&set_thread_name);
    }
#endif
}
extern float frame_time;
static int64_t hook_profiler_push(void* self, const char* zone, const char* source, int line) {
    using namespace std::literals;
    bool is_connected = tracy_active;
    auto& p = profiler;
    if ("Update"sv == zone) {
        if (frame_gc_time) {
            static struct {
                std::atomic_bool vaild;
                std::mutex mtx;
                std::unordered_map<std::thread::id, int> count_map;
            } thread_id_count;
            if (!thread_id_count.vaild.load(std::memory_order_relaxed)) {
                auto tid = std::this_thread::get_id();
                std::unique_lock<std::mutex> lock(thread_id_count.mtx);
                auto& count = thread_id_count.count_map[tid];
                lock.unlock();
                count++;
                bool except = false;
                if (count >= 600 && thread_id_count.vaild.compare_exchange_strong(except, true, std::memory_order_relaxed)){
                    set_thread_name(0, "SimUpdateThread");
                    thread_id_count.vaild.store(true, std::memory_order_relaxed);
                }
            }

            if (thread_name == "SimUpdateThread"sv)
                p.start_time = get_time_ms();
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

static int64_t hook_profiler_pop(void* self) {
    auto& p = profiler;
    --p.stack;
    if (p.stack < 0) {
        p.stack = 0;
    } else if (p.stack == 0 && p.start_time) {
        auto now = get_time_ms();
        auto left_time = std::min<float>(frame_time - float(now - p.start_time), frame_gc_time);
        p.start_time = 0;
        if (left_time > 0) {
            now += left_time;
            if (p.L) {
                ZoneScopedN("frame gc");
                auto L = p.L;
                p.L = 0;
                do
                {
                    lua_gc_func(L, 5, 0);
                } while (get_time_ms() < now);
            }
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
extern void gum_luajit_profiler_update_thread_id(lua_State *target_L, GumThreadId id);
void lua_event_notifyer(LUA_EVENT ev, lua_State * L) {
    switch (ev) {
        case LUA_EVENT::new_state:
            profiler.L = 0;
            break;
        case LUA_EVENT::close_state:
            profiler.L = 0;
            //gum_luajit_profiler_update_thread_id(nullptr, gum_process_get_current_thread_id());
            return;
        case LUA_EVENT::call_lua_gc:
            profiler.L = profiler.start_time ? L : 0;
            break;
    }
    //gum_luajit_profiler_update_thread_id(L, gum_process_get_current_thread_id());
}
//#define profiler_lua_gc 0
#ifdef profiler_lua_gc
#include "util/InvocationListener.hpp"
    struct InvocationListenerProfiler: InvocationListener {
        virtual ~InvocationListenerProfiler () {}

        virtual void on_enter (GumInvocationContext * context) {
            hook_profiler_push(0, (const char*)gum_invocation_context_get_listener_function_data(context), "", 0);
        };
        virtual void on_leave (GumInvocationContext * context) {
            hook_profiler_pop(0);
        };
    };
#endif