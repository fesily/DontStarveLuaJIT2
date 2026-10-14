// plugin_debug_profiler — replace_profiler / tracy / framegc API bodies (Task 2).
#include "GameProfilerHook.hpp"

#include "config/InjectorHostConfig.hpp"
#include "util/LinuxGameSignatures.hpp"

#include <atomic>
#include <frida-gum.h>
#include "util/frida_gum_interceptor.hpp"

bool tracy_active = false;

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_replace_profiler_api() {
    static std::atomic_char replaced;
    if (replaced) {
        return 1;
    }
#ifdef __linux__
    // GCC 9 splits FrameProfiler::Push into an enabled-check wrapper and a
    // .part.0 body, plus a constant-propagated singleton wrapper. Both callers
    // keep zone/source/line in rsi/rdx/ecx. Hook both wrappers so disabled stock
    // profiling still reaches our replacement. Resolve through FDE ranges.
    function_relocation::MemorySignature profiler_push{ds::linux_signatures::profiler_push, 0};
    function_relocation::MemorySignature profiler_pop{ds::linux_signatures::profiler_pop, 0};
    function_relocation::MemorySignature profiler_push_singleton{ds::linux_signatures::profiler_push_singleton, 0};
#elif defined(__APPLE__)
    function_relocation::MemorySignature profiler_push{"41 83 84 24 80 01 00 00 01", -0xF6};
    function_relocation::MemorySignature profiler_pop{"64 48 8B 1C 25 F8 FF FF FF", -0x15};
    return 0;// TODO
#elif defined(_WIN32)
    function_relocation::MemorySignature profiler_push{"44 8B 9B 88 02 00 00", -0x175};
    function_relocation::MemorySignature profiler_pop{"81 7F 1C 00 3C 00 00", -0x7D};
#else
    return 0;
#endif

#if !defined(__APPLE__)
    auto path = gum_module_get_path(gum_process_get_main_module());
#ifdef __linux__
    if (!profiler_push_singleton.scan_function(path)) return 0;
#endif
    const bool found =
#ifdef __linux__
            profiler_pop.scan_function(path) && profiler_push.scan_function(path);
#else
            profiler_pop.scan(path) && profiler_push.scan(path);
#endif
    if (found) {
        const bool push_ok = Hook((uint8_t *) profiler_push.target_address, (uint8_t *) hook_profiler_push);
#ifdef __linux__
        const bool singleton_ok = Hook((uint8_t *) profiler_push_singleton.target_address, (uint8_t *) hook_profiler_push);
#else
        const bool singleton_ok = true;
#endif
        const bool pop_ok = Hook((uint8_t *) profiler_pop.target_address, (uint8_t *) ProfilerHooker::hook_profiler_pop);
        if (!push_ok || !singleton_ok || !pop_ok) {
            if (push_ok) ResetHook((uint8_t *) profiler_push.target_address);
#ifdef __linux__
            if (singleton_ok) ResetHook((uint8_t *) profiler_push_singleton.target_address);
#endif
            if (pop_ok) ResetHook((uint8_t *) profiler_pop.target_address);
            return 0;
        }
#ifdef profiler_lua_gc
        auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
        static Gum::InvocationListenerProxy linstener{new Gum::InvocationListenerProfiler()};
        ds::gum::attach(interceptor, (void *) get_luajit_address("lua_gc"),
                        GUM_INVOCATION_LISTENER(linstener.cproxy), (void *) "lua_gc");
#endif
        replaced = 1;
    }
    return replaced;
#endif
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_enable_tracy(int en) {
    tracy_active = en != 0;
}
