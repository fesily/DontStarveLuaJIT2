// plugin_debug_profiler — replace_profiler / tracy / framegc API bodies (Task 2).
#include "GameProfilerHook.hpp"

#include "config/InjectorHostConfig.hpp"
#include "ProfilerSignatures.hpp"
#include "core/SignatureResolveApi.hpp"

#include <atomic>
#include <frida-gum.h>
#include "util/frida_gum_interceptor.hpp"

bool tracy_active = false;

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_replace_profiler_api() {
    static std::atomic_char replaced;
    if (replaced) {
        return 1;
    }
#if !defined(_WIN32) && !defined(__linux__)
    // macOS (and anything else): the FrameProfiler shapes are not modelled yet.
    // Not registering a definition is what keeps this an explicit "unsupported"
    // instead of a pattern that silently never matches.
    return 0;
#else
    // GCC 9 splits FrameProfiler::Push into an enabled-check wrapper and a
    // .part.0 body, plus a constant-propagated singleton wrapper. Both callers
    // keep zone/source/line in rsi/rdx/ecx, so both wrappers are hooked; the
    // Linux definitions resolve through their exact FDE ranges.
    ds::sig::ResolveReport push{};
    ds::sig::ResolveReport pop{};
    ds::sig::ResolveReport singleton{};
    const bool has_push = ds::sig::host_resolve("debug.profiler.push", &push) && push.target_va != 0;
    const bool has_pop = ds::sig::host_resolve("debug.profiler.pop", &pop) && pop.target_va != 0;
#ifdef __linux__
    const bool has_singleton =
            ds::sig::host_resolve("debug.profiler.push_singleton", &singleton) && singleton.target_va != 0;
    if (!has_singleton) {
        return 0;
    }
#else
    const bool has_singleton = false;
#endif
    if (!has_push || !has_pop) {
        return 0;
    }
    const bool push_ok = Hook((uint8_t *) push.target_va, (uint8_t *) hook_profiler_push);
#ifdef __linux__
    const bool singleton_ok = Hook((uint8_t *) singleton.target_va, (uint8_t *) hook_profiler_push);
#else
    const bool singleton_ok = true;
#endif
    const bool pop_ok = Hook((uint8_t *) pop.target_va, (uint8_t *) ProfilerHooker::hook_profiler_pop);
    if (!push_ok || !singleton_ok || !pop_ok) {
        if (push_ok) ResetHook((uint8_t *) push.target_va);
#ifdef __linux__
        if (singleton_ok) ResetHook((uint8_t *) singleton.target_va);
#endif
        if (pop_ok) ResetHook((uint8_t *) pop.target_va);
        return 0;
    }
#ifdef profiler_lua_gc
    auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
    static Gum::InvocationListenerProxy linstener{new Gum::InvocationListenerProfiler()};
    ds::gum::attach(interceptor, (void *) get_luajit_address("lua_gc"),
                    GUM_INVOCATION_LISTENER(linstener.cproxy), (void *) "lua_gc");
#endif
    replaced = 1;
    return replaced;
#endif
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_enable_tracy(int en) {
    tracy_active = en != 0;
}
