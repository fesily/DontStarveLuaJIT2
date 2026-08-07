// plugin_debug_profiler — replace_profiler / tracy / framegc API bodies (Task 2).
#include "GameProfilerHook.hpp"

#include "config/InjectorHostConfig.hpp"

#include <atomic>
#include <frida-gum.h>

bool tracy_active = false;

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_replace_profiler_api() {
    static std::atomic_char replaced;
    if (replaced) {
        return 1;
    }
#ifdef __linux__
    // profiler_push: compiler now emits `add dword [rbx+0x180],1` (was r12-based 41 83 84 24 ...).
    // Anchor on the surrounding `mov [rbp+0x18],0x42 ; mov [rbp+0x28],r14d ; add [rbx+0x180],1`
    // tail to stay unique (the bare increment matches twice), func entry is -0xEE from match start.
    function_relocation::MemorySignature profiler_push{"C6 45 18 42 44 89 75 28 83 83 80 01 00 00 01", -0xEE};
    function_relocation::MemorySignature profiler_pop{"64 48 8B 1C 25 F8 FF FF FF", -0x15};
#elif defined(__APPLE__)
    function_relocation::MemorySignature profiler_push{"41 83 84 24 80 01 00 00 01", -0xF6};
    function_relocation::MemorySignature profiler_pop{"64 48 8B 1C 25 F8 FF FF FF", -0x15};
    return 0; // TODO
#elif defined(_WIN32)
    function_relocation::MemorySignature profiler_push{"44 8B 9B 88 02 00 00", -0x175};
    function_relocation::MemorySignature profiler_pop{"81 7F 1C 00 3C 00 00", -0x7D};
#else
    return 0;
#endif

#if !defined(__APPLE__)
    auto path = gum_module_get_path(gum_process_get_main_module());
    if (profiler_pop.scan(path) && profiler_push.scan(path)) {
        Hook((uint8_t *) profiler_push.target_address, (uint8_t *) hook_profiler_push);
        Hook((uint8_t *) profiler_pop.target_address, (uint8_t *) ProfilerHooker::hook_profiler_pop);
#ifdef profiler_lua_gc
        auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
        static Gum::InvocationListenerProxy linstener{new Gum::InvocationListenerProfiler()};
        GumAttachOptions attach_opts{};
        attach_opts.listener_function_data = (void *) "lua_gc";
        gum_interceptor_attach(interceptor, (void *) get_luajit_address("lua_gc"),
                               GUM_INVOCATION_LISTENER(linstener.cproxy), &attach_opts);
#endif
        replaced = 1;
    }
    return replaced;
#endif
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_enable_tracy(int en) {
    tracy_active = en != 0;
}
