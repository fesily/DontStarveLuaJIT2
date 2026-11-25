// POSIX game-side shell: thin shared library named libInjector that only
// constructor-calls bootstrap to load the real mod-local Injector module.
// Windows uses Winmm instead (see loader/winmm_main.cpp).
#include "loader/bootstrap/InjectorBootstrap.hpp"
#include <cstdio>

#if defined(_WIN32)
#  error "InjectorStub is POSIX-only; Windows uses Winmm"
#endif

namespace {

struct BootstrapOnce {
    BootstrapOnce() {
        auto fn = ds::bootstrap::load_injector_hook_entry();
        if (!fn) {
            ds::bootstrap::append_boot_log("shell(stub): failed to load real Injector");
            std::fprintf(stderr,
                "[ds-bootstrap] stub: failed to load real Injector\n");
            return;
        }
        if (!fn()) {
            ds::bootstrap::append_boot_log("shell(stub): HookStartupEntry returned false");
            std::fprintf(stderr,
                "[ds-bootstrap] stub: HookStartupEntry returned false\n");
            return;
        }
        ds::bootstrap::append_boot_log("shell(stub): HookStartupEntry OK");
        std::fprintf(stderr, "[ds-bootstrap] stub: HookStartupEntry OK\n");
    }
};

// Force dynamic initializer before main / game chdir hooks inside real module.
static BootstrapOnce g_bootstrap_once;

} // namespace

#if defined(__linux__) || defined(__APPLE__)
// Read by the real Injector's allocator shim: the POSIX stub owns the
// process-wide allocator through the static MI_OVERRIDE=ON archive, so the late
// GOT rewrite must stay off even if DS_ALLOC_SHIM is set.
extern "C" __attribute__((visibility("default"))) int ds_stub_alloc_override(void) {
    return 1;
}
#endif
