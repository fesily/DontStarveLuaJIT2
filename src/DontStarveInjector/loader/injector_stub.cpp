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
            std::fprintf(stderr,
                "[ds-bootstrap] stub: failed to load real Injector\n");
            return;
        }
        if (!fn()) {
            std::fprintf(stderr,
                "[ds-bootstrap] stub: HookStartupEntry returned false\n");
            return;
        }
        std::fprintf(stderr, "[ds-bootstrap] stub: HookStartupEntry OK\n");
    }
};

// Force dynamic initializer before main / game chdir hooks inside real module.
static BootstrapOnce g_bootstrap_once;

} // namespace
