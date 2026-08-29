#include <Windows.h>
#include <TCHAR.h>
#include <cstdio>
#include <cstring>

#include "platform.hpp"
#include "loader/bootstrap/InjectorBootstrap.hpp"

void wait_debugger() {
    TCHAR filePath[MAX_PATH];
    ::GetModuleFileName(NULL, filePath, MAX_PATH);

    if (_tcsstr(filePath, _T("dontstarve")) != NULL) {
        const auto filename = "Debug.config";

        if (::GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES) {
            ::AllocConsole();
        }

        if (IsDebuggerPresent()) {
            return;
        }
        // Optional attach: only when DS_LUAJIT_WAIT_DEBUGGER=1
        char env[8]{};
        if (GetEnvironmentVariableA("DS_LUAJIT_WAIT_DEBUGGER", env, sizeof(env)) > 0 &&
            (env[0] == '1' || env[0] == 'y' || env[0] == 'Y')) {
            while (!IsDebuggerPresent()) {
                Sleep(100);
            }
        }
    }
}

void DontStarveInjectorStart() {
    wait_debugger();

    auto hook_startup_entry = ds::bootstrap::load_injector_hook_entry();
    if (!hook_startup_entry) {
        std::fprintf(stderr,
                     "[ds-bootstrap] can't load injector.dll (bootstrap resolve/load failed)\n");
        std::fflush(stderr);
        return;
    }
    if (hook_startup_entry()) {
        std::fprintf(stderr, "[ds-bootstrap] installed injector startup hook\n");
        std::fflush(stderr);
        return;
    }
    std::fprintf(stderr, "[ds-bootstrap] failed to install injector startup hook\n");
    std::fflush(stderr);
}
