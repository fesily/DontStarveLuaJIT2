#include <optional>
#include <string>
#include <unordered_map>
#include <thread>
#include <format>
#include <filesystem>
#include <Windows.h>
#include <TCHAR.h>
#include <ShlObj.h>
#include <cassert>
#include <memory>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/msvc_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "platform.hpp"


extern "C" {
#include <lua.hpp>
}

using namespace std::literals;

void printenv() {
    char **env;
#if defined(WIN) && (_MSC_VER >= 1900)
    env = *__p__environ();
#else
    extern char **environ;
    env = environ;
#endif
    for (env; *env; ++env) {
        fprintf(stdout, "%s\n", *env);
    }
}

void wait_debugger() {
    TCHAR filePath[MAX_PATH];
    ::GetModuleFileName(NULL, filePath, MAX_PATH);

    if (_tcsstr(filePath, _T("dontstarve")) != NULL) {
        const auto filename = "Debug.config";
        BOOL enableDebug = ::GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES;
        ::AllocConsole();

        if (enableDebug) {
#ifndef NDEBUG
            if (getenv("NOVSDEBUGGER") == NULL) {
                if (!IsDebuggerPresent()) {
                    STARTUPINFO si;
                    ZeroMemory(&si, sizeof(si));
                    si.cb = sizeof(si);

                    PROCESS_INFORMATION pi;
                    ZeroMemory(&pi, sizeof(pi));
                    auto cmd = std::format("vsjitdebugger -p {}", GetCurrentProcessId());
                    CreateProcessA(NULL, cmd.data(), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL,
                                NULL,
                                &si,
                                &pi);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
            }
            if (getenv("NOWAITDEBUGGER") == NULL) {
                auto limit = std::chrono::system_clock::now() + 15s;
                while (!IsDebuggerPresent())
                {
                    std::this_thread::yield();
                    if (std::chrono::system_clock::now() > limit)
                        break;
                }
            }
#endif // NDEBUG
            auto fp = fopen(filename, "r");
            char buffer[1024] = {};
            if (fread(buffer, sizeof(char), sizeof(buffer) / sizeof(char), fp) > 0) {
                _putenv_s("LUA_INIT", buffer);
            }
            fclose(fp);
            printenv();
        }
    }
}

void DontStarveInjectorStart() {
    std::initializer_list<std::shared_ptr<spdlog::sinks::sink>> sinks = {
            std::make_shared<spdlog::sinks::msvc_sink_st>(), std::make_shared<spdlog::sinks::stdout_color_sink_st>()};
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("", sinks.begin(), sinks.end()));
    
    spdlog::set_level(spdlog::level::err);
#ifdef DEBUG
    spdlog::set_level(spdlog::level::trace);
#endif

    bool isClientMod = !getExePath().filename().string().contains("server");
    auto mod = LoadLibraryA("injector");
    if (!mod) {
        spdlog::error("can't load injector.dll");
        return;
    }
    auto ptr = (void (*)(bool)) GetProcAddress(mod, "Inject");
    ptr(isClientMod);
}