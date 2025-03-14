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
#include "PersistentString.hpp"
#include "steam.hpp"
#include "../luajit_config.hpp"

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

        if (enableDebug) {
            ::AllocConsole();
#ifndef NDEBUG
            if (!IsDebuggerPresent())
            {
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
            auto limit = std::chrono::system_clock::now() + 15s;
            while (!IsDebuggerPresent())
            {
                std::this_thread::yield();
                if (std::chrono::system_clock::now() > limit)
                    break;
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

std::filesystem::path getUserDoctmentDir() {
    static auto p = []() -> std::filesystem::path {
        char path[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, path);
        return path;
    }();
    return p;
}

std::filesystem::path getKleiDoctmentDir() {
    return getUserDoctmentDir() / "klei";
}

std::filesystem::path getKleiGameDoctmentDir() {
    constexpr auto game_doctment_name = "DoNotStarveTogether";
    return getKleiDoctmentDir() / game_doctment_name;
}

std::filesystem::path getGameDir() {
    static std::filesystem::path p = getExePath().parent_path().parent_path();
    return p;
}

#ifdef ENABLE_STEAM_SUPPORT
std::optional<std::filesystem::path> getGameUserDoctmentDir()
{
    auto userid = getUserId();
    if (userid)
        return getKleiGameDoctmentDir() / std::to_string(userid.value());
    return std::nullopt;
}
std::optional<std::filesystem::path> GetClientSaveDir()
{
    auto dir = getGameUserDoctmentDir();
    if (dir)
        return dir.value() / "client_save";
    return std::nullopt;
}

std::optional<std::filesystem::path> getModindexPath()
{
    auto dir = GetClientSaveDir();
    if (dir)
        return dir.value() / "modindex";
    return std::nullopt;
}
#endif

const std::optional<luajit_config>& getLuajitConfig() {
    static auto config = luajit_config::read_from_file();
    return config;
}


void updater();

void installer(bool unsetup);

void DontStarveInjectorStart() {
    std::initializer_list<std::shared_ptr<spdlog::sinks::sink>> sinks = {
            std::make_shared<spdlog::sinks::msvc_sink_st>(), std::make_shared<spdlog::sinks::stdout_color_sink_st>()};
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("", sinks.begin(), sinks.end()));
    
    spdlog::set_level(spdlog::level::err);
#ifdef DEBUG
    spdlog::set_level(spdlog::level::trace);
#endif
    auto dir = getGameDir();

    bool isClientMod = !getExePath().filename().string().contains("server");
    if (!isClientMod) {
        auto& config = getLuajitConfig();
        if (config && config->server_disable_luajit) {
            spdlog::error("config found disablejit when server: ON");
            return;
        }
    }
    // auto updater
#if 0
    if (isClientMod && !std::string_view(GetCommandLineA()).contains("-disable_check_luajit_mod")) {
        updater();
    } else {
        std::atexit(updater);
    }
#endif
    auto mod = LoadLibraryA("injector");
    if (!mod) {
        spdlog::error("can't load injector.dll");
        return;
    }
    auto ptr = (void (*)(bool)) GetProcAddress(mod, "Inject");
    ptr(isClientMod);
}