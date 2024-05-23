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


bool isClientMod = []() {
    return !getExePath().filename().string().contains("server");
}();


void updater();

void installer(bool unsetup);

#ifdef ENABLE_AUTOINSTALLER

std::optional<bool> _mod_enabled(std::tuple<std::string, size_t> &out)
{
    auto modindexPath = getModindexPath();
    if (!modindexPath)
        return std::nullopt;
    auto modindex = GetPersistentString(modindexPath->string());
    if (!modindex.has_value())
        return std::nullopt;
    std::string_view view = modindex.value();
    auto L = luaL_newstate();
    luaL_openlibs(L);
    luaL_dostring(L, view.data());
    lua_setglobal(L, "mod");
    luaL_dostring(L, R"(
        if not mod then
            return false
        
        for k,info in pair(mod.known_mods) do
            if k:find('luajit',1, true) then
                return info.enabled
            end
        end
        return false;
    )");
    auto res = lua_toboolean(L, -1);
    lua_close(L);
    return res;
}

bool mod_enabled()
{
    std::tuple<std::string, size_t> out;
    auto opt_enabled = _mod_enabled(out);
    return opt_enabled.value_or(true);
}

void removeBat()
{
    const auto gameUserDoctmentDir = getGameUserDoctmentDir();
    if (gameUserDoctmentDir)
        std::filesystem::remove(gameUserDoctmentDir.value() / "Cluster_65534.bat");
}
#endif

static bool shouldloadmod() {
#ifdef ENABLE_AUTOINSTALLER
    auto clientSaveDir = GetClientSaveDir();
    if (!clientSaveDir)
        return true;
    auto boot_modindex_path = clientSaveDir.value() / "boot_modindex";
    // check root_modindex
    auto boot_modindex = GetPersistentString(boot_modindex_path.string());
    if (boot_modindex.value_or("").find("loading") != std::string::npos)
    {
        spdlog::info("boot_modindex is loading");
        return false;
    }
    // check enable luajit
    if (!mod_enabled())
    {
        spdlog::info("luajit mod not enabled");
        return false;
    }
#endif
    return true;
}


void DontStarveInjectorStart() {
    std::initializer_list<std::shared_ptr<spdlog::sinks::sink>> sinks = {
            std::make_shared<spdlog::sinks::msvc_sink_st>(), std::make_shared<spdlog::sinks::stdout_color_sink_st>()};
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("", sinks.begin(), sinks.end()));
    auto dir = getGameDir();
// no workshop
#ifdef ENABLE_AUTOINSTALLER
    removeBat();
#endif

    // auto updater
    if (isClientMod && !std::string_view(GetCommandLineA()).contains("-disable_check_luajit_mod")) {
        updater();
        if (!shouldloadmod()) {
            return;
        }
    } else {
        std::atexit(updater);
    }
    auto mod = LoadLibraryA("injector");
    if (!mod) {
        spdlog::error("can't load injector.dll");
        return;
    }
    auto ptr = (void (*)(bool)) GetProcAddress(mod, "Inject");
    ptr(isClientMod);
}