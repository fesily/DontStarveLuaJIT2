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

using namespace std::literals;
void printenv()
{
    char **env;
#if defined(WIN) && (_MSC_VER >= 1900)
    env = *__p__environ();
#else
    extern char **environ;
    env = environ;
#endif
    for (env; *env; ++env)
    {
        fprintf(stdout, "%s\n", *env);
    }
}
void wait_debugger()
{
    TCHAR filePath[MAX_PATH];
    ::GetModuleFileName(NULL, filePath, MAX_PATH);

    if (_tcsstr(filePath, _T("dontstarve")) != NULL)
    {
        const auto filename = "Debug.config";
        BOOL enableDebug = ::GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES;

        if (enableDebug)
        {
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
            if (fread(buffer, sizeof(char), sizeof(buffer) / sizeof(char), fp) > 0)
            {
                _putenv_s("LUA_INIT", buffer);
            }
            fclose(fp);
            printenv();
        }
    }
}

std::filesystem::path getUserDoctmentDir()
{
    static auto p = []() -> std::filesystem::path
    {
        char path[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, path);
        return path;
    }();
    return p;
}

std::filesystem::path getKleiDoctmentDir()
{
    return getUserDoctmentDir() / "klei";
}

std::filesystem::path getKleiGameDoctmentDir()
{
    constexpr auto game_doctment_name = "DoNotStarveTogether";
    return getKleiDoctmentDir() / game_doctment_name;
}


std::filesystem::path getGameDir()
{
    static std::filesystem::path p = getExePath().parent_path().parent_path();
    return p;
}
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

std::filesystem::path getLuajitMtxPath()
{
    return getGameDir() / "data" / "luajit.mutex";
}
bool isClientMod = []()
{
    return !getExePath().filename().string().contains("server");
}();

void updater();
void installer(bool unsetup);
auto enabled_key = "enabled="sv;
auto enabled_key1 = "[\"enabled\"]="sv;
static std::optional<bool> _mod_enabled(std::string_view key, size_t pos, std::string_view view, std::tuple<std::string, size_t> &out)
{
    size_t enabled_pos = pos;
    for (size_t i = 0; i < 3; i++)
    {
        enabled_pos = view.find(key, enabled_pos + 1);
        // skip tem_enabled=
        if (enabled_pos == std::string::npos)
            return std::nullopt;
        auto c = view[enabled_pos - 1];
        if (c == ',' || c == '{')
            break;
    }
    std::string modid_str = modid_name;
    auto next_mod_pos = view.find("workshop-", pos + modid_str.length());
    if (next_mod_pos != std::string::npos && enabled_pos > next_mod_pos)
    {
        // invaild enabled
        return std::nullopt;
    }
    std::get<1>(out) = enabled_pos;
    return view.substr(enabled_pos + key.size()).starts_with("true");
}

std::optional<bool> _mod_enabled(std::tuple<std::string, size_t> &out)
{
    auto modindexPath = getModindexPath();
    if (!modindexPath)
        return std::nullopt;
    auto modindex = GetPersistentString(modindexPath->string());
    if (!modindex.has_value())
        return std::nullopt;
    std::string_view view = modindex.value();
    std::string modid_str = modid_name;
    auto pos = view.find(modid_str);
    if (pos == std::string::npos)
        return std::nullopt;
    auto res = _mod_enabled(enabled_key, pos, view, out);
    if (!res)
    {
        res = _mod_enabled(enabled_key1, pos, view, out);
    }
    if (res)
    {
        std::get<0>(out) = std::string(view);
    }
    return res;
}

bool mod_enabled()
{
    std::tuple<std::string, size_t> out;
    auto opt_enabled = _mod_enabled(out);
    return opt_enabled.value_or(true);
}

void enable_mod(bool enabled)
{
    std::tuple<std::string, size_t> out;
    auto opt_enabled = _mod_enabled(out);
    if (!opt_enabled.has_value())
        return;
    auto orignal_enabled = opt_enabled.value();
    if (orignal_enabled == enabled)
        return;
    auto &[modindex, enabled_pos] = out;
    auto new_modindex = modindex.replace(enabled_pos + enabled_key.length(), (orignal_enabled ? "true"sv : "false"sv).length(), enabled ? "true" : "false");
    auto modindexPath = getModindexPath();
    if (modindexPath)
        SetPersistentString(modindexPath->string(), new_modindex, false);
}

static bool shouldloadmod()
{
    auto mutex_file = getLuajitMtxPath();
    if (std::filesystem::exists(mutex_file))
    {
        spdlog::info("find luajit.mutex");
        return false;
    }
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
    if (isModNeedUpdated())
    {
        spdlog::info("find new mod version");
        return false;
    }
    // check enable luajit
    if (!mod_enabled())
    {
        spdlog::info("luajit mod not enabled");
        return false;
    }
    auto fp = fopen(mutex_file.string().c_str(), "w");
    if (fp)
        fclose(fp);
    return true;
}

void removeBat()
{
    const auto gameUserDoctmentDir = getGameUserDoctmentDir();
    if (gameUserDoctmentDir)
        std::filesystem::remove(gameUserDoctmentDir.value() / "Cluster_65534.bat");
}

void DontStarveInjectorStart()
{
    std::initializer_list<std::shared_ptr<spdlog::sinks::sink>> sinks = {std::make_shared<spdlog::sinks::msvc_sink_st>(), std::make_shared<spdlog::sinks::stdout_color_sink_st>()};
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("", sinks.begin(), sinks.end()));
    removeBat();
    auto dir = getGameDir();
    // auto updater
    if (isClientMod && !std::string_view(GetCommandLineA()).contains("-disable_check_luajit_mod"))
    {
        updater();
        if (!shouldloadmod())
        {
            std::filesystem::remove(getLuajitMtxPath());
            enable_mod(false);
            return;
        }
    }
    else
    {
        std::atexit(updater);
    }
    auto mod = LoadLibraryA("injector");
    if (!mod)
    {
        spdlog::error("can't load injector.dll");
        return;
    }
    auto ptr = (void (*)(bool))GetProcAddress(mod, "Inject");
    ptr(isClientMod);
}