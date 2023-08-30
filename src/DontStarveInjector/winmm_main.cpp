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

#include "PersistentString.hpp"
#include "steam.hpp"

using namespace std::literals;

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
            auto fp = fopen(filename, "r");
            char buffer[1024] = {};
            if (fread(buffer, sizeof(char), sizeof(buffer) / sizeof(char), fp) > 0)
            {
                _putenv_s("LUA_INIT", buffer);
            }
            fclose(fp);
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

std::filesystem::path getExePath()
{
    static std::filesystem::path p = []
    {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, 255);
        return std::filesystem::path{path};
    }();
    return p;
}

std::filesystem::path getGameDir()
{
    static std::filesystem::path p = getExePath().parent_path().parent_path();
    return p;
}
std::filesystem::path getGameUserDoctmentDir()
{
    auto userid = getUserId();
    return getKleiGameDoctmentDir() / std::to_string(userid);
}
std::filesystem::path GetClientSaveDir()
{
    return getGameUserDoctmentDir() / "client_save";
}

std::filesystem::path getModindexPath()
{
    return GetClientSaveDir() / "modindex";
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
std::optional<bool> _mod_enabled(std::tuple<std::string, size_t> &out)
{
    auto modindex = GetPersistentString(getModindexPath().string());
    if (!modindex.has_value())
        return std::nullopt;
    std::string_view view = modindex.value();
    std::string modid_str = modid_name;
    auto pos = view.find(modid_str);
    if (pos == std::string::npos)
        return std::nullopt;
    size_t enabled_pos = pos;
    for (size_t i = 0; i < 3; i++)
    {
        enabled_pos = view.find(enabled_key, enabled_pos + 1);
        // skip tem_enabled=
        if (enabled_pos == std::string::npos)
            return std::nullopt;
        auto c = view[enabled_pos - 1];
        if (c == ',' || c == '{')
            break;
    }
    auto next_mod_pos = view.find("workshop-", pos + modid_str.length());
    if (next_mod_pos != std::string::npos && enabled_pos > next_mod_pos)
    {
        // invaild enabled
        return std::nullopt;
    }
    out = std::make_tuple(modindex.value(), enabled_pos);
    return view.substr(enabled_pos + enabled_key.size()).starts_with("true");
}

bool mod_enabled()
{
    std::tuple<std::string, size_t> out;
    auto opt_enabled = _mod_enabled(out);
    return opt_enabled.value_or(false);
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
    SetPersistentString(getModindexPath().string(), new_modindex, false);
}

static bool shouldloadmod()
{
    auto mutex_file = getLuajitMtxPath();
    if (std::filesystem::exists(mutex_file))
        return false;
    auto clientSaveDir = GetClientSaveDir();
    auto boot_modindex_path = clientSaveDir / "boot_modindex";
    // check root_modindex
    auto boot_modindex = GetPersistentString(boot_modindex_path.string());
    if (boot_modindex.value_or("").find("loading") != std::string::npos)
        return false;
    // check enable luajit
    if (!mod_enabled())
        return false;
    auto fp = fopen(mutex_file.string().c_str(), "w");
    if (fp)
        fclose(fp);
    return true;
}

void DontStarveInjectorStart()
{
    std::filesystem::remove(getGameUserDoctmentDir() / "Cluster_65534.bat");
    auto dir = getGameDir();
    // auto updater
    if (isClientMod)
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
        MessageBoxA(NULL, "can't load injector.dll", "Error!", 0);
        std::exit(1);
    }
    auto ptr = (void (*)(bool))GetProcAddress(mod, "Inject");
    ptr(isClientMod);
}