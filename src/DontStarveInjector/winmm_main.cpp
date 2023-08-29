#include <optional>
#include <string>
#include <unordered_map>
#include <thread>
#include <format>
#include <filesystem>
#include <Windows.h>
#include <TCHAR.h>
#include <ShlObj.h>

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
    auto modindex_path = clientSaveDir / "modindex";
    auto modindex_lua = GetPersistentString(modindex_path.string());
    if (modindex_lua.value_or("").find(std::to_string(modid)) != std::string::npos)
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
            return;
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