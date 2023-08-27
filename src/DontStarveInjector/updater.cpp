#include <steam_api.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <format>
#include <Windows.h>
#ifndef MOD_VERSION
#error "not define MOD_VERSION"
#endif

using namespace std::literals;

std::filesystem::path getGameDir();
std::filesystem::path getModDir()
{
    uint64_t punSizeOnDisk;
    uint32_t punTimeStamp;
    char path[MAX_PATH];
    if (SteamUGC()->GetItemInstallInfo(3010545764, &punSizeOnDisk, path, 255, &punTimeStamp))
    {
        return path;
    }
    return {};
}

bool need_updater()
{
    if (!SteamAPI_Init())
        return false;

    auto dir = getModDir();
    if (dir.empty())
        return false;
    if (!std::filesystem::exists(dir))
        return true;
    auto modinfo_path = dir / "modinfo.lua";
    std::ifstream ss(modinfo_path);
    std::string line;
    while (std::getline(ss, line))
    {
        constexpr auto prefix = "version = \""sv;
        if (line.starts_with(prefix))
        {
            auto version = line.substr(prefix.size(), line.find_last_of('"') - prefix.size());
            if (version == MOD_VERSION)
            {
                return false;
            }
            break;
        }
    }
    return true;
}
auto getModBinDir()
{
    return getModDir() / "bin64" / "windows";
}
auto hashfile(std::filesystem::path path)
{
    std::string filecontext;
    std::ifstream ss(path);
    while (!ss.eof())
    {
        char buf[4096];
        ss.read(buf, 4096);
        auto read_bytes = ss.gcount();
        filecontext.append(buf, read_bytes);
    }
    return std::hash<std::string>{}(filecontext);
}

void updater();

void Installer(bool setup) 
{
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    char path[MAX_PATH];
    HMODULE hmod;

    auto bin_dir = getModBinDir();
    auto game_dir = getGameDir() / "bin64";
    std::string update_cmd;
    if (!setup || !std::filesystem::exists(bin_dir))
    {
        // unsetup
        SetEnvironmentVariableW(L"GAME_FILE", (game_dir / "Winmm.dll").c_str());

        update_cmd = "rm $Env:GAME_FILE";
    }
    else
    {

        auto bin_dir_copy = bin_dir.make_preferred().string();
        auto game_dir_copy = game_dir.make_preferred().string();

        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (const char*)&updater, &hmod);
        GetModuleFileNameA(hmod, path, MAX_PATH);
        SetEnvironmentVariableA("GAME_DIR", game_dir_copy.c_str());
        SetEnvironmentVariableA("BIN_DIR", bin_dir_copy.c_str());
        update_cmd = "xcopy $Env:BIN_DIR $Env:GAME_DIR /C /Y";
    }
#define DEBUG_SHELL 0
    auto cmd = std::format("powershell"
#if DEBUG_SHELL
        " -NoExit"
#endif
        " -Command $Host.UI.RawUI.WindowTitle='LUAJIT_UPDATER';Wait-Process {}; {};start steam://rungameid/322330;",
        GetCurrentProcessId(), update_cmd);
    OutputDebugStringA(cmd.c_str());
    if (CreateProcessA(NULL, cmd.data(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        std::exit(0);
    }
}

void updater()
{
    if (!need_updater())
        return;
    Installer(true);
}
