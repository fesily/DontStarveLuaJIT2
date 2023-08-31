#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <format>
#include <Windows.h>
#include <spdlog/spdlog.h>
#ifndef MOD_VERSION
#error "not define MOD_VERSION"
#endif
#include "steam.hpp"
#include "PersistentString.hpp"

using namespace std::literals;

std::filesystem::path getGameDir();
static std::filesystem::path getModinfoLuaPath()
{
    return getModDir() / "modinfo.lua";
}
static bool mod_has_removed()
{
    return !std::filesystem::exists(getModinfoLuaPath());
}
static bool need_updater()
{
    std::ifstream ss(getModinfoLuaPath());
    std::string line;
    while (std::getline(ss, line))
    {
        constexpr auto prefix = "version = \""sv;
        if (line.starts_with(prefix))
        {
            auto version = line.substr(prefix.size(), line.find_last_of('"') - prefix.size());
            if (version == MOD_VERSION)
                return false;
            spdlog::info("need update, mod version is not " MOD_VERSION);
            return true;
        }
    }
    spdlog::info("need update, no mod version");
    return true;
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
std::filesystem::path getLuajitMtxPath();
void enable_mod(bool enabled);

static auto unsetup_pre(std::filesystem::path game_dir)
{
    // disabale luajit mod
    enable_mod(false);

    // unsetup
    SetEnvironmentVariableW(L"GAME_FILE", (game_dir / "Winmm.dll").c_str());

    return "rm $Env:GAME_FILE";
}

static auto setup_pre(std::filesystem::path game_dir)
{
    std::filesystem::remove(getLuajitMtxPath());
    auto bin_dir = getModDir() / "bin64" / "windows";
    auto bin_dir_copy = bin_dir.make_preferred().string();
    auto game_dir_copy = game_dir.make_preferred().string();

    char path[MAX_PATH];
    HMODULE hmod;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (const char *)&updater, &hmod);
    GetModuleFileNameA(hmod, path, MAX_PATH);
    SetEnvironmentVariableA("GAME_DIR", game_dir_copy.c_str());
    SetEnvironmentVariableA("BIN_DIR", bin_dir_copy.c_str());
    return "xcopy $Env:BIN_DIR $Env:GAME_DIR /C /Y";
}

static void installer(bool setup)
{
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    auto game_dir = getGameDir() / "bin64";
    std::string update_cmd = (setup ? setup_pre : unsetup_pre)(game_dir);

#define DEBUG_SHELL 0
    auto cmd = std::format("powershell"
#if DEBUG_SHELL
                           " -NoExit"
#endif
                           " -Command $Host.UI.RawUI.WindowTitle='LUAJIT_UPDATER';Wait-Process {}; {};start steam://rungameid/322330;",
                           GetCurrentProcessId(), update_cmd);
    spdlog::info("run shell:{}", cmd);
    if (CreateProcessA(NULL, cmd.data(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        std::exit(0);
    }
}

void updater()
{
    if (mod_has_removed())
    {
        spdlog::info("mod removed, unsetup it!");
        installer(false);
        return;
    }
    if (!need_updater())
        return;
    installer(true);
}
