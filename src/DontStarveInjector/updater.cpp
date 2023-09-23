#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <format>
#include <charconv>
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

static uint32_t toversion(const std::string_view& view)
{
    size_t offset = 0;
    auto npos = view.find('.', offset);
    if (npos == view.npos)
        return 0;
    auto m = view.substr(offset, npos - offset);
    offset = npos + 1;
    npos = view.find('.', offset);
    if (npos == view.npos)
        return 0;
    auto s = view.substr(offset, npos - offset);
    auto p = view.substr(npos + 1);
    union alignas(alignof(uint32_t))
    {
        struct
        {

            uint8_t m;
            uint8_t s;
            uint8_t s1;
            uint8_t p;
        };
        uint32_t v;
    } version;

    std::from_chars(m.data(), m.data() + m.size(), version.m);
    std::from_chars(s.data(), s.data() + s.size(), *(uint16_t*)&version.s);
    std::from_chars(p.data(), p.data() + p.size(), version.p);
    return version.v;
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
            if (toversion(version) <= toversion(MOD_VERSION))
                return false;
            spdlog::info("need update, mod version [{}] is not " MOD_VERSION, version);
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
