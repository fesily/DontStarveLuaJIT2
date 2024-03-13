#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <format>
#include <charconv>
#include <Windows.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include "platform.hpp"
#include "steam.hpp"
#include "PersistentString.hpp"

using namespace std::literals;

std::filesystem::path getGameDir();

struct luajit_config {
    std::string modmain_path;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(luajit_config, modmain_path);

static std::optional<luajit_config> read_from_file() {
    auto path = getGameDir() / "data" / "luajit_config.json";
    std::ifstream sf(path.string().c_str());
    if (!sf.is_open())
        return std::nullopt;
    nlohmann::json j;
    sf >> j;
    return j.get<luajit_config>();
}

static std::optional<std::filesystem::path> getModDir() {
    static std::optional<luajit_config> config = read_from_file();
    if (config)
        return std::filesystem::path(config->modmain_path).parent_path();
    return std::nullopt;
}

static std::optional<std::filesystem::path> getModinfoLuaPath() {
    auto dir = getModDir();
    if (dir)
        return dir.value() / "modinfo.lua";
    return std::nullopt;
}

static bool mod_has_removed() {
    auto p = getModinfoLuaPath();
    if (p)
        return !std::filesystem::exists(p.value());
    return false;
}

auto hashfile(std::filesystem::path path) {
    std::string hash;
    std::ifstream ss(path);
    while (!ss.eof()) {
        std::string buf;
        buf.resize(512);
        ss.read(buf.data(), 512);
        size_t read_bytes = ss.gcount();
        hash += std::hash<std::string_view>{}({buf.data(), read_bytes});
    }
    return std::hash<std::string>{}(hash);
}

// md5 整个文件夹内的所有文件
static std::string md5_dir(std::filesystem::path dir) {
    std::string result;
    for (auto &p: std::filesystem::recursive_directory_iterator(dir)) {
        if (p.is_regular_file()) {
            result += std::to_string(hashfile(p));
        }
    }
    return std::to_string(std::hash<std::string>{}(result));
}

static auto need_updater() {
    auto modDir = getModDir();
    if (!modDir)
        return std::tuple{false, false};

    auto binDir = modDir.value() / "bin64" /
                  #ifdef _WIN32
                  "windows"
                  #else
                  "linux"
#endif
    ;
    bool needRestart = false;
    bool needUpdate = false;
    auto gameBinDir = getExePath().parent_path();
    for (auto &p: std::filesystem::recursive_directory_iterator(binDir)) {
        if (p.is_regular_file()) {
            auto filename = p.path().filename().string();

            if (filename.ends_with(".dll") || filename.ends_with(".so")) {
                auto gamePath = gameBinDir / filename;
                if (!std::filesystem::exists(gamePath) || hashfile(gamePath) != hashfile(p)) {
                    needUpdate = true;
#ifdef _WIN32
                    if (filename == "Winmm.dll")
                    {
                        needRestart = true;
                    }
#endif
                }
            }
        }
    }
    return std::tuple{needUpdate, needRestart};
}

void updater();

std::filesystem::path getLuajitMtxPath();

static auto unsetup_pre(std::filesystem::path game_dir) {
    // unsetup
    SetEnvironmentVariableW(L"GAME_FILE", (game_dir / "Winmm.dll").c_str());

    return "rm $Env:GAME_FILE";
}

static std::optional<const char *> setup_pre(std::filesystem::path game_dir) {
    std::filesystem::remove(getLuajitMtxPath());
    auto modDir = getModDir();
    if (!modDir) {
        return std::nullopt;
    }
    auto bin_dir = modDir.value() / "bin64" / "windows";
    auto bin_dir_copy = bin_dir.make_preferred().string();
    auto game_dir_copy = game_dir.make_preferred().string();

    char path[MAX_PATH];
    HMODULE hmod;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (const char *) &updater, &hmod);
    GetModuleFileNameA(hmod, path, MAX_PATH);
    SetEnvironmentVariableA("GAME_DIR", game_dir_copy.c_str());
    SetEnvironmentVariableA("BIN_DIR", bin_dir_copy.c_str());
    return "xcopy $Env:BIN_DIR $Env:GAME_DIR /C /Y";
}

static void installer(bool setup, bool restart) {
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    auto game_dir = getGameDir() / "bin64";
    std::string update_cmd;
    if (setup) {
        auto cmd = setup_pre(game_dir);
        if (!cmd)
            return;
        update_cmd = cmd.value();
    } else {
        update_cmd = unsetup_pre(game_dir);
    }

#define DEBUG_SHELL !NDEBUG
    auto cmd = std::format("powershell"
                           #if !NDEBUG
                           " -NoExit"
                           #endif
                           " -Command $Host.UI.RawUI.WindowTitle='LUAJIT_UPDATER';Wait-Process {}; {};"
#ifdef ENABLE_STEAM_SUPPORT
            "start steam://rungameid/322330;"
#endif
            ,
                           GetCurrentProcessId(), update_cmd);
#ifndef ENABLE_STEAM_SUPPORT
    cmd += "start " + getExePath().string();
#endif
    spdlog::info("run shell:{}", cmd);
    if (CreateProcessA(NULL, cmd.data(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (!restart)
            std::exit(0);
    }
}

void updater() {
    if (mod_has_removed()) {
        spdlog::info("mod removed, unsetup it!");
        installer(false, true);
        return;
    }
    auto [needUpdate, needRestart] = need_updater();
    if (!needUpdate)
        return;
    installer(true, needRestart);
}
