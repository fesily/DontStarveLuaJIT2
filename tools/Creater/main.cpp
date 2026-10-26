#include <format>
#include <frida-gum.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <string_view>

#ifdef _WIN32
#include <crtdbg.h>
#include <windows.h>
#endif

#include "platform.hpp"
#include "frida_gum_interceptor.hpp"
#include "SignatureJson.hpp"
#include "GameSignature.hpp"
#include "DontStarveSignature.hpp"
#include "ctx.hpp"

#ifndef GAMEDIR
#error "not defined GAME_DIR"
#endif

#ifndef LUA51_PATH
#error "not defined LUA51_PATH"
#endif

#ifndef WORKER_DIR
#error "not defined WORKER_DIR"
#endif

const char *game_path = GAMEDIR R"(/bin64/dontstarve_steam_x64)" EXECUTABLE_SUFFIX;
const char *game_server_path = GAMEDIR R"(/bin64/dontstarve_dedicated_server_nullrenderer_x64)" EXECUTABLE_SUFFIX;
const char *lua51_path = LUA51_PATH;
const char *worker_dir = WORKER_DIR;

enum class ToolMode { Auto, Create, Update };

// "create" / "update" force one branch of SignatureUpdater::create_or_update().
// Empty/null keeps the in-game Auto behaviour; anything else is rejected so a
// typo cannot silently run the wrong branch.
static bool parse_tool_mode(const char *arg, ToolMode &out) {
    if (arg == nullptr || *arg == '\0') {
        out = ToolMode::Auto;
        return true;
    }
    const std::string_view s{arg};
    if (s == "create" || s == "Create") {
        out = ToolMode::Create;
        return true;
    }
    if (s == "update" || s == "Update") {
        out = ToolMode::Update;
        return true;
    }
    fprintf(stderr, "unknown mode '%s' (expected 'create' or 'update')\n", arg);
    return false;
}

static SignatureMode to_signature_mode(ToolMode mode) {
    switch (mode) {
        case ToolMode::Create:
            return SignatureMode::Create;
        case ToolMode::Update:
            return SignatureMode::Update;
        default:
            return SignatureMode::Auto;
    }
}

static const char *tool_mode_name(ToolMode mode) {
    switch (mode) {
        case ToolMode::Create:
            return "create";
        case ToolMode::Update:
            return "update";
        default:
            return "auto";
    }
}


int update(bool isClient, const char *path, ToolMode mode) {
    fprintf(stderr, "game_path:\t%s\n", path);
    fprintf(stderr, "mode:\t%s (%s)\n", tool_mode_name(mode), isClient ? "client" : "server");
#ifdef _WIN32
    if (!loadlib(path)){
        fprintf(stderr, "can't load %s\n", path);
        return 1;
    }
#endif
    const auto lua_entry =
#ifdef __linux__
            luaModuleSignature.scan_function(path);
#else
            luaModuleSignature.scan(path);
#endif
    if (lua_entry == 0) {
        fprintf(stderr, "%s", "can find lua module base addr\n");
        return 1;
    }

    // Tools: no plugin_core_vm → pass Mod/signatures_*.json explicitly (no CWD/bin64).
    using namespace std::literals;
    const auto sig_path =
            (std::filesystem::path{worker_dir} /
             ("signatures_"s + (isClient ? "client"s : "server"s) + ".json"))
                    .string();
    auto updater = SignatureUpdater::create_or_update(isClient, luaModuleSignature.target_address,
                                                      sig_path, to_signature_mode(mode));
    if (!updater) {
        fprintf(stderr, "%s", updater.error().c_str());
        return 1;
    }
    SignatureJson json{isClient};
    json.file_path = sig_path;
    json.update_signatures(updater->signatures);
    return 0;
}

bool pre_updater() {
    set_worker_directory(worker_dir);
    SignatureJson::version_path = GAMEDIR "/version.txt";
    function_relocation::init_ctx();
    return loadlib(lua51_path);
}

#ifdef _WIN32
int main(int argc, char **argv)
{
#ifdef _WIN32
    // Batch tool: a modal CRT assert / WER dialog would hang the run forever.
    // Route assert/error reports to stderr and disable fault dialogs.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    _set_error_mode(_OUT_TO_STDERR);
    // Keep diagnostics even when the process aborts mid-run.
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
#endif
    // Signature.cpp / MemorySignature.cpp log through this named logger; without
    // it every strategy/per-scan message is silently dropped by spdlog::get().
    // NOTE: function_relocation::init_ctx() already creates the
    // "FunctionRelocation" logger (rotating file next to this exe); creating it
    // here makes spdlog::create throw. Only mirror it to the console on demand.
    ToolMode mode = ToolMode::Auto;
    if (!parse_tool_mode(argc > 1 ? argv[1] : nullptr, mode))
        return 2;
    // Tests must never rewrite the shipped Mod/signatures_*.json: redirect the
    // DB writes (create/update) to a scratch directory instead.
    if (const char *out_dir = std::getenv("SIGNATURE_TOOL_OUTPUT_DIR"); out_dir && *out_dir) {
        worker_dir = out_dir;
        fprintf(stderr, "[tool] output dir:\t%s\n", worker_dir);
    }
    fprintf(stderr, "[tool] gum_init_embedded...\n");
    gum_init_embedded();
    fprintf(stderr, "[tool] pre_updater...\n");
    if (pre_updater()) {
        if (const char *env = std::getenv("DS_FR_LOG"); env && *env == '1') {
            if (auto fr = spdlog::get("FunctionRelocation")) {
                fr->sinks().push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
                fr->set_level(spdlog::level::info);
            }
        }
        fprintf(stderr, "[tool] client phase...\n");
        const int client_rc = update(true, game_path, mode);
        if (client_rc != 0) return client_rc;
        fprintf(stderr, "[tool] server phase...\n");
        return update(false, game_server_path, mode);
    }
    return -1;
}
#else

#include <dlfcn.h>
#include <chrono>
#include "ctx.hpp"

static bool (*orgin)(uint32_t unOwnAppID);

static bool SteamAPI_RestartAppIfNecessary_hook(uint32_t unOwnAppID) {
    using namespace std::chrono_literals;
    spdlog::warn("SteamAPI_RestartAppIfNecessary_hook");
    std::this_thread::sleep_for(10000s);
    return orgin(unOwnAppID);
}

static bool (*orgin1)(uint32_t unIP, uint16_t usSteamPort, uint16_t usGamePort, uint16_t usQueryPort, int eServerMode,
                      const char *pchVersionString);

bool SteamGameServer_Init_hook(uint32_t unIP, uint16_t usSteamPort, uint16_t usGamePort, uint16_t usQueryPort,
                               int eServerMode, const char *pchVersionString) {
    using namespace std::chrono_literals;
    spdlog::warn("SteamGameServer_Init_hook");
    std::this_thread::sleep_for(10000s);
    return orgin1(unIP, usSteamPort, usGamePort, usQueryPort, eServerMode, pchVersionString);
}

static void HookGame(const char *api_name, bool isClient) {
    auto hsteam = dlopen(
#ifdef __linux__
            "libsteam_api.so"
#else
            "@executable_path/../Library/libsteam_api.dylib"
#endif
            , RTLD_NOW);
    auto api = dlsym(hsteam, api_name);
    if (!api) {
        gum_deinit_embedded();
        return;
    }
    auto interceptor = gum_interceptor_obtain();
    auto *replacement = isClient ? (void *) &SteamAPI_RestartAppIfNecessary_hook
                                 : (void *) &SteamGameServer_Init_hook;
    auto **original = isClient ? (void **) &orgin : (void **) &orgin1;
    // New Frida interceptor API: original** before options (not replacement_data).
    auto ret = ds::gum::replace(interceptor, api, replacement, original);
    if (ret != GumReplaceReturn::GUM_REPLACE_OK)
        exit(ret);
}

__attribute__((constructor)) void init() {
    gum_init_embedded();
    auto path = std::filesystem::path(gum_module_get_path(gum_process_get_main_module())).filename().string();
    if (!path.contains("dontstarve")) {
        gum_deinit_embedded();
        return;
    }

    // Preloaded into the game here, so argv belongs to the game: the mode comes
    // from the environment (the CMake create/update_signatures targets set it).
    ToolMode mode = ToolMode::Auto;
    if (!parse_tool_mode(std::getenv("SIGNATURE_TOOL_MODE"), mode)) {
        exit(2);
    }

    bool isClient = !path.contains("nullrenderer");
    const auto api_name = isClient ?
                          "SteamAPI_RestartAppIfNecessary"
                                   : "SteamInternal_GameServer_Init";
    HookGame(api_name, isClient);
#ifdef __APPLE__
    // apple will check debugger, when debugger attach no call SteamAPI_RestartAppIfNecessary
    if (isClient)
        HookGame("SteamAPI_Init", isClient);
#endif
    std::thread([isClient, mode] {
                    if (pre_updater()) {
                        exit(update(isClient, gum_module_get_path(gum_process_get_main_module()), mode));
                    }
                    exit(-1);
                }
    ).detach();
}

#endif
