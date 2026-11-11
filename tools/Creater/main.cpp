#include <format>
#include <frida-gum.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <crtdbg.h>
#include <windows.h>
#endif

#include "platform.hpp"
#include "frida_gum_interceptor.hpp"
#include "SignatureJson.hpp"
#include "CoreVmSignatures.hpp"
#include "DontStarveSignature.hpp"
#include "SignatureCache.hpp"
#include "SignatureRunner.hpp"
#include "signature_providers.hpp"
#include "ctx.hpp"
#include "FunctionRanges.hpp"
#include "ModuleSections.hpp"
#include "UniqueSignature.hpp"

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

enum class ToolMode { Auto, Create, Update, Check };

// "create" / "update" / "check" force one branch; empty/null keeps the in-game
// Auto behaviour; anything else is rejected so a typo cannot silently run the
// wrong branch.
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
    if (s == "check" || s == "Check") {
        out = ToolMode::Check;
        return true;
    }
    fprintf(stderr, "unknown mode '%s' (expected 'create', 'update' or 'check')\n", arg);
    return false;
}

static const char *tool_mode_name(ToolMode mode) {
    switch (mode) {
        case ToolMode::Create:
            return "create";
        case ToolMode::Update:
            return "update";
        case ToolMode::Check:
            return "check";
        default:
            return "auto";
    }
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

static ds::sig::RunnerMode to_runner_mode(ToolMode mode) {
    switch (mode) {
        case ToolMode::Create:
            return ds::sig::RunnerMode::Create;
        case ToolMode::Check:
            return ds::sig::RunnerMode::Check;
        case ToolMode::Update:
        default:
            // Auto (no argument, the in-game semantics) keeps the same contract as
            // update for fixed entries: validate what is stored, re-scan from the
            // definition and rewrite the records that verified.
            return ds::sig::RunnerMode::Update;
    }
}

using namespace std::literals;

namespace {

// One target (client or server binary) with the strings the POD context points
// at kept alive next to it.
struct TargetContext {
    std::string path;
    std::string version;
    std::string digest;
    std::string fixed_cache_path;
    ds::sig::ContextView view{};
    bool ready = false;
    std::string error;
};

TargetContext make_target(const char *path, bool is_client) {
    TargetContext target;
    target.path = path ? path : "";
    target.view.struct_size = sizeof(ds::sig::ContextView);
    target.view.platform = ds::sig::host_platform();
    target.view.is_client = is_client ? 1 : 0;
    target.view.module_path = target.path.c_str();

    auto *module = gum_process_find_module_by_name(target.path.c_str());
    if (auto *range = module ? gum_module_get_range(module) : nullptr) {
        target.view.module_base = range->base_address;
        target.view.module_size = range->size;
        // Use the loader's own spelling from here on: every downstream lookup
        // (scan by name, section parse) matches on it.
        if (const char *canonical = gum_module_get_path(module)) {
            target.path = canonical;
            target.view.module_path = target.path.c_str();
        }
    } else {
        target.error = "target module is not loaded";
        return target;
    }

    const auto version = SignatureJson::current_version();
    if (version > 0) {
        target.version = std::to_string(version);
        target.view.game_version = target.version.c_str();
    }
    target.digest = ds::sig::module_content_digest(target.path.c_str());
    if (target.digest.empty()) {
        target.error = "cannot read the target binary for its content digest";
        return target;
    }
    target.view.module_digest = target.digest.c_str();

    target.fixed_cache_path =
            (std::filesystem::path{worker_dir} / ("plugin_signatures_"s + (is_client ? "client" : "server") + ".json"))
                    .string();
    target.view.cache_path = target.fixed_cache_path.c_str();
    target.ready = true;
    return target;
}

// The Lua DB path for this target (same rule the runtime uses: mod root).
std::string lua_db_path(bool is_client) {
    return (std::filesystem::path{worker_dir} / ("signatures_"s + (is_client ? "client" : "server") + ".json"))
            .string();
}

// The Lua module anchor, resolved through the same core.vm definition the runtime
// and the plugin use. `use_cache=false` for create/update (must re-scan).
uintptr_t resolve_lua_anchor(const ds::sig::ContextView &view, bool use_cache, std::string &detail) {
    ds::sig::ProviderV1 table{};
    if (!ds::sig::make_provider(&ds::core_vm::signature_provider(), &table)) {
        detail = "core.vm provider descriptor is malformed";
        return 0;
    }
    ds::sig::ContextView ctx = view;
    if (!use_cache) {
        ctx.cache_path = nullptr;
    }
    ds::sig::ResolveReport report{};
    if (!table.resolve(table.self, "core.vm.lua_module", &ctx, &report) || report.target_va == 0) {
        detail = report.detail;
        return 0;
    }
    return static_cast<uintptr_t>(report.target_va);
}

void print_entry(const ds::sig::EntryOutcome &entry, const char *mode) {
    if (!entry.applicable) {
        fprintf(stderr, "[%s] %-28s %-46s status=%s\n", mode, entry.owner.c_str(), entry.name.c_str(),
                ds::sig::resolve_status_name(entry.status));
        return;
    }
    const std::string detail = entry.detail.empty() ? std::string{} : " " + entry.detail;
    fprintf(stderr, "[%s] %-28s %-46s status=%s rva=0x%llx raw_hits=%u cache=%s%s%s\n", mode,
            entry.owner.c_str(), entry.name.c_str(), ds::sig::resolve_status_name(entry.status),
            static_cast<unsigned long long>(entry.rva), entry.raw_hits,
            ds::sig::cache_status_name(entry.cache), entry.repaired ? " repaired=1" : "", detail.c_str());
}

// Fixed providers for one target. Returns false when any applicable entry failed.
bool run_fixed_providers(const TargetContext &target, ToolMode mode) {
    bool ok = true;
    const auto runner_mode = to_runner_mode(mode);
    for (const auto &binding : ds::sig::repository_providers()) {
        const ds::sig::ProviderDesc *desc = &binding.desc();
        if (!desc) {
            fprintf(stderr, "[%s] provider %s has no descriptor\n", tool_mode_name(mode), binding.owner);
            ok = false;
            continue;
        }
        const auto report = ds::sig::run_provider(*desc, target.view, runner_mode);
        for (const auto &entry : report.entries) {
            print_entry(entry, tool_mode_name(mode));
        }
        for (const auto &owner : report.owners) {
            if (!owner.wrote_cache) {
                fprintf(stderr, "[%s] %s cache not written: %s\n", tool_mode_name(mode), owner.owner.c_str(),
                        owner.write_detail.c_str());
            }
        }
        ok = ok && report.ok;
    }
    return ok;
}

// Read-only Lua DB check: every stored entry must still be unique from the Lua
// base and still land on an exact function entry. Never creates, updates or
// repairs anything.
bool check_lua_db(const TargetContext &target, bool is_client, uintptr_t lua_base) {
    SignatureJson json{is_client};
    json.file_path = lua_db_path(is_client);
    auto signatures = json.read_from_signatures();
    if (!signatures) {
        fprintf(stderr, "[check] lua %s DB unusable (%s)\n", is_client ? "client" : "server",
                json.file_path.c_str());
        return false;
    }
    function_relocation::ModuleSections module{};
    if (!function_relocation::get_module_sections(target.path.c_str(), module)) {
        fprintf(stderr, "[check] lua module sections unavailable\n");
        return false;
    }
    if (lua_base == 0) {
        fprintf(stderr, "[check] lua module base unresolved\n");
        return false;
    }
    const auto scan_range = function_relocation::signature_search_range(module, lua_base);
    bool ok = true;
    size_t checked = 0;
    for (const auto &[name, info] : signatures->funcs) {
        const uintptr_t entry = lua_base + info.offset;
        if (!function_relocation::validate_unique_signature({&scan_range, 1}, info, entry)) {
            fprintf(stderr, "[check] lua %-40s offset=%llu not unique from the Lua base\n", name.c_str(),
                    static_cast<unsigned long long>(info.offset));
            ok = false;
            continue;
        }
#ifdef __linux__
        if (function_relocation::resolve_function_entry(module, entry) != entry) {
            fprintf(stderr, "[check] lua %-40s offset=%llu is not an FDE entry\n", name.c_str(),
                    static_cast<unsigned long long>(info.offset));
            ok = false;
            continue;
        }
#endif
        ++checked;
    }
    fprintf(stderr, "[check] lua %s entries verified=%zu\n", is_client ? "client" : "server", checked);
    return ok;
}

} // namespace

int update(bool isClient, const char *path, ToolMode mode) {
    fprintf(stderr, "game_path:\t%s\n", path);
    fprintf(stderr, "mode:\t%s (%s)\n", tool_mode_name(mode), isClient ? "client" : "server");
#ifdef _WIN32
    if (!loadlib(path)) {
        fprintf(stderr, "can't load %s\n", path);
        return 1;
    }
#endif
    TargetContext target = make_target(path, isClient);
    if (!target.ready) {
        fprintf(stderr, "[%s] %s: %s\n", tool_mode_name(mode), path, target.error.c_str());
        return 1;
    }

    bool ok = true;

    // --- Lua group (existing matcher/generator, unchanged) -------------------
    std::string anchor_detail;
    const uintptr_t lua_base = resolve_lua_anchor(target.view, /*use_cache=*/false, anchor_detail);
    if (mode == ToolMode::Check) {
        // The DB check never trusts a cached anchor: it re-scans the module (which
        // is not injected in this tool) and proves every stored entry.
        const auto fresh = lua_base;
        if (fresh == 0) {
            fprintf(stderr, "[check] lua anchor unresolved (%s)\n", anchor_detail.c_str());
            ok = false;
        } else if (!check_lua_db(target, isClient, fresh)) {
            ok = false;
        }
    } else {
        if (lua_base == 0) {
            fprintf(stderr, "[%s] lua anchor unresolved (%s)\n", tool_mode_name(mode), anchor_detail.c_str());
            ok = false;
        } else {
            const auto sig_path = lua_db_path(isClient);
            auto updater = SignatureUpdater::create_or_update(isClient, lua_base, sig_path, to_signature_mode(mode));
            if (!updater) {
                // Existing failure semantics: a missing/invalid Lua DB in Update
                // mode is a hard failure and must not be papered over.
                fprintf(stderr, "%s", updater.error().c_str());
                ok = false;
            } else if (mode != ToolMode::Check) {
                SignatureJson json{isClient};
                json.file_path = sig_path;
                json.update_signatures(updater->signatures);
                fprintf(stderr, "[%s] lua %s entries written=%zu\n", tool_mode_name(mode),
                        isClient ? "client" : "server", updater->signatures.funcs.size());
            }
        }
    }

    // --- Fixed provider group ------------------------------------------------
    if (!run_fixed_providers(target, mode)) {
        ok = false;
    }
    return ok ? 0 : 1;
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
    // Signature.cpp / MemorySignature.cpp log through this named logger; without
    // it every strategy/per-scan message is silently dropped by spdlog::get().
    // NOTE: function_relocation::init_ctx() already creates the
    // "FunctionRelocation" logger (rotating file next to this exe); creating it
    // here makes spdlog::create throw. Only mirror it to the console on demand.
    ToolMode mode = ToolMode::Auto;
    if (!parse_tool_mode(argc > 1 ? argv[1] : nullptr, mode))
        return 2;
    // Tests must never rewrite the shipped Mod/signatures_*.json or the fixed
    // cache: redirect the DB writes (create/update) to a scratch directory.
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
        // A client failure never skips the server: both targets produce their own
        // independent results and the exit code is the aggregate.
        fprintf(stderr, "[tool] server phase...\n");
        const int server_rc = update(false, game_server_path, mode);
        return (client_rc != 0 || server_rc != 0) ? 1 : 0;
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
    // from the environment (the CMake create/update/check targets set it).
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
