#include "gameModConfig.hpp"
#include "MemorySignature.hpp"
#include "GameOpenGl.hpp"
#include "game_info.hpp"
#include "luajit_config.hpp"
#include "util/inlinehook.hpp"
#include "util/platform.hpp"
#include "disasm.h"
#include "ScanCtx.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <frida-gum.h>
#include <optional>
#include <spdlog/spdlog.h>
#include <string_view>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#include <KnownFolders.h>
#include <ShlObj.h>
#pragma comment(lib, "Shell32.lib")
#endif

namespace {

using namespace std::string_view_literals;

constexpr uint64_t kPrimaryWorkshopId = 3444078585ULL;
constexpr auto kPrimaryWorkshopModName = "workshop-3444078585"sv;
constexpr std::array<std::string_view, 5> kStaticModAliases = {
        kPrimaryWorkshopModName,
        "3444078585"sv,
        "luajit"sv,
        "luajit2"sv,
        "DontStarveLuaJit2"sv,
};

struct ResolvedModIdentity {
    std::string canonical_modname;
    std::string modname;
    std::string modid;
    std::vector<std::string> aliases;
};

static void add_alias(std::vector<std::string> &aliases, std::string_view alias) {
    if (alias.empty()) {
        return;
    }
    const auto value = std::string{alias};
    if (std::find(aliases.begin(), aliases.end(), value) == aliases.end()) {
        aliases.push_back(value);
    }
}

static bool is_digits(std::string_view value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; });
}

static void add_alias_variants(std::vector<std::string> &aliases, std::string_view alias) {
    add_alias(aliases, alias);
    if (alias.starts_with("workshop-"sv)) {
        add_alias(aliases, alias.substr(sizeof("workshop-") - 1));
    } else if (is_digits(alias)) {
        add_alias(aliases, std::string{"workshop-"}.append(alias));
    }
}

static std::string resolve_canonical_modname_from_modmain_path(std::string_view modmain_path) {
    if (modmain_path.empty()) {
        return {};
    }

    const auto folder = std::filesystem::path(modmain_path).parent_path().filename().string();
    if (folder.empty()) {
        return {};
    }

    if (!is_digits(folder)) {
        return folder;
    }

    return std::string{"workshop-"}.append(folder);
}

static std::string resolve_modid_from_modname(std::string_view modname) {
    if (modname.starts_with("workshop-"sv)) {
        return std::string{modname.substr(sizeof("workshop-") - 1)};
    }
    return std::string{modname};
}

static ResolvedModIdentity build_mod_identity() {
    ResolvedModIdentity identity;
    identity.canonical_modname = std::string{kPrimaryWorkshopModName};
    identity.modname = identity.canonical_modname;
    identity.modid = resolve_modid_from_modname(identity.modname);

    if (auto config = luajit_config::read_from_file(); config) {
        if (!config->modmain_path.empty()) {
            const auto canonical_from_modmain_path = resolve_canonical_modname_from_modmain_path(config->modmain_path);
            if (!canonical_from_modmain_path.empty()) {
                identity.canonical_modname = canonical_from_modmain_path;
                identity.modname = canonical_from_modmain_path;
                identity.modid = resolve_modid_from_modname(identity.modname);
                add_alias_variants(identity.aliases, canonical_from_modmain_path);
            }
        }
        add_alias_variants(identity.aliases, identity.modname);
        add_alias_variants(identity.aliases, identity.modid);
    }

    for (auto alias: kStaticModAliases) {
        add_alias_variants(identity.aliases, alias);
    }

    add_alias_variants(identity.aliases, identity.canonical_modname);
    return identity;
}

static std::filesystem::path GetHomeDir() {
    auto home = getenv("HOME");
    if (home == nullptr) {
        home = getenv("USERPROFILE");
    }
    if (home == nullptr) {
        return {};
    }
    return std::filesystem::path{home};
}

static std::filesystem::path GetUserDocumentsDir() {
#ifdef _WIN32
    PWSTR documents_path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT, nullptr, &documents_path))) {
        std::filesystem::path documents_dir = documents_path;
        CoTaskMemFree(documents_path);
        return documents_dir;
    }
#endif

    const auto home_dir = GetHomeDir();
    if (home_dir.empty()) {
        return {};
    }
    return home_dir / "Documents";
}

static std::filesystem::path GetPlatformKleiRootDir() {
#if defined(__linux__)
    const auto home_dir = GetHomeDir();
    if (home_dir.empty()) {
        return {};
    }
    return home_dir / ".klei";
#else
    const auto documents_dir = GetUserDocumentsDir();
    if (documents_dir.empty()) {
        return {};
    }
    return documents_dir / "Klei";
#endif
}

static std::filesystem::path GetAppStorageBaseDir(std::string_view relative_path = {}) {
#if defined(__linux__)
    const auto home_dir = GetHomeDir();
    if (home_dir.empty()) {
        return {};
    }
    if (relative_path.empty()) {
        return home_dir;
    }

    const auto normalized = std::filesystem::path{relative_path}.generic_string();
    if (normalized == "Klei") {
        return home_dir / ".klei";
    }
    if (std::string_view{normalized}.starts_with("Klei/"sv)) {
        return home_dir / std::filesystem::path{std::string{".klei/"}.append(normalized.substr(sizeof("Klei/") - 1))};
    }
    return home_dir / std::filesystem::path{relative_path};
#else
    const auto documents_dir = GetUserDocumentsDir();
    if (documents_dir.empty()) {
        return {};
    }
    if (relative_path.empty()) {
        return documents_dir;
    }
    return documents_dir / std::filesystem::path{relative_path};
#endif
}

static std::string_view GetDefaultPersistentStorageRoot() {
#if defined(_WIN32) || defined(__APPLE__)
    return "APP:Klei/"sv;
#else
    return ".klei/"sv;
#endif
}

static std::filesystem::path GetKleiSaveDataDir(std::string_view ownid) {
    const auto klei_root = GetPlatformKleiRootDir();
    if (klei_root.empty()) {
        return {};
    }

    auto save_dir = klei_root / "DoNotStarveTogether";
    if (!ownid.empty()) {
        save_dir /= ownid;
    }
    spdlog::info("resolved Klei save data dir for ownid '{}' to {}", ownid, save_dir.string());
    return save_dir;
}

static std::filesystem::path GetModConfigDataDir(std::string_view ownid, const std::string_view &cluster_name = "client_save") {
    auto save_dir = GetKleiSaveDataDir(ownid);
    if (save_dir.empty()) {
        return {};
    }
    return save_dir / cluster_name / "mod_config_data";
}

static std::filesystem::path GetModConfigDataFileName(std::string_view modname) {
    std::string_view ext = InjectorConfig::instance()->AppVersionDevPatch ? "_dev" : "";
    return std::string("modconfiguration_").append(modname).append(ext);
}

static std::string read_env_or_cmd_value(const char *key) {
    char buffer[256] = {};
    InjectorConfig::getEnvOrCmdValue(key, buffer, sizeof(buffer));
    return buffer;
}

static std::filesystem::path GetPersistentStorageRootDir(std::string_view persist_root) {
    if (persist_root.empty()) {
        return {};
    }

    auto normalized = std::string{persist_root};
    constexpr auto app_prefix = "APP:"sv;
    if (std::string_view{normalized}.starts_with(app_prefix)) {
        normalized.erase(0, app_prefix.size());
        const auto resolved_root = GetAppStorageBaseDir(normalized);
        spdlog::info("resolved persistent storage root '{}' to {}", persist_root, resolved_root.string());
        return resolved_root;
    }

    std::filesystem::path root{normalized};
    if (root.is_absolute()) {
        spdlog::info("using absolute persistent storage root {}", root.string());
        return root;
    }

    const auto base = GetHomeDir();
    if (base.empty()) {
        return {};
    }
    const auto resolved_root = base / root;
    spdlog::info("resolved relative persistent storage root '{}' to {}", persist_root, resolved_root.string());
    return resolved_root;
}

static void add_path_candidate(std::vector<std::filesystem::path> &candidates, const std::filesystem::path &candidate) {
    if (candidate.empty()) {
        return;
    }
    if (std::find(candidates.begin(), candidates.end(), candidate) == candidates.end()) {
        candidates.push_back(candidate);
    }
}

static std::vector<std::filesystem::path> GetServerModOverridesPaths(const GameInfo &game_info,
                                                                     const std::optional<std::string> &ownerdir_hint) {
    std::vector<std::filesystem::path> candidates;
    const auto persist_root = GetPersistentStorageRootDir(game_info.persist_root);
    if (persist_root.empty()) {
        return candidates;
    }

    const auto config_root = persist_root / game_info.config_dir;
    const auto shard_suffix = std::filesystem::path{game_info.cluster_name} / game_info.shared_name / "modoverrides.lua";

    if (ownerdir_hint && !ownerdir_hint->empty()) {
        add_path_candidate(candidates, config_root / *ownerdir_hint / shard_suffix);
    }

    std::error_code ec;
    if (std::filesystem::exists(config_root, ec) && std::filesystem::is_directory(config_root, ec)) {
        std::vector<std::filesystem::path> ownerdirs;
        for (const auto &entry: std::filesystem::directory_iterator(config_root, ec)) {
            if (ec) {
                break;
            }
            if (!entry.is_directory(ec)) {
                continue;
            }
            const auto ownerdir_name = entry.path().filename().string();
            if (ownerdir_name.empty() || ownerdir_name == game_info.cluster_name) {
                continue;
            }
            ownerdirs.push_back(entry.path());
        }
        std::sort(ownerdirs.begin(), ownerdirs.end());
        for (const auto &ownerdir: ownerdirs) {
            add_path_candidate(candidates, ownerdir / shard_suffix);
        }
    }

    add_path_candidate(candidates, config_root / shard_suffix);
    return candidates;
}

static GameInfo GetServerGameInfo() {
    GameInfo game_info;
    if (auto runtime_info = readGameInfo()) {
        game_info = *runtime_info;
    }

    if (auto value = read_env_or_cmd_value("persistent_storage_root"); !value.empty()) {
        game_info.persist_root = value;
    }
    if (auto value = read_env_or_cmd_value("conf_dir"); !value.empty()) {
        game_info.config_dir = value;
    }
    if (auto value = read_env_or_cmd_value("cluster"); !value.empty()) {
        game_info.cluster_name = value;
    }
    if (auto value = read_env_or_cmd_value("shard"); !value.empty()) {
        game_info.shared_name = value;
    }

    if (game_info.persist_root.empty()) {
        game_info.persist_root = std::string{GetDefaultPersistentStorageRoot()};
    }
    if (game_info.config_dir.empty()) {
        game_info.config_dir = "DoNotStarveTogether";
    }
    if (game_info.cluster_name.empty()) {
        game_info.cluster_name = "Cluster_1";
    }
    if (game_info.shared_name.empty()) {
        game_info.shared_name = "Master";
    }
    return game_info;
}

static bool is_supported_lua_vm_type(std::string_view value) {
    return value == "jit"sv || value == "game"sv || value == "lua51"sv || value == "51"sv || value == "5.1"sv ||
           value == "jit_gen"sv || value == "_51"sv;
}

static void update_string_field(std::string &field, GameJitConfigSource &source, std::string_view value, GameJitConfigSource new_source) {
    if (value.empty()) {
        return;
    }
    field = std::string{value};
    source = new_source;
}

static void update_bool_field(bool &field, GameJitConfigSource &source, bool value, GameJitConfigSource new_source) {
    field = value;
    source = new_source;
}

static std::optional<GameJitModConfig> load_resolved_game_mod_config() {
    GameJitModConfig resolved = make_default_game_mod_config();
    const auto identity = build_mod_identity();
    resolved.modname = identity.modname;
    resolved.modid = identity.modid;
    resolved.modname_source = GameJitConfigSource::luajit_config;
    resolved.modid_source = GameJitConfigSource::luajit_config;

    if (const auto config = luajit_config::read_from_file(); config) {
        if (!config->modmain_path.empty()) {
            resolved.modmain_path = config->modmain_path;
            resolved.modmain_path_source = GameJitConfigSource::luajit_config;
        }
        update_bool_field(resolved.AlwaysEnableMod, resolved.AlwaysEnableModSource, config->always_enable_mod,
                          GameJitConfigSource::luajit_config);
        resolved.DisableJITWhenServer = config->server_disable_luajit;
        resolved.DisableJITWhenServerSource = GameJitConfigSource::luajit_config;
    }

    auto *ictx = InjectorCtx::instance();
    std::filesystem::path canonical_save_path;
    if (ictx->DontStarveInjectorIsClient) {
        auto mod_config_data = GetModConfigDataDir(std::to_string(ictx->steam_account_id));
        canonical_save_path = mod_config_data / GetModConfigDataFileName(identity.canonical_modname);
        spdlog::info("resolved client mod config data dir to {}", mod_config_data.string());
        spdlog::info("resolved canonical mod config save path to {}", canonical_save_path.string());

        for (const auto &alias: identity.aliases) {
            auto candidate = mod_config_data / GetModConfigDataFileName(alias);
            spdlog::info("checking client mod config candidate {}", candidate.string());
            if (!std::filesystem::exists(candidate)) {
                continue;
            }

            spdlog::info("try load mod configuration from {}", candidate.string());
            if (LoadGameJitModConfigFromSaveFile(candidate, resolved)) {
                if (canonical_save_path.empty()) {
                    canonical_save_path = candidate;
                    resolved.save_file = canonical_save_path.string();
                }
                break;
            }
        }
    } else {
        const auto ownerdir_value = read_env_or_cmd_value("ownerdir");
        const auto ownerdir_hint = !ownerdir_value.empty() ? std::make_optional(ownerdir_value)
                                                           : (ictx->steam_account_id != 0 ? std::make_optional(std::to_string(ictx->steam_account_id))
                                                                                         : std::optional<std::string>{});
        const auto game_info = GetServerGameInfo();
        spdlog::info("resolved server game storage config: persist_root='{}', config_dir='{}', cluster='{}', shard='{}'",
                     game_info.persist_root, game_info.config_dir, game_info.cluster_name, game_info.shared_name);
        if (ownerdir_hint && !ownerdir_hint->empty()) {
            spdlog::info("using server ownerdir hint '{}'", *ownerdir_hint);
        }

        const auto candidates = GetServerModOverridesPaths(game_info, ownerdir_hint);
        for (const auto &candidate: candidates) {
            spdlog::info("checking server mod overrides candidate {}", candidate.string());
            if (!std::filesystem::exists(candidate)) {
                continue;
            }

            spdlog::info("try load server mod overrides from {}", candidate.string());
            if (LoadGameJitModConfigFromModOverridesFile(candidate, identity.aliases, resolved)) {
                break;
            }
        }
    }

    std::string angle_backend;
    const auto configured_angle_backend = InjectorConfig::instance()->DST_ANGLE_BACKEND;
    if (configured_angle_backend != DstAngleBackend::Unknown) {
        angle_backend = to_string(configured_angle_backend);
    } else if (const auto *platform = getenv("ANGLE_DEFAULT_PLATFORM");
               platform != nullptr && from_string(platform) != DstAngleBackend::Unknown) {
        angle_backend = platform;
    }
    if (!angle_backend.empty()) {
        update_string_field(resolved.AngleBackend, resolved.AngleBackendSource, angle_backend, GameJitConfigSource::env_or_cmd);
    }

    auto lua_vm_type = (const char*) InjectorConfig::instance()->lua_vm_type;
    if (lua_vm_type != nullptr && is_supported_lua_vm_type(lua_vm_type)) {
        update_string_field(resolved.LuaVmType, resolved.LuaVmTypeSource, lua_vm_type, GameJitConfigSource::env_or_cmd);
    }

    if (ictx->DontStarveInjectorIsClient && !canonical_save_path.empty()) {
        WriteGameJitModConfigToSaveFile(canonical_save_path, resolved);
    }

    return resolved;
}

} // namespace

struct GameConfigs {
    std::optional<int> render_fps;
    std::optional<bool> client_network_tick;
} game_configs;

extern "C" void lj_ds_print_game_configs() {
    if (game_configs.render_fps) {
        printf("Render FPS: %d\n", game_configs.render_fps.value());
    } else {
        printf("Render FPS: not set\n");
    }
    if (game_configs.client_network_tick) {
        printf("Client Network Tick: %s\n", game_configs.client_network_tick.value() ? "enabled" : "disabled");
    } else {
        printf("Client Network Tick: not set\n");
    }
}

template<typename T>
static void protect_memory_writer(T *addr, T val) {
    GumPageProtection prot;
    gum_memory_query_protection(addr, &prot);
    gum_mprotect(addr, sizeof(T), prot | GUM_PAGE_WRITE);
    *addr = val;
    gum_mprotect(addr, sizeof(T), prot);
};

float frame_time_s = 1.0 / 30;
static float *fps_ptr;
static function_relocation::MemorySignature set_notebook_mode{"F3 0F 11 89 D8 01 00 00", -0x3E};
static void set_notebook_mode_config_hook(void *) {}
static function_relocation::MemorySignature set_notebook_mode_config{"80 B9 D4 01 00 00 00", -0x6};

auto main_module_path = [] { return gum_module_get_path(gum_process_get_main_module()); };

static bool find_set_notebook_mode_imm() {
    if (!InjectorCtx::instance()->DontStarveInjectorIsClient) {
        if (!set_notebook_mode_config.scan(main_module_path())) return false;
        //delete this mode
        Hook((uint8_t *) set_notebook_mode_config.target_address, (uint8_t *) &set_notebook_mode_config_hook);
    }
    if (set_notebook_mode.scan(main_module_path())) {
        function_relocation::disasm ds{(uint8_t *) set_notebook_mode.target_address, 256};
        int offset = 0;
        int movss[] = {
                1023969417,// 1/30
                1015580809,// 1/60
                1106247680,// 30.0
                1114636288,// 60.0
        };
        void *addrs[4];
        for (auto &&insn: ds) {
            if (insn.id != X86_INS_MOVSS) continue;
            if (insn.detail->x86.operands[0].type != x86_op_type::X86_OP_REG) continue;
            if (insn.detail->x86.operands[1].type != x86_op_type::X86_OP_MEM) continue;
            if (insn.detail->x86.operands[0].reg != x86_reg::X86_REG_XMM0 && insn.detail->x86.operands[0].reg != x86_reg::X86_REG_XMM1)
                return false;

            auto ptr = (int32_t *) function_relocation::read_operand_rip_mem(insn, insn.detail->x86.operands[1]);
            if (movss[offset] != *ptr) return false;
            addrs[offset] = (float *) insn.address;
            offset++;
            if (offset == 4)
                break;
        }
        GumAddressSpec spec{(void *) set_notebook_mode.target_address, INT_MAX / 2};
        float *ptr = (float *) gum_memory_allocate_near(&spec, 256, sizeof(void *), GUM_PAGE_RW);
        if (!ptr) return false;
        auto movss_writer = +[](void *addr, float *target) {
            // target = addr + 8 + offset
            auto offset = (int64_t) target - (int64_t) addr - 8;
            gum_mprotect(addr, 16, GUM_PAGE_RWX);
            *(((int32_t *) addr) + 1) = (int32_t) offset;
            gum_mprotect(addr, 16, GUM_PAGE_RX);
        };
        for (size_t i = 0; i < 4; i++) {
            movss_writer(addrs[i], ptr + i);
        }
        fps_ptr = ptr;
        auto new_val = (int *) fps_ptr;
        memcpy(new_val, movss, 4 * sizeof(int));
        return true;
    }
    return false;
}


static float *find_luaupdate_imm(function_relocation::MemorySignature &sign) {
    if (sign.scan(main_module_path())) {
        if (!sign.only_one) {
            sign.target_address = sign.targets.front();
            for (auto addr: sign.targets) {
                if (sign.target_address != addr)
                    return nullptr;
            }
        }
        auto insn = function_relocation::disasm::get_insn((uint8_t *) sign.target_address, 8 + 1);
        if (insn->detail->x86.operands[1].type != x86_op_type::X86_OP_MEM) return nullptr;
        auto imm = (int32_t *) function_relocation::read_operand_rip_mem(*insn, insn->detail->x86.operands[1]);
        if (0x3D088889 == *imm) {
            return (float *) imm;
        }
    }
    return nullptr;
}

static float *find_network_logic_fps(function_relocation::MemorySignature &sign) {
    if (sign.scan(main_module_path())) {
        if (!sign.only_one) {
            sign.target_address = sign.targets.front();
            for (auto addr: sign.targets) {
                if (sign.target_address != addr)
                    return nullptr;
            }
        }
        auto insn = function_relocation::disasm::get_insn((uint8_t *) sign.target_address, 8 + 1);
        if (insn->detail->x86.operands[1].type != x86_op_type::X86_OP_MEM) return nullptr;
        auto imm = (int32_t *) function_relocation::read_operand_rip_mem(*insn, insn->detail->x86.operands[1]);
        if (0x41F3FFFF == *imm) {
            return (float *) imm;
        }
    }
    return nullptr;
}

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_set_target_fps(int fps, int tt) {
#ifndef _WIN32
    return -1;
#endif
    if (fps <= 0) return -1;

    if (tt & 0b01) {
        static auto target_address = []() {
            return find_set_notebook_mode_imm();
        }();
        if (!fps) return -1;

        float val = 1.0f / (float) fps;
        float val2 = (float) fps;
        if (target_address) {
            auto old = fps_ptr[3];
            fps_ptr[1] = val;
            fps_ptr[3] = val2;
            frame_time_s = std::min(val, 1 / 30.0f);
            game_configs.render_fps = fps;
            return old;
        }
    }
    return -1;
}

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_replace_network_tick(char upload_tick, char download_tick, bool isclient) {
#ifndef _WIN32
    return 0;
#endif
    auto ictx = InjectorCtx::instance();
    if (isclient != ictx->DontStarveInjectorIsClient) return 0;
    if (!upload_tick)
        upload_tick = 10;
    if (!download_tick && !upload_tick)
        download_tick = 15;
    /*
    服务器模式: 
        1. 使用固定时间 1000/fps 来处理无人情况下的网络层
        2. 使用固定tick间隔来处理 有玩家的情况下的网络层 tick = logic fps / fps


    客户端模式: 区别上下行模式
    上行固定10fps, 100ms
    下行固定15fps, 66ms
    超过渲染帧率将会去掉下行tick, 只保留上行tick
    */
    static struct NetworkTickContext {
        char *upload_address;
        char *uploadtime_address;
        char *download_address;
    } ctx;
    static char *upload_address;
    static char *uploadtime_address;
    static char *download_address;
    static bool inited = false;
    static auto client_network_tick_addr = [] {
        function_relocation::MemorySignature reset_network_tick_val = {"BB 0F 00 00 00 48 83 B9 88 02 00 00 00", 1}; // always 15
        function_relocation::MemorySignature default_client_network_tick_time = {"44 8D 76 64", 0x3};                // 100ms
        function_relocation::MemorySignature default_client_network_tick_update_fps = {"41 BC 0A 00 00 00 85 D2", 0};//  =10 upload tick
        auto mainpath = main_module_path();
        if (reset_network_tick_val.scan(mainpath) && default_client_network_tick_time.scan(mainpath) && default_client_network_tick_update_fps.scan(mainpath)) {
            // test edx,edx | jz => nop |nop | jmp  always jmp reset network_tick
            auto patched_address = (std::array<char, 3> *) (default_client_network_tick_update_fps.target_address + 6);
            protect_memory_writer(patched_address, std::array<char, 3>{char(0x90), char(0x90), char(0xEB)});
            auto b1 = (char *) default_client_network_tick_time.target_address;
            // download tick, upload time, upload tick
            ctx.download_address = (char *) reset_network_tick_val.target_address;
            ctx.uploadtime_address = b1;
            ctx.upload_address = (char *) default_client_network_tick_update_fps.target_address + 2;
            return true;
        }
        return false;
    }();
    if (client_network_tick_addr) {
        if (!ictx->DontStarveInjectorIsClient) {
            download_tick = upload_tick; // server mode, use the same tick for upload and download
        }
        upload_tick = std::min<char>(120, upload_tick);
        protect_memory_writer(ctx.upload_address, upload_tick);
        auto tick_time = (char) (int) (1000.0 / upload_tick);
        protect_memory_writer(ctx.uploadtime_address, tick_time);
        download_tick = std::min<char>(120, download_tick);
        protect_memory_writer(ctx.download_address, download_tick);
    }
    return 0;
}
#include "GameProfilerHook.hpp"

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_update(const char *mod_directory, int tt) {
    if (!mod_directory) return 0;
#ifdef _WIN32
    auto mod_dir = std::filesystem::path{mod_directory};
    if (!std::filesystem::exists(mod_dir)) return 0;
    mod_dir = std::filesystem::absolute(mod_dir);
    auto installer = mod_dir / "install.bat";
    if (!std::filesystem::exists(installer)) return 0;
    std::string cmd = std::format("cmd /C \"{}\" {}", installer.string(), tt == 1 ? "uninstall" : "");
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcess(NULL, (char *) cmd.c_str(), 0, 0, FALSE, CREATE_NEW_CONSOLE, 0, mod_directory, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
#endif
    return 0;
}

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_replace_profiler_api() {
    static std::atomic_char replaced;
    if (replaced) return 1;
#ifdef __linux__
    function_relocation::MemorySignature profiler_push{"41 83 84 24 80 01 00 00 01", -0xF6};
    function_relocation::MemorySignature profiler_pop{"64 48 8B 1C 25 F8 FF FF FF", -0x15};
#elif defined(__APPLE__)
    function_relocation::MemorySignature profiler_push{"41 83 84 24 80 01 00 00 01", -0xF6};
    function_relocation::MemorySignature profiler_pop{"64 48 8B 1C 25 F8 FF FF FF", -0x15};
    return 0;//TODO
#elif defined(_WIN32)
    function_relocation::MemorySignature profiler_push{"44 8B 9B 88 02 00 00", -0x175};
    function_relocation::MemorySignature profiler_pop{"81 7F 1C 00 3C 00 00", -0x7D};
#endif

    auto path = gum_module_get_path(gum_process_get_main_module());
    if (profiler_pop.scan(path) && profiler_push.scan(path)) {
        Hook((uint8_t *) profiler_push.target_address, (uint8_t *) hook_profiler_push);
        Hook((uint8_t *) profiler_pop.target_address, (uint8_t *) ProfilerHooker::hook_profiler_pop);
#ifdef profiler_lua_gc
        auto interceptor = InjectorCtx::instance().GetGumInterceptor();
        static Gum::InvocationListenerProxy linstener{new Gum::InvocationListenerProfiler()};
        gum_interceptor_attach(interceptor, (void *) get_luajit_address("lua_gc"), GUM_INVOCATION_LISTENER(linstener.cproxy), (void *) "lua_gc");
#endif
        replaced = 1;
    }
    return replaced;
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_enable_tracy(int en) {
    tracy_active = en;
}
DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_get_mod_version() {
    return MOD_VERSION;
}

std::optional<GameJitModConfig> GameJitModConfig::instance() {
    static std::optional<GameJitModConfig> mod_config_options = load_resolved_game_mod_config();
    return mod_config_options;
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_set_vbpool_enabled(bool enable);

extern "C" void LoadGameModConfig() {
#ifdef _WIN32
    auto config = GameJitModConfig::instance();
    if (config && config->EnableVBPool) {
        DS_LUAJIT_set_vbpool_enabled(true);
    }
    repalce_set_thread_name();
    InitGameOpenGl();
#endif
}