#include "SignatureManager.hpp"
#include "SignatureResolveApi.hpp"

#include "PluginPath.hpp"

#include "SignatureCache.hpp"

#include "util/GameVersionFile.hpp"
#include "util/PathText.hpp"

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ds::sig {
namespace {

using namespace std::literals;

// The Lua DB's version file, resolved relative to the process CWD (bin64/),
// exactly like SignatureJson::version_path.
constexpr const char *kVersionPath = "../version.txt";

struct State {
    std::mutex mutex;
    RuntimeTarget target;
    std::vector<ProviderV1> providers;
    // "<owner>.<symbol>" -> index into providers. Names are unique per platform,
    // so the Manager answers ownership instead of asking every provider in turn.
    std::unordered_map<std::string, size_t> name_index;
    std::unordered_map<std::string, ResolveReport> memo;
    // Lazily derived once the mod root is discoverable; empty means "no cache".
    std::string cache_path;
    bool cache_path_resolved = false;
    std::string module_digest;
    bool digest_computed = false;
};

State &state() {
    static State s;
    return s;
}

std::string derive_cache_path(const RuntimeTarget &target) {
    std::filesystem::path root;
    for (const auto &dir : ds::plugin::default_plugin_search_dirs()) {
        root = ds::plugin::mod_root_from_plugins_dir(dir);
        if (!root.empty()) {
            break;
        }
    }
    if (root.empty()) {
        // Package root layouts place Injector.dll/libilnjector next to Mod/.
        root = ds::plugin::injector_module_dir();
    }
    if (root.empty()) {
        return {};
    }
    const std::string file = "plugin_signatures_"s + (target.is_client ? "client" : "server") + ".json";
    // The cache is opened by narrow stdio/nlohmann: keep ANSI when it maps and fall
    // back to UTF-8 instead of throwing on an unrepresentable root (same rule the
    // Lua DB path follows).
    return ds::util::path_to_native_lossy(root / file);
}

void fill_context(ContextView &ctx, State &s) {
    ctx.platform = s.target.platform;
    ctx.is_client = s.target.is_client ? 1 : 0;
    ctx.module_path = s.target.module_path.empty() ? nullptr : s.target.module_path.c_str();
    ctx.module_base = s.target.module_base;
    ctx.module_size = s.target.module_size;
    ctx.game_version = s.target.game_version.empty() ? nullptr : s.target.game_version.c_str();
    if (!s.cache_path_resolved) {
        s.cache_path_resolved = true;
        s.cache_path = derive_cache_path(s.target);
    }
    ctx.cache_path = s.cache_path.empty() ? nullptr : s.cache_path.c_str();
    if (!s.digest_computed) {
        s.digest_computed = true;
        std::error_code ec;
        const bool cache_exists =
                !s.cache_path.empty() && std::filesystem::exists(std::filesystem::path{s.cache_path}, ec);
        if (cache_exists) {
            s.module_digest = module_content_digest(ctx.module_path);
            if (s.module_digest.empty()) {
                spdlog::warn("[signature] target content digest unavailable for {}; cache identity starts disabled",
                             ctx.module_path ? ctx.module_path : "<main module>");
            }
        }
    }
    ctx.module_digest = s.module_digest.empty() ? nullptr : s.module_digest.c_str();
}

bool provider_well_formed(const ProviderV1 *provider, std::string *detail) {
    if (!provider) {
        if (detail) *detail = "null provider";
        return false;
    }
    if (provider->struct_size != sizeof(ProviderV1)) {
        if (detail) *detail = "provider struct_size mismatch";
        return false;
    }
    if (provider->interface_version != kProviderInterfaceVersion) {
        if (detail) *detail = "provider interface_version mismatch";
        return false;
    }
    if (!provider->entry_count || !provider->entry_at || !provider->get_cached ||
        !provider->extract_from_file || !provider->resolve) {
        if (detail) *detail = "provider entry point missing";
        return false;
    }
    const uint32_t count = provider->entry_count(provider->self);
    for (uint32_t i = 0; i < count; ++i) {
        EntryView view{};
        if (!provider->entry_at(provider->self, i, &view)) {
            if (detail) *detail = "provider entry_at() failed";
            return false;
        }
        if (view.name[0] == '\0' || view.owner[0] == '\0') {
            if (detail) *detail = "provider entry has an empty owner/name";
            return false;
        }
        std::string expected{view.owner};
        expected += '.';
        if (std::strncmp(view.name, expected.c_str(), expected.size()) != 0) {
            if (detail) *detail = "provider entry name is not '<owner>.<symbol>': " + std::string{view.name};
            return false;
        }
        if (view.platform_mask == kPlatformNone) {
            if (detail) *detail = "provider entry names no platform: " + std::string{view.name};
            return false;
        }
    }
    return true;
}

} // namespace

void configure_runtime(const RuntimeTarget &target) {
    auto &s = state();
    std::lock_guard lock(s.mutex);
    s.target = target;
    if (s.target.module_path.empty()) {
        if (auto *main_module = gum_process_get_main_module()) {
            s.target.module_path = gum_module_get_path(main_module);
            if (auto *range = gum_module_get_range(main_module)) {
                s.target.module_base = range->base_address;
                s.target.module_size = range->size;
            }
        }
    }
    if (s.target.game_version.empty()) {
        const auto version = readGameVersion(kVersionPath);
        if (version != static_cast<uintptr_t>(-1)) {
            s.target.game_version = std::to_string(version);
        }
    }
    s.cache_path_resolved = false;
    s.digest_computed = false;
    spdlog::info("[signature] runtime target platform={} is_client={} module=\"{}\" version={}",
                 platform_name(s.target.platform), s.target.is_client, s.target.module_path,
                 s.target.game_version);
}

RuntimeTarget runtime_target() {
    auto &s = state();
    std::lock_guard lock(s.mutex);
    return s.target;
}

bool validate_provider(const ProviderV1 *provider, std::string *detail) {
    if (!provider_well_formed(provider, detail)) {
        return false;
    }
    auto &s = state();
    std::lock_guard lock(s.mutex);
    const uint32_t count = provider->entry_count(provider->self);
    for (uint32_t i = 0; i < count; ++i) {
        EntryView view{};
        if (!provider->entry_at(provider->self, i, &view)) {
            if (detail) *detail = "provider entry_at() failed";
            return false;
        }
        for (const auto &existing : s.providers) {
            const uint32_t existing_count = existing.entry_count(existing.self);
            for (uint32_t j = 0; j < existing_count; ++j) {
                EntryView other{};
                if (!existing.entry_at(existing.self, j, &other)) {
                    continue;
                }
                if (std::strcmp(view.name, other.name) == 0 &&
                    masks_overlap(view.platform_mask, other.platform_mask)) {
                    if (detail) *detail = "duplicate signature name: " + std::string{view.name};
                    return false;
                }
            }
        }
    }
    return true;
}

bool add_provider(const ProviderV1 *provider, std::string *detail) {
    if (!validate_provider(provider, detail)) {
        return false;
    }
    auto &s = state();
    std::lock_guard lock(s.mutex);
    // The table is POD and owned by the publishing module for the process
    // lifetime; copy the table itself so a module that unloads its data segment
    // can never leave us calling through a dangling struct pointer.
    s.providers.push_back(*provider);
    const auto copied = s.providers.back();
    const size_t index = s.providers.size() - 1;
    const uint32_t count = copied.entry_count(copied.self);
    for (uint32_t i = 0; i < count; ++i) {
        EntryView view{};
        if (!copied.entry_at(copied.self, i, &view)) {
            continue;
        }
        // Platform variants of one name share the owner, so the first index wins.
        s.name_index.emplace(view.name, index);
    }
    EntryView first{};
    (void) copied.entry_at(copied.self, 0, &first);
    spdlog::info("[signature] provider registered owner={} entries={}", first.owner, count);
    return true;
}

bool resolve_entry(const char *name, ResolveReport *out) {
    if (!out) {
        return false;
    }
    *out = ResolveReport{};
    if (!name || !*name) {
        out->status = ResolveStatus::Internal;
        std::snprintf(out->detail, sizeof(out->detail), "empty signature name");
        return false;
    }
    auto &s = state();
    std::lock_guard lock(s.mutex);
    if (const auto memo = s.memo.find(name); memo != s.memo.end()) {
        *out = memo->second;
        return out->status == ResolveStatus::Resolved;
    }

    ContextView ctx{};
    fill_context(ctx, s);
    if (ctx.platform == kPlatformNone) {
        out->status = ResolveStatus::Unsupported;
        std::snprintf(out->detail, sizeof(out->detail), "unsupported host platform");
        s.memo.emplace(name, *out);
        return false;
    }

    const auto owner = s.name_index.find(name);
    if (owner == s.name_index.end()) {
        out->status = ResolveStatus::Internal;
        std::snprintf(out->detail, sizeof(out->detail), "no registered provider owns this signature name");
        spdlog::warn("[signature] {} -> {}", name, out->detail);
    } else {
        const auto &provider = s.providers[owner->second];
        ResolveReport candidate{};
        const bool ok = provider.resolve(provider.self, name, &ctx, &candidate);
        *out = candidate;
        if (!ok) {
            spdlog::warn("[signature] {} -> {} ({})", name, candidate.detail, static_cast<int>(candidate.status));
        } else if (candidate.from_cache) {
            spdlog::info("[signature] {} -> {:#x} (cache)", name, candidate.target_va);
        } else {
            spdlog::info("[signature] {} -> {:#x} (scan)", name, candidate.target_va);
        }
    }
    s.memo.emplace(name, *out);
    return out->status == ResolveStatus::Resolved;
}

std::vector<std::string> provider_owners() {
    auto &s = state();
    std::lock_guard lock(s.mutex);
    std::vector<std::string> owners;
    for (const auto &provider : s.providers) {
        EntryView view{};
        if (provider.entry_at(provider.self, 0, &view)) {
            owners.emplace_back(view.owner);
        }
    }
    return owners;
}

} // namespace ds::sig

int32_t ds_signature_resolve_ex(const char *name, uint64_t *target_address, char *detail, uint32_t detail_cap) {
    ds::sig::ResolveReport report{};
    const bool ok = ds::sig::resolve_entry(name, &report);
    if (ok && target_address) {
        *target_address = report.target_va;
    }
    if (detail && detail_cap) {
        const size_t n = std::strlen(report.detail);
        const size_t write = n < detail_cap - 1 ? n : static_cast<size_t>(detail_cap) - 1;
        std::memcpy(detail, report.detail, write);
        detail[write] = '\0';
    }
    return static_cast<int32_t>(report.status);
}
