#pragma once
// Fetch manifest + download/verify/extract apply pipeline for plugin.manager.

#include "PluginPinConfig.hpp"
#include "PluginLocalInventory.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds::plugin_manager {

// Build configuration of THIS module, baked in by CMake ($<CONFIG>). Assets stamped
// with an INCOMPATIBLE configuration are refused (see build_config_compatible).
// "any" (the default when the macro is absent, e.g. ad-hoc test builds) disables the
// constraint — legacy manifests without a stamp stay installable.
#ifndef DS_PLUGIN_BUILD_CONFIG
#  define DS_PLUGIN_BUILD_CONFIG "any"
#endif
inline constexpr const char *kBuildConfigAny = "any";

// Build-configuration COMPATIBILITY CLASS (not an exact name match):
//   Windows/MSVC: Debug is isolated — it links the debug CRT (ucrtbased.dll,
//   msvcp140D.dll, vcruntime140D.dll), uses /MDd and _ITERATOR_DEBUG_LEVEL=2, and its
//   vcpkg deps are the *D-suffixed* ones (spdlogd/fmtd/zlibd1). Mixing those with a
//   Release-family module means different CRT DLLs, separate heaps and different STL
//   debug layouts -> LoadLibrary failure or silent cross-CRT heap/STL misuse.
//   Release / RelWithDebInfo / MinSizeRel all link /MD with IDL 0 and are
//   interchangeable (they differ only in optimisation/debug-info flags).
//   POSIX: one libstdc++/libc++ ABI (CMake Debug does not set _GLIBCXX_DEBUG), so the
//   axis does not exist there and any stamp pair is compatible.
// Empty or "any" on either side = unconstrained (legacy manifests, ad-hoc builds).
inline bool build_config_compatible(std::string_view asset_cfg, std::string_view self_cfg) {
    if (asset_cfg.empty() || self_cfg.empty() || asset_cfg == kBuildConfigAny ||
        self_cfg == kBuildConfigAny) {
        return true; // unconstrained side: legacy manifest / ad-hoc build
    }
#if defined(_WIN32)
    // Only the Debug vs Release-family boundary is an ABI boundary (debug CRT + IDL 2).
    return (asset_cfg == "Debug") == (self_cfg == "Debug");
#else
    return true; // no debug CRT / iterator-debug split in these builds
#endif
}

// Runtime platform key used in plugins-manifest platforms{}: windows|linux|macos.
std::string current_platform_key();

// Resolve release tag: explicit arg > cfg.release_tag > GitHub /releases/latest when follow_latest.
// Network via http_get_with_proxy. On failure returns nullopt and sets *err.
std::optional<std::string> resolve_release_tag(const ds::plugin::PluginPinConfig &cfg,
                                               const char *release_tag_or_null, std::string *err);

// GET plugins-manifest.json for tag; returns parsed JSON or nullopt.
std::optional<nlohmann::json> fetch_plugins_manifest(const ds::plugin::PluginPinConfig &cfg,
                                                     std::string_view release_tag, std::string *err);

// Fill channel_cache from manifest plugins[].id → version.
ds::plugin::ChannelVersionCache channel_cache_from_manifest(const nlohmann::json &manifest);

// Platform slot for plugin id from manifest (platforms[current] only; no foreign fallback).
// Returns {asset, sha256, module, files, version} or nullopt.

struct ManifestPluginAsset {
    std::string id;
    std::string version;
    std::string asset;
    std::string sha256; // module sha256 from manifest (verify module file after extract)
    std::string module;
    std::vector<std::string> files;
    std::string build_config; // platform slot stamp ("Release"…); empty/"any" = unconstrained
    // Package directory under <plugins_dir>/ (single safe segment) that `module` and
    // `files[]` are relative to. Always set: flat installs are not supported.
    std::string package;
};

std::optional<ManifestPluginAsset> lookup_manifest_asset(const nlohmann::json &manifest,
                                                         std::string_view plugin_id,
                                                         std::string_view platform_key,
                                                         std::string *err);

// Download asset zip, sha256-verify module, extract allowlisted files into plugins_dir
// (or update_pending on lock). Writes/overwrites meta.json from package when present.
// Sets *needs_restart when any file lands in update_pending or replaces an existing module.
// Refused = asset build configuration does not match this build (nothing downloaded).
enum class ApplyOneOutcome { Installed, Refused, Failed };

ApplyOneOutcome apply_one_plugin(const ds::plugin::PluginPinConfig &cfg,
                                 const nlohmann::json &manifest,
                                 const ManifestPluginAsset &asset,
                                 const std::filesystem::path &plugins_dir, bool *needs_restart,
                                 std::string *err);

// Progress snapshot for UI (apply / multi-step fetch).
struct ApplyProgress {
    std::string phase;     // resolve | download | extract | install | done | error
    size_t current = 0;    // 1-based step index when total > 0
    size_t total = 0;      // planned plugin actions (0 = indeterminate)
    std::string plugin_id; // current plugin id (may be empty)
    std::string message;   // short human status
};

using ApplyProgressFn = void (*)(const ApplyProgress &p, void *user);

// Apply plan actions (id filter optional). Uses g-level helpers in Api for cache/manifest.
// Pure-ish entry for testing with injected http + temp plugins_dir.
// `progress` may be null; called between steps (not during HTTP body stream).
struct ApplyResult {
    size_t attempted = 0;
    size_t succeeded = 0;
    // Skipped on purpose (build-configuration mismatch); not a failure and never
    // counted in succeeded. attempted == succeeded + refused means "nothing failed".
    size_t refused = 0;
    bool needs_restart = false;
    std::string last_error;
};

ApplyResult apply_plan(const ds::plugin::PluginPinConfig &cfg, const nlohmann::json &manifest,
                       const std::vector<ds::plugin::PlanAction> &actions,
                       const std::filesystem::path &plugins_dir,
                       std::string_view only_id_or_empty,
                       ApplyProgressFn progress = nullptr, void *progress_user = nullptr);

// Install extracted files: try plugins_dir first; on open/write failure of an existing
// locked target, write to plugins_dir/update_pending/ instead.
// Returns true if all files installed (direct or pending). *used_pending set when any pending.
// Package layout only: members install into <plugins_dir>/<package>/ and the lock
// fallback writes to <plugins_dir>/update_pending/<package>/ (mirrors the mover).
bool install_extracted_files(const std::filesystem::path &staging_dir,
                             const std::filesystem::path &plugins_dir, std::string_view package,
                             const std::vector<std::string> &members, bool *used_pending,
                             std::string *err);

} // namespace ds::plugin_manager
