#include "PluginApply.hpp"
#include "PluginDownloadUrl.hpp"
#include "PluginHash.hpp"
#include "PluginHttp.hpp"
#include "PluginZipExtract.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif
namespace ds::plugin_manager {
namespace {

constexpr int kHttpTimeoutMs = 60000;
constexpr int kAutoDirectTimeoutMs = 3000;

std::string github_api_base_from_github_base(std::string_view github_base) {
    // https://github.com → https://api.github.com
    // Custom GHES-style bases: {base}/api/v3 (best-effort; default path is fine for github.com).
    const std::string_view base = trim_trailing_slashes(github_base);
    if (base == "https://github.com" || base == "http://github.com") {
        return "https://api.github.com";
    }
    std::string out(base);
    out.append("/api/v3");
    return out;
}

bool file_looks_locked_or_unwritable(const std::filesystem::path &path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return false;
    }
    // Try open for write without truncating first via rename probe:
    // open with app mode to check share/lock.
    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!f.is_open()) {
        return true;
    }
    return false;
}

bool try_write_bytes(const std::filesystem::path &path, const std::string &bytes, std::string *err) {
    std::error_code ec;
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path(), ec);
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        if (err) {
            *err = "cannot open for write: " + path.generic_string();
        }
        return false;
    }
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!out) {
        if (err) {
            *err = "write failed: " + path.generic_string();
        }
        return false;
    }
    return true;
}

bool copy_file_overwrite(const std::filesystem::path &from, const std::filesystem::path &to,
                         std::string *err) {
    std::error_code ec;
    if (!to.parent_path().empty()) {
        std::filesystem::create_directories(to.parent_path(), ec);
    }
    // Prefer remove + rename for atomic-ish replace when possible.
    if (std::filesystem::exists(to, ec)) {
        std::filesystem::remove(to, ec);
    }
    std::filesystem::rename(from, to, ec);
    if (!ec) {
        return true;
    }
    ec.clear();
    std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        if (err) {
            *err = "copy failed: " + from.generic_string() + " -> " + to.generic_string() + " (" +
                   ec.message() + ")";
        }
        return false;
    }
    std::filesystem::remove(from, ec);
    return true;
}

} // namespace

std::string current_platform_key() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

std::optional<std::string> resolve_release_tag(const ds::plugin::PluginPinConfig &cfg,
                                               const char *release_tag_or_null, std::string *err) {
    if (release_tag_or_null && release_tag_or_null[0]) {
        return std::string(release_tag_or_null);
    }
    if (!cfg.release_tag.empty()) {
        return cfg.release_tag;
    }
    if (!cfg.follow_latest) {
        if (err) {
            *err = "resolve_release_tag: no release_tag and follow_latest=false";
        }
        return std::nullopt;
    }

    // GitHub API: GET /repos/{repo}/releases/latest → tag_name
    const std::string api = github_api_base_from_github_base(cfg.github_base) + "/repos/" +
                            cfg.repo + "/releases/latest";
    std::string body;
    std::string http_err;
    if (!http_get_with_proxy(api, cfg.gh_proxy_base, cfg.prefer_proxy, kHttpTimeoutMs, &body,
                             &http_err, kAutoDirectTimeoutMs)) {
        if (err) {
            *err = "resolve_release_tag: " + http_err;
        }
        return std::nullopt;
    }
    try {
        auto j = nlohmann::json::parse(body);
        if (!j.contains("tag_name") || !j["tag_name"].is_string()) {
            if (err) {
                *err = "resolve_release_tag: latest response missing tag_name";
            }
            return std::nullopt;
        }
        return j["tag_name"].get<std::string>();
    } catch (const std::exception &ex) {
        if (err) {
            *err = std::string("resolve_release_tag: parse error: ") + ex.what();
        }
        return std::nullopt;
    }
}

std::optional<nlohmann::json> fetch_plugins_manifest(const ds::plugin::PluginPinConfig &cfg,
                                                     std::string_view release_tag,
                                                     std::string *err) {
    if (release_tag.empty()) {
        if (err) {
            *err = "fetch_manifest: empty release_tag";
        }
        return std::nullopt;
    }
    const std::string direct =
        release_asset_url(cfg.github_base, cfg.repo, release_tag, "plugins-manifest.json");
    std::string body;
    std::string http_err;
    if (!http_get_with_proxy(direct, cfg.gh_proxy_base, cfg.prefer_proxy, kHttpTimeoutMs, &body,
                             &http_err, kAutoDirectTimeoutMs)) {
        if (err) {
            *err = "fetch_manifest: " + http_err;
        }
        return std::nullopt;
    }
    try {
        auto j = nlohmann::json::parse(body);
        if (!j.is_object()) {
            if (err) {
                *err = "fetch_manifest: root not object";
            }
            return std::nullopt;
        }
        return j;
    } catch (const std::exception &ex) {
        if (err) {
            *err = std::string("fetch_manifest: parse error: ") + ex.what();
        }
        return std::nullopt;
    }
}

ds::plugin::ChannelVersionCache channel_cache_from_manifest(const nlohmann::json &manifest) {
    ds::plugin::ChannelVersionCache cache;
    if (!manifest.contains("plugins") || !manifest["plugins"].is_array()) {
        return cache;
    }
    for (const auto &p : manifest["plugins"]) {
        if (!p.is_object()) {
            continue;
        }
        if (!p.contains("id") || !p["id"].is_string()) {
            continue;
        }
        if (!p.contains("version") || !p["version"].is_string()) {
            continue;
        }
        cache[p["id"].get<std::string>()] = p["version"].get<std::string>();
    }
    return cache;
}

std::optional<ManifestPluginAsset> lookup_manifest_asset(const nlohmann::json &manifest,
                                                         std::string_view plugin_id,
                                                         std::string_view platform_key,
                                                         std::string *err) {
    if (!manifest.contains("plugins") || !manifest["plugins"].is_array()) {
        if (err) {
            *err = "manifest: missing plugins[]";
        }
        return std::nullopt;
    }
    const nlohmann::json *entry = nullptr;
    for (const auto &p : manifest["plugins"]) {
        if (!p.is_object() || !p.contains("id") || !p["id"].is_string()) {
            continue;
        }
        if (p["id"].get<std::string>() == plugin_id) {
            entry = &p;
            break;
        }
    }
    if (!entry) {
        if (err) {
            *err = "manifest: plugin not found: " + std::string(plugin_id);
        }
        return std::nullopt;
    }

    ManifestPluginAsset out;
    out.id = (*entry)["id"].get<std::string>();
    if (entry->contains("version") && (*entry)["version"].is_string()) {
        out.version = (*entry)["version"].get<std::string>();
    }

    if (!entry->contains("platforms") || !(*entry)["platforms"].is_object()) {
        if (err) {
            *err = "manifest: no platforms for " + out.id;
        }
        return std::nullopt;
    }
    const auto &plats = (*entry)["platforms"];
    const nlohmann::json *slot = nullptr;
    if (plats.contains(std::string(platform_key)) && plats[std::string(platform_key)].is_object()) {
        slot = &plats[std::string(platform_key)];
    } else {
        // Fallback: first available platform entry.
        for (auto it = plats.begin(); it != plats.end(); ++it) {
            if (it.value().is_object()) {
                slot = &it.value();
                break;
            }
        }
    }
    if (!slot) {
        if (err) {
            *err = "manifest: no platform slot for " + out.id;
        }
        return std::nullopt;
    }
    if (slot->contains("available") && (*slot)["available"].is_boolean() &&
        !(*slot)["available"].get<bool>()) {
        if (err) {
            *err = "manifest: platform unavailable for " + out.id;
        }
        return std::nullopt;
    }
    auto req_str = [&](const char *key, std::string &dst) -> bool {
        if (!slot->contains(key) || !(*slot)[key].is_string() || (*slot)[key].get<std::string>().empty()) {
            if (err) {
                *err = std::string("manifest: missing ") + key + " for " + out.id;
            }
            return false;
        }
        dst = (*slot)[key].get<std::string>();
        return true;
    };
    if (!req_str("asset", out.asset) || !req_str("sha256", out.sha256) ||
        !req_str("module", out.module)) {
        return std::nullopt;
    }
    if (slot->contains("files") && (*slot)["files"].is_array()) {
        for (const auto &f : (*slot)["files"]) {
            if (f.is_string()) {
                out.files.push_back(f.get<std::string>());
            }
        }
    }
    return out;
}

bool install_extracted_files(const std::filesystem::path &staging_dir,
                             const std::filesystem::path &plugins_dir,
                             const std::vector<std::string> &basenames, bool *used_pending,
                             std::string *err) {
    if (used_pending) {
        *used_pending = false;
    }
    std::error_code ec;
    std::filesystem::create_directories(plugins_dir, ec);
    const auto pending_dir = plugins_dir / "update_pending";

    for (const auto &name : basenames) {
        const auto src = staging_dir / name;
        if (!std::filesystem::is_regular_file(src, ec)) {
            continue; // optional meta may be absent
        }
        const auto dest = plugins_dir / name;
        bool go_pending = false;
        if (std::filesystem::exists(dest, ec) && file_looks_locked_or_unwritable(dest)) {
            go_pending = true;
        } else {
            std::string copy_err;
            if (!copy_file_overwrite(src, dest, &copy_err)) {
                // Fall back to pending on any write failure (DLL lock common on Windows).
                go_pending = true;
            }
        }
        if (go_pending) {
            std::filesystem::create_directories(pending_dir, ec);
            const auto pend = pending_dir / name;
            std::string copy_err;
            // Re-copy from staging (src may already have been moved).
            if (!std::filesystem::exists(src, ec)) {
                // Already moved? try dest was partial — read from pending fail.
                if (err) {
                    *err = "install: staging missing after failed direct write: " + name;
                }
                return false;
            }
            // If direct copy partially removed src via rename, recover from dest? Prefer copy.
            // copy_file_overwrite may have removed src on success only; on failure src remains.
            if (!copy_file_overwrite(src, pend, &copy_err)) {
                if (err) {
                    *err = "install: pending write failed for " + name + ": " + copy_err;
                }
                return false;
            }
            if (used_pending) {
                *used_pending = true;
            }
            std::fprintf(stderr, "[plugin_manager] install pending: %s\n", pend.string().c_str());
        } else {
            std::fprintf(stderr, "[plugin_manager] install: %s\n", dest.string().c_str());
        }
    }
    return true;
}

bool apply_one_plugin(const ds::plugin::PluginPinConfig &cfg, const nlohmann::json &manifest,
                      const ManifestPluginAsset &asset, const std::filesystem::path &plugins_dir,
                      bool *needs_restart, std::string *err) {
    (void)manifest;
    if (asset.asset.empty() || asset.module.empty()) {
        if (err) {
            *err = "apply: incomplete asset for " + asset.id;
        }
        return false;
    }

    // Tag for download: prefer manifest release_tag field if present, else cfg.
    std::string tag = cfg.release_tag;
    // Caller should have set cfg.release_tag / resolved; also accept top-level later via
    // apply_plan which patches tag into a local cfg copy.

    if (tag.empty()) {
        if (err) {
            *err = "apply: empty release_tag for download of " + asset.id;
        }
        return false;
    }

    const std::string direct =
        release_asset_url(cfg.github_base, cfg.repo, tag, asset.asset);
    std::string zip_bytes;
    std::string http_err;
    if (!http_get_with_proxy(direct, cfg.gh_proxy_base, cfg.prefer_proxy, kHttpTimeoutMs, &zip_bytes,
                             &http_err, kAutoDirectTimeoutMs)) {
        if (err) {
            *err = "apply download: " + http_err;
        }
        return false;
    }
    if (zip_bytes.size() < 4 || zip_bytes[0] != 'P' || zip_bytes[1] != 'K') {
        if (err) {
            *err = "apply: downloaded asset is not a zip for " + asset.id;
        }
        return false;
    }

    std::error_code ec;
    const auto staging =
        std::filesystem::temp_directory_path(ec) /
        ("ds_plugin_apply_" + asset.id + "_" + std::to_string(
#ifdef _WIN32
                                                   GetCurrentProcessId()
#else
                                                   static_cast<unsigned>(::getpid())
#endif
                                                       ));
    std::filesystem::remove_all(staging, ec);
    std::filesystem::create_directories(staging, ec);

    std::string zerr;
    auto extracted =
        extract_plugin_zip_memory(zip_bytes.data(), zip_bytes.size(), staging, asset.files, &zerr);
    if (!extracted.has_value()) {
        std::filesystem::remove_all(staging, ec);
        if (err) {
            *err = "apply extract: " + zerr;
        }
        return false;
    }
    if (*extracted == 0) {
        std::filesystem::remove_all(staging, ec);
        if (err) {
            *err = "apply: no allowlisted files extracted for " + asset.id;
        }
        return false;
    }

    // Verify module sha256 against manifest (module file hash, not zip hash).
    const auto module_path = staging / asset.module;
    if (!std::filesystem::is_regular_file(module_path, ec)) {
        std::filesystem::remove_all(staging, ec);
        if (err) {
            *err = "apply: module missing after extract: " + asset.module;
        }
        return false;
    }
    auto digest = sha256_file_hex(module_path);
    if (!digest.has_value() || !sha256_hex_equal(*digest, asset.sha256)) {
        std::filesystem::remove_all(staging, ec);
        if (err) {
            *err = "apply: sha256 mismatch for " + asset.module +
                   " (got " + digest.value_or("<read-error>") + ", expected " + asset.sha256 + ")";
        }
        return false;
    }

    // Collect basenames actually present in staging (allowlist ∩ extracted).
    std::vector<std::string> basenames;
    if (!asset.files.empty()) {
        basenames = asset.files;
    } else {
        for (const auto &entry : std::filesystem::directory_iterator(staging, ec)) {
            if (entry.is_regular_file(ec)) {
                basenames.push_back(entry.path().filename().string());
            }
        }
    }

    bool used_pending = false;
    std::string ierr;
    if (!install_extracted_files(staging, plugins_dir, basenames, &used_pending, &ierr)) {
        std::filesystem::remove_all(staging, ec);
        if (err) {
            *err = ierr;
        }
        return false;
    }
    std::filesystem::remove_all(staging, ec);

    if (needs_restart && used_pending) {
        *needs_restart = true;
    }
    // Replacing a module that may already be loaded also warrants restart.
    if (needs_restart) {
        *needs_restart = true;
    }
    return true;
}

ApplyResult apply_plan(const ds::plugin::PluginPinConfig &cfg, const nlohmann::json &manifest,
                       const std::vector<ds::plugin::PlanAction> &actions,
                       const std::filesystem::path &plugins_dir,
                       std::string_view only_id_or_empty) {
    ApplyResult result;
    if (plugins_dir.empty()) {
        result.last_error = "apply: empty plugins_dir";
        return result;
    }

    // Resolve tag once: manifest.release_tag or cfg.
    ds::plugin::PluginPinConfig cfg_local = cfg;
    if (cfg_local.release_tag.empty() && manifest.contains("release_tag") &&
        manifest["release_tag"].is_string()) {
        cfg_local.release_tag = manifest["release_tag"].get<std::string>();
    }
    if (cfg_local.release_tag.empty()) {
        result.last_error = "apply: cannot determine release_tag";
        return result;
    }

    const std::string platform = current_platform_key();

    for (const auto &action : actions) {
        if (!only_id_or_empty.empty() && action.id != only_id_or_empty) {
            continue;
        }
        // prefer_present with empty `to` and no channel entry may still try channel version.
        ++result.attempted;
        std::string lerr;
        auto asset = lookup_manifest_asset(manifest, action.id, platform, &lerr);
        if (!asset) {
            result.last_error = lerr;
            std::fprintf(stderr, "[plugin_manager] apply skip %s: %s\n", action.id.c_str(),
                         lerr.c_str());
            continue;
        }
        // If plan targets a specific version and manifest has different, still apply manifest
        // asset for that id (channel catalog is SSOT for downloadable bits).
        bool nr = false;
        if (!apply_one_plugin(cfg_local, manifest, *asset, plugins_dir, &nr, &lerr)) {
            result.last_error = lerr;
            std::fprintf(stderr, "[plugin_manager] apply fail %s: %s\n", action.id.c_str(),
                         lerr.c_str());
            continue;
        }
        ++result.succeeded;
        if (nr) {
            result.needs_restart = true;
        }
    }

    if (result.attempted > 0 && result.succeeded == 0 && result.last_error.empty()) {
        result.last_error = "apply: no matching actions";
    }
    return result;
}

} // namespace ds::plugin_manager
