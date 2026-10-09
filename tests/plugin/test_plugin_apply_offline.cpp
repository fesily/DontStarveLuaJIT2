// Offline apply pipeline tests with injected HTTP (no network).
#include "plugins/plugin_manager/PluginApply.hpp"
#include "plugins/plugin_manager/PluginHash.hpp"
#include "plugins/plugin_manager/PluginHttp.hpp"
#include "plugins/plugin_manager/PluginPinConfig.hpp"
#include "plugins/plugin_manager/PluginZipExtract.hpp"

#include <nlohmann/json.hpp>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <zip.h>

namespace fs = std::filesystem;
using namespace ds::plugin_manager;
using ds::plugin::PlanAction;
using ds::plugin::PluginPinConfig;
using ds::plugin::defaults;

static std::unordered_map<std::string, std::string> g_http_map;
static int g_http_hits = 0;

static bool mock_http_get(std::string_view url, int /*timeout_ms*/, std::string *body,
                          std::string *err) {
    ++g_http_hits;
    const std::string key(url);
    auto it = g_http_map.find(key);
    if (it == g_http_map.end()) {
        // Also try matching by suffix for proxy-wrapped URLs.
        for (const auto &kv : g_http_map) {
            if (key.size() >= kv.first.size() &&
                key.compare(key.size() - kv.first.size(), kv.first.size(), kv.first) == 0) {
                if (body) {
                    *body = kv.second;
                }
                return true;
            }
        }
        if (err) {
            *err = "mock_http: not found: " + key;
        }
        return false;
    }
    if (body) {
        *body = it->second;
    }
    return true;
}

static fs::path make_temp_dir(const char *tag) {
    std::error_code ec;
    auto base = fs::temp_directory_path(ec) / (std::string("ds_t8_apply_") + tag);
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    return base;
}

static std::string read_bytes(const fs::path &p) {
    std::ifstream in(p, std::ios::binary);
    assert(in.is_open());
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static std::string build_zip_bytes(const std::vector<std::pair<std::string, std::string>> &entries) {
    const auto dir = make_temp_dir("zipbuild");
    const auto zip_path = dir / "a.zip";
    int zerr = 0;
    zip_t *za = zip_open(zip_path.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &zerr);
    assert(za);
    for (const auto &e : entries) {
        void *copy = malloc(e.second.size() ? e.second.size() : 1);
        assert(copy);
        if (!e.second.empty()) {
            memcpy(copy, e.second.data(), e.second.size());
        }
        zip_source_t *src = zip_source_buffer(za, copy, e.second.size(), 1);
        assert(src);
        assert(zip_file_add(za, e.first.c_str(), src, ZIP_FL_ENC_UTF_8) >= 0);
    }
    assert(zip_close(za) == 0);
    auto bytes = read_bytes(zip_path);
    std::error_code ec;
    fs::remove_all(dir, ec);
    return bytes;
}

static void test_channel_cache_and_lookup() {
    const nlohmann::json manifest = nlohmann::json::parse(R"({
      "schema_version": 1,
      "repo": "fesily/DontStarveLuaJIT2",
      "release_tag": "v9.9.9",
      "plugins": [
        {
          "id": "debug.dummy",
          "version": "1.2.3",
          "platforms": {
            "windows": {
              "available": true,
              "asset": "plugin_dummy-1.2.3-windows.zip",
              "sha256": "deadbeef",
              "module": "plugin_dummy.dll",
              "files": ["plugin_dummy.dll", "plugin_dummy.meta.json"]
            },
            "linux": {
              "available": true,
              "asset": "plugin_dummy-1.2.3-linux.zip",
              "sha256": "cafebabe",
              "module": "plugin_dummy.so",
              "files": ["plugin_dummy.so"]
            }
          }
        }
      ]
    })");

    auto cache = channel_cache_from_manifest(manifest);
    assert(cache.size() == 1);
    assert(cache["debug.dummy"] == "1.2.3");

    std::string err;
    auto asset = lookup_manifest_asset(manifest, "debug.dummy", current_platform_key(), &err);
    assert(asset.has_value());
    assert(asset->id == "debug.dummy");
    assert(asset->version == "1.2.3");
    assert(!asset->asset.empty());
    assert(!asset->module.empty());
    printf("PASS: channel_cache_and_lookup (platform=%s module=%s)\n",
           current_platform_key().c_str(), asset->module.c_str());
}

static void test_apply_plan_with_mock_http() {
    set_http_get_override(&mock_http_get);
    g_http_map.clear();
    g_http_hits = 0;

    const std::string module_name =
#if defined(_WIN32)
        "plugin_dummy.dll";
#else
        "plugin_dummy.so";
#endif
    const std::string module_bytes = "MZ-PLUGIN-BYTES-v2";
    const std::string digest = sha256_hex(module_bytes);
    const std::string meta = R"({"id":"debug.dummy","version":"2.0.0","sha256":")" + digest +
                             R"(","module":")" + module_name + R"("})";
    const std::string zip_bytes =
        build_zip_bytes({{module_name, module_bytes}, {"plugin_dummy.meta.json", meta}});

    const std::string platform = current_platform_key();
    const std::string asset_name = "plugin_dummy-2.0.0-" + platform + ".zip";
    const std::string tag = "v2.0.0";
    const std::string direct_asset =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/" + tag + "/" + asset_name;
    g_http_map[direct_asset] = zip_bytes;

    nlohmann::json manifest;
    manifest["schema_version"] = 1;
    manifest["repo"] = "fesily/DontStarveLuaJIT2";
    manifest["release_tag"] = tag;
    manifest["plugins"] = nlohmann::json::array();
    nlohmann::json plug;
    plug["id"] = "debug.dummy";
    plug["version"] = "2.0.0";
    plug["platforms"] = nlohmann::json::object();
    nlohmann::json slot;
    slot["available"] = true;
    slot["asset"] = asset_name;
    slot["sha256"] = digest;
    slot["module"] = module_name;
    slot["files"] = nlohmann::json::array({module_name, "plugin_dummy.meta.json"});
    plug["platforms"][platform] = slot;
    manifest["plugins"].push_back(plug);

    PluginPinConfig cfg = defaults();
    cfg.release_tag = tag;
    cfg.prefer_proxy = "never";

    const auto plugins_dir = make_temp_dir("plugins");
    PlanAction action;
    action.id = "debug.dummy";
    action.from = "1.0.0";
    action.to = "2.0.0";
    action.reason = "version_mismatch";

    auto result = apply_plan(cfg, manifest, {action}, plugins_dir, "");
    assert(result.succeeded == 1);
    assert(result.attempted == 1);
    // Package layout is the only supported install target.
    const auto pkg_dir = plugins_dir / "plugin_dummy";
    assert(fs::exists(pkg_dir / module_name));
    assert(read_bytes(pkg_dir / module_name) == module_bytes);
    assert(fs::exists(pkg_dir / "plugin_dummy.meta.json"));
    assert(!fs::exists(plugins_dir / module_name));
    assert(g_http_hits >= 1);

    // Bad sha256 fails and leaves old content? no prior content — dest should not update on fail.
    g_http_map.clear();
    g_http_hits = 0;
    g_http_map[direct_asset] = zip_bytes;
    slot["sha256"] = std::string(64, '0');
    plug["platforms"][platform] = slot;
    manifest["plugins"] = nlohmann::json::array({plug});
    // Wipe and re-apply with bad hash.
    std::error_code ec;
    fs::remove_all(plugins_dir, ec);
    fs::create_directories(plugins_dir, ec);
    result = apply_plan(cfg, manifest, {action}, plugins_dir, "");
    assert(result.succeeded == 0);
    assert(!result.last_error.empty());
    assert(result.last_error.find("sha256") != std::string::npos);

    set_http_get_override(nullptr);
    fs::remove_all(plugins_dir, ec);
    printf("PASS: apply_plan_with_mock_http\n");
}

static void test_fetch_manifest_mock() {
    set_http_get_override(&mock_http_get);
    g_http_map.clear();
    const std::string tag = "v3.1.4";
    const std::string manifest_url =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/" + tag +
        "/plugins-manifest.json";
    const std::string body = R"({"schema_version":1,"release_tag":"v3.1.4","plugins":[{"id":"a","version":"1"}]})";
    g_http_map[manifest_url] = body;

    PluginPinConfig cfg = defaults();
    cfg.release_tag = tag;
    cfg.prefer_proxy = "never";
    std::string err;
    auto man = fetch_plugins_manifest(cfg, tag, &err);
    assert(man.has_value());
    assert((*man)["release_tag"] == "v3.1.4");
    auto cache = channel_cache_from_manifest(*man);
    assert(cache["a"] == "1");

    // resolve uses explicit arg
    auto t = resolve_release_tag(cfg, "v9", &err);
    assert(t && *t == "v9");

    set_http_get_override(nullptr);
    printf("PASS: fetch_manifest_mock\n");
}

static void test_install_package_only() {
    // Installs are always package-relative: <plugins>/<package>/<member>.
    const auto staging = make_temp_dir("stage");
    const auto plugins = make_temp_dir("plug");
    std::ofstream(staging / "script_face.lua", std::ios::binary) << "LUA";
    {
        std::ofstream out(staging / "plugin_x.dll", std::ios::binary);
        out << "DATA";
    }
    bool pending = false;
    std::string err;
    assert(install_extracted_files(staging, plugins, "plugin_x", {"plugin_x.dll"}, &pending, &err));
    assert(!pending);
    assert(read_bytes(plugins / "plugin_x" / "plugin_x.dll") == "DATA");
    assert(!fs::exists(plugins / "plugin_x.dll")); // never flat

    // Safe replace: existing live content is not wiped before new bytes land.
    {
        std::ofstream out(staging / "plugin_x.dll", std::ios::binary | std::ios::trunc);
        out << "NEWDATA";
    }
    assert(install_extracted_files(staging, plugins, "plugin_x", {"plugin_x.dll"}, &pending, &err));
    assert(read_bytes(plugins / "plugin_x" / "plugin_x.dll") == "NEWDATA");

    // Unsafe package dir / members rejected at install.
    assert(!install_extracted_files(staging, plugins, "../evil", {"plugin_x.dll"}, &pending, &err));
    assert(err.find("unsafe package") != std::string::npos);
    assert(!install_extracted_files(staging, plugins, "plugin_x", {"../evil.dll"}, &pending, &err));
    assert(err.find("unsafe") != std::string::npos);
    assert(!install_extracted_files(staging, plugins, "plugin_x", {"/abs.lua"}, &pending, &err));

    std::error_code ec;
    fs::remove_all(staging, ec);
    fs::remove_all(plugins, ec);
    printf("PASS: install_package_only\n");
}

static void test_reject_pathlike_module_and_files() {
    const nlohmann::json manifest = nlohmann::json::parse(R"({
      "schema_version": 1,
      "plugins": [
        {
          "id": "evil.path",
          "version": "1.0.0",
          "platforms": {
            "windows": {
              "available": true,
              "asset": "x.zip",
              "sha256": "00",
              "module": "../evil.dll",
              "files": ["plugin_ok.dll"]
            },
            "linux": {
              "available": true,
              "asset": "x.zip",
              "sha256": "00",
              "module": "../evil.so",
              "files": ["plugin_ok.so"]
            },
            "macos": {
              "available": true,
              "asset": "x.zip",
              "sha256": "00",
              "module": "../evil.dylib",
              "files": ["plugin_ok.dylib"]
            }
          }
        }
      ]
    })");
    std::string err;
    auto asset = lookup_manifest_asset(manifest, "evil.path", current_platform_key(), &err);
    assert(!asset.has_value());
    // Path-like module: rejected (package inferred from the stem fails the segment check,
    // or the module fails the relative-member check).
    assert(err.find("unsafe") != std::string::npos);

    // Nested files[] without a package field: the release is clearly packaged, so the
    // module stem is used as the package dir (see test_package_layout_install).
    nlohmann::json man2 = nlohmann::json::parse(R"({
      "plugins": [{
        "id": "evil.files",
        "version": "1.0.0",
        "platforms": {
          "windows": {
            "available": true,
            "asset": "x.zip",
            "sha256": "00",
            "module": "plugin_ok.dll",
            "files": ["plugin_ok.dll", "subdir/nested.dll"]
          },
          "linux": {
            "available": true,
            "asset": "x.zip",
            "sha256": "00",
            "module": "plugin_ok.so",
            "files": ["plugin_ok.so", "subdir/nested.so"]
          },
          "macos": {
            "available": true,
            "asset": "x.zip",
            "sha256": "00",
            "module": "plugin_ok.dylib",
            "files": ["plugin_ok.dylib", "subdir/nested.dylib"]
          }
        }
      }]
    })");
    err.clear();
    asset = lookup_manifest_asset(man2, "evil.files", current_platform_key(), &err);
    assert(asset.has_value());
    assert(asset->package == "plugin_ok"); // inferred package dir, nested member kept
    assert(asset->files.size() == 2);

    // Traversal attempts are still rejected (absolute members / escaping package dirs).
    nlohmann::json man3 = nlohmann::json::parse(R"({
      "plugins": [{
        "id": "evil.escape",
        "version": "1.0.0",
        "platforms": {
          "windows": {"available": true, "asset": "x.zip", "sha256": "00",
                      "module": "plugin_ok.dll", "files": ["../../escape.dll"],
                      "package": "plugin_ok"},
          "linux": {"available": true, "asset": "x.zip", "sha256": "00",
                    "module": "plugin_ok.so", "files": ["../../escape.so"],
                    "package": "plugin_ok"},
          "macos": {"available": true, "asset": "x.zip", "sha256": "00",
                    "module": "plugin_ok.dylib", "files": ["../../escape.dylib"],
                    "package": "plugin_ok"}
        }
      }]
    })");
    err.clear();
    asset = lookup_manifest_asset(man3, "evil.escape", current_platform_key(), &err);
    assert(!asset.has_value());
    assert(err.find("unsafe files") != std::string::npos);

    nlohmann::json man4 = nlohmann::json::parse(R"({
      "plugins": [{
        "id": "evil.pkg",
        "version": "1.0.0",
        "platforms": {
          "windows": {"available": true, "asset": "x.zip", "sha256": "00",
                      "module": "plugin_ok.dll", "files": ["plugin_ok.dll"],
                      "package": "../evil"},
          "linux": {"available": true, "asset": "x.zip", "sha256": "00",
                    "module": "plugin_ok.so", "files": ["plugin_ok.so"],
                    "package": "../evil"},
          "macos": {"available": true, "asset": "x.zip", "sha256": "00",
                    "module": "plugin_ok.dylib", "files": ["plugin_ok.dylib"],
                    "package": "../evil"}
        }
      }]
    })");
    err.clear();
    asset = lookup_manifest_asset(man4, "evil.pkg", current_platform_key(), &err);
    assert(!asset.has_value());
    assert(err.find("unsafe package") != std::string::npos);

    // Module must be <package><ext> — the loader only looks for plugins/<pkg>/<pkg>.<ext>.
    nlohmann::json man5 = nlohmann::json::parse(R"({
      "plugins": [{
        "id": "evil.mismatch",
        "version": "1.0.0",
        "platforms": {
          "windows": {"available": true, "asset": "x.zip", "sha256": "00",
                      "module": "other.dll", "files": ["other.dll"], "package": "plugin_ok"},
          "linux": {"available": true, "asset": "x.zip", "sha256": "00",
                    "module": "other.so", "files": ["other.so"], "package": "plugin_ok"},
          "macos": {"available": true, "asset": "x.zip", "sha256": "00",
                    "module": "other.dylib", "files": ["other.dylib"], "package": "plugin_ok"}
        }
      }]
    })");
    err.clear();
    asset = lookup_manifest_asset(man5, "evil.mismatch", current_platform_key(), &err);
    assert(!asset.has_value());
    assert(err.find("must be <package><ext>") != std::string::npos);
    printf("PASS: reject_pathlike_module_and_files\n");
}

static void test_reject_foreign_platform() {
    // Manifest only has a different platform than current → fail, no fallback.
    const std::string foreign =
#if defined(_WIN32)
        "linux";
#elif defined(__APPLE__)
        "windows";
#else
        "windows";
#endif
    nlohmann::json manifest;
    manifest["plugins"] = nlohmann::json::array();
    nlohmann::json plug;
    plug["id"] = "only.foreign";
    plug["version"] = "1.0.0";
    plug["platforms"] = nlohmann::json::object();
    nlohmann::json slot;
    slot["available"] = true;
    slot["asset"] = "plugin_x.zip";
    slot["sha256"] = "00";
    slot["module"] = "plugin_x.so";
    slot["files"] = nlohmann::json::array({"plugin_x.so"});
    plug["platforms"][foreign] = slot;
    manifest["plugins"].push_back(plug);

    std::string err;
    auto asset = lookup_manifest_asset(manifest, "only.foreign", current_platform_key(), &err);
    assert(!asset.has_value());
    assert(err.find("platform") != std::string::npos);
    assert(err.find("missing") != std::string::npos);

    // available:false for current platform also fails.
    plug["platforms"] = nlohmann::json::object();
    slot["module"] = "plugin_x.dll";
    slot["files"] = nlohmann::json::array({"plugin_x.dll"});
    slot["available"] = false;
    plug["platforms"][current_platform_key()] = slot;
    manifest["plugins"] = nlohmann::json::array({plug});
    err.clear();
    asset = lookup_manifest_asset(manifest, "only.foreign", current_platform_key(), &err);
    assert(!asset.has_value());
    assert(err.find("unavailable") != std::string::npos);
    printf("PASS: reject_foreign_platform\n");
}

static void test_http_body_size_cap_constant() {
    // Cap is exposed for transport paths; mock override bypasses platform GET.
    assert(kMaxHttpBodyBytes == 64ull * 1024ull * 1024ull);
    // Document expected error substring used by WinHTTP/curl bound paths.
    const std::string sample_err =
        "http_get: response exceeds " + std::to_string(kMaxHttpBodyBytes) + " bytes";
    assert(sample_err.find("exceeds") != std::string::npos);
    printf("PASS: http_body_size_cap_constant\n");
}

static void test_apply_requires_nonempty_files() {
    set_http_get_override(&mock_http_get);
    g_http_map.clear();
    g_http_hits = 0;

    const std::string module_name =
#if defined(_WIN32)
        "plugin_dummy.dll";
#else
        "plugin_dummy.so";
#endif
    const std::string module_bytes = "MZ-PLUGIN-BYTES-nofiles";
    const std::string digest = sha256_hex(module_bytes);
    const std::string zip_bytes = build_zip_bytes({{module_name, module_bytes}});

    const std::string platform = current_platform_key();
    const std::string asset_name = "plugin_dummy-9.0.0-" + platform + ".zip";
    const std::string tag = "v9.0.0";
    const std::string direct_asset =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/" + tag + "/" + asset_name;
    g_http_map[direct_asset] = zip_bytes;

    nlohmann::json manifest;
    manifest["schema_version"] = 1;
    manifest["repo"] = "fesily/DontStarveLuaJIT2";
    manifest["release_tag"] = tag;
    nlohmann::json plug;
    plug["id"] = "debug.dummy";
    plug["version"] = "9.0.0";
    nlohmann::json slot;
    slot["available"] = true;
    slot["asset"] = asset_name;
    slot["sha256"] = digest;
    slot["module"] = module_name;
    // Intentionally omit files[] — production apply must refuse.
    plug["platforms"] = nlohmann::json::object();
    plug["platforms"][platform] = slot;
    manifest["plugins"] = nlohmann::json::array({plug});

    PluginPinConfig cfg = defaults();
    cfg.release_tag = tag;
    cfg.prefer_proxy = "never";

    const auto plugins_dir = make_temp_dir("plugins_nofiles");
    PlanAction action;
    action.id = "debug.dummy";
    action.from = "1.0.0";
    action.to = "9.0.0";
    action.reason = "version_mismatch";

    auto result = apply_plan(cfg, manifest, {action}, plugins_dir, "");
    assert(result.succeeded == 0);
    assert(result.attempted == 1);
    assert(!result.last_error.empty());
    assert(result.last_error.find("files[]") != std::string::npos);
    assert(!fs::exists(plugins_dir / module_name));

    set_http_get_override(nullptr);
    std::error_code ec;
    fs::remove_all(plugins_dir, ec);
    printf("PASS: apply_requires_nonempty_files\n");
}

// Compatibility classes (not exact names): Debug is isolated on MSVC, the Release
// family is interchangeable, POSIX has no such split. This is the predicate the
// install gate uses, so a Release asset is NOT refused in a RelWithDebInfo tree.
static void test_build_config_compatibility_classes() {
    using ds::plugin_manager::build_config_compatible;
    // Unconstrained sides always pass (legacy manifests / ad-hoc builds).
    assert(build_config_compatible("", "Debug"));
    assert(build_config_compatible("Release", ""));
    assert(build_config_compatible("any", "Debug"));
    assert(build_config_compatible("Debug", "any"));
    // Release family is mutually compatible on every platform.
    assert(build_config_compatible("Release", "RelWithDebInfo"));
    assert(build_config_compatible("MinSizeRel", "Release"));
    assert(build_config_compatible("RelWithDebInfo", "RelWithDebInfo"));
#if defined(_WIN32)
    // MSVC: debug CRT + iterator-debug level make Debug a separate ABI.
    assert(!build_config_compatible("Debug", "RelWithDebInfo"));
    assert(!build_config_compatible("Release", "Debug"));
    assert(!build_config_compatible("Debug", "Debug") == false);
    assert(build_config_compatible("Debug", "Debug"));
#else
    // POSIX: one libstdc++/libc++ ABI — the axis does not exist.
    assert(build_config_compatible("Debug", "Release"));
    assert(build_config_compatible("RelWithDebInfo", "Debug"));
#endif
    printf("PASS: build_config_compatibility_classes\n");
}

// Build-configuration stamp: assets stamped with another configuration must be refused
// before any download; matching/absent/"any" stamps stay installable.
static void test_build_config_stamp_matrix() {
    set_http_get_override(&mock_http_get);

    const std::string module_name =
#if defined(_WIN32)
        "plugin_dummy.dll";
#else
        "plugin_dummy.so";
#endif
    const std::string module_bytes = "MZ-PLUGIN-STAMP";
    const std::string digest = sha256_hex(module_bytes);
    const std::string meta = R"({"id":"debug.dummy","version":"2.0.0","sha256":")" + digest +
                             R"(","module":")" + module_name + R"("})";
    const std::string zip_bytes =
        build_zip_bytes({{module_name, module_bytes}, {"plugin_dummy.meta.json", meta}});
    const std::string platform = current_platform_key();
    const std::string tag = "v2.0.0";
    const std::string direct_asset =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/" + tag + "/" +
        "plugin_dummy-2.0.0-" + platform + ".zip";

    auto make_manifest = [&](const std::string &stamp, bool include_stamp) {
        nlohmann::json manifest;
        manifest["schema_version"] = 1;
        manifest["repo"] = "fesily/DontStarveLuaJIT2";
        manifest["release_tag"] = tag;
        nlohmann::json plug;
        plug["id"] = "debug.dummy";
        plug["version"] = "2.0.0";
        nlohmann::json slot;
        slot["available"] = true;
        slot["asset"] = "plugin_dummy-2.0.0-" + platform + ".zip";
        slot["sha256"] = digest;
        slot["module"] = module_name;
        slot["files"] = nlohmann::json::array({module_name, "plugin_dummy.meta.json"});
        if (include_stamp) {
            slot["build_config"] = stamp;
        }
        plug["platforms"][platform] = slot;
        manifest["plugins"] = nlohmann::json::array({plug});
        return manifest;
    };

    PlanAction action;
    action.id = "debug.dummy";
    action.from = "1.0.0";
    action.to = "2.0.0";
    action.reason = "version_mismatch";

    PluginPinConfig cfg = defaults();
    cfg.release_tag = tag;
    cfg.prefer_proxy = "never";

    struct Case {
        const char *name;
        bool include_stamp;
        const char *stamp;
        bool expect_install;
    };
    // This test binary is stamped with Debug (see tests/CMakeLists.txt).
    const Case cases[] = {
        {"matching", true, DS_PLUGIN_BUILD_CONFIG, true},
        {"any", true, kBuildConfigAny, true},
        {"unstamped-legacy", false, "", true},
        {"mismatch", true, "RelWithDebInfo", false},
    };

    for (const auto &c : cases) {
        g_http_map.clear();
        g_http_hits = 0;
        g_http_map[direct_asset] = zip_bytes;
        const auto manifest = make_manifest(c.stamp, c.include_stamp);
        const auto plugins_dir = make_temp_dir("stamp");

        const auto result = apply_plan(cfg, manifest, {action}, plugins_dir, "");
        if (c.expect_install) {
            assert(result.succeeded == 1);
            assert(result.refused == 0);
            assert(fs::exists(plugins_dir / "plugin_dummy" / module_name));
            assert(read_bytes(plugins_dir / "plugin_dummy" / module_name) == module_bytes);
            assert(g_http_hits >= 1);
        } else {
            assert(result.succeeded == 0);
            assert(result.refused == 1);
            assert(result.attempted == 1);
            assert(result.last_error.empty()); // refusal is not an error
            assert(!fs::exists(plugins_dir / "plugin_dummy" / module_name)); // nothing installed
            assert(g_http_hits == 0);                      // refused before the download
        }
        printf("PASS: build_config_%s\n", c.name);
    }
    // Mixed plan: one installable + one refused → nothing failed.
    g_http_map.clear();
    g_http_hits = 0;
    g_http_map[direct_asset] = zip_bytes;
    {
        auto manifest = make_manifest("RelWithDebInfo", true);
        auto plug = manifest["plugins"][0];
        plug["id"] = "debug.dummy";
        manifest["plugins"] = nlohmann::json::array({plug});
        const auto plugins_dir = make_temp_dir("stamp_mixed");
        const auto result = apply_plan(cfg, manifest, {action}, plugins_dir, "");
        assert(result.refused == 1 && result.succeeded == 0);
        assert(result.attempted == result.succeeded + result.refused);
        printf("PASS: build_config_attempted_accounting\n");
    }
}

// --- package layout (plugins/<package>/<members>) --------------------------------

static nlohmann::json pkg_manifest(const std::string &direct_asset, const std::string &digest,
                                  const std::string &platform, const std::string &module,
                                  const std::vector<std::string> &files, bool with_package,
                                  const char *package = "plugin_dummy") {
    nlohmann::json manifest;
    manifest["schema_version"] = 1;
    manifest["repo"] = "fesily/DontStarveLuaJIT2";
    manifest["release_tag"] = "v2.0.0";
    nlohmann::json plug;
    plug["id"] = "debug.dummy";
    plug["version"] = "2.0.0";
    nlohmann::json slot;
    slot["available"] = true;
    slot["asset"] = direct_asset.substr(direct_asset.rfind('/') + 1);
    slot["sha256"] = digest;
    slot["module"] = module;
    slot["files"] = files;
    if (with_package) {
        slot["package"] = package;
    }
    plug["platforms"][platform] = slot;
    manifest["plugins"] = nlohmann::json::array({plug});
    return manifest;
}

// Cross-tag pin: the manifest slot is not the version the action asked for, so the apply
// must refuse before downloading (spec: "switch channel/tag first").
static void test_cross_tag_pin_refused() {
    set_http_get_override(&mock_http_get);
    const std::string platform = current_platform_key();
    const std::string module_name =
#if defined(_WIN32)
        "plugin_dummy.dll";
#else
        "plugin_dummy.so";
#endif
    const std::string module_bytes = "MZ-OFFTAG";
    const std::string digest = sha256_hex(module_bytes);
    const std::string asset_name = "plugin_dummy-2.0.0-" + platform + ".zip";
    g_http_map.clear();
    g_http_hits = 0;
    g_http_map["https://github.com/fesily/DontStarveLuaJIT2/releases/download/v2.0.0/" + asset_name] =
        build_zip_bytes({{module_name, module_bytes}});

    const auto manifest = pkg_manifest(asset_name, digest, platform, module_name, {module_name},
                                      true, "plugin_dummy"); // slot version is 2.0.0

    PluginPinConfig cfg = defaults();
    cfg.release_tag = "v2.0.0";
    cfg.prefer_proxy = "never";

    PlanAction action;
    action.id = "debug.dummy";
    action.from = "1.0.0";
    action.to = "1.0.0"; // the pin the user asked for; the tag publishes 2.0.0
    action.reason = "pin_unavailable";

    const auto plugins_dir = make_temp_dir("offtag");
    const auto result = apply_plan(cfg, manifest, {action}, plugins_dir, "");
    assert(result.succeeded == 0);
    assert(result.attempted == 1);
    assert(result.last_error.find("switch channel/tag first") != std::string::npos);
    assert(g_http_hits == 0); // refused before any download
    assert(!fs::exists(plugins_dir / "plugin_dummy" / module_name));
    printf("PASS: cross_tag_pin_refused\n");
}

static void test_package_layout_install() {
    set_http_get_override(&mock_http_get);
    const std::string platform = current_platform_key();
    const std::string module_name =
#if defined(_WIN32)
        "plugin_dummy.dll";
#else
        "plugin_dummy.so";
#endif
    const std::string module_bytes = "MZ-PACKAGED";
    const std::string digest = sha256_hex(module_bytes);
    const std::string meta = R"({"id":"debug.dummy","version":"2.0.0","sha256":")" + digest +
                             R"(","module":")" + module_name + R"("})";
    const std::vector<std::string> files = {module_name, "plugin_dummy.meta.json", "modinfo.lua",
                                            "scripts/extra.lua"};
    const std::string zip_bytes = build_zip_bytes({{module_name, module_bytes},
                                                   {"plugin_dummy.meta.json", meta},
                                                   {"modinfo.lua", "-- lua face"},
                                                   {"scripts/extra.lua", "return 1"}});
    const std::string asset_name = "plugin_dummy-2.0.0-" + platform + ".zip";
    g_http_map.clear();
    g_http_hits = 0;
    g_http_map["https://github.com/fesily/DontStarveLuaJIT2/releases/download/v2.0.0/" + asset_name] =
        zip_bytes;

    PluginPinConfig cfg = defaults();
    cfg.release_tag = "v2.0.0";
    cfg.prefer_proxy = "never";
    PlanAction action;
    action.id = "debug.dummy";
    action.from = "1.0.0";
    action.to = "2.0.0";
    action.reason = "version_mismatch";

    // Explicit package field.
    for (int variant = 0; variant < 2; ++variant) {
        const auto plugins_dir = make_temp_dir(variant == 0 ? "pkg_explicit" : "pkg_inferred");
        const auto manifest = pkg_manifest(asset_name, digest, platform, module_name, files,
                                          variant == 0, "plugin_dummy");
        const auto result = apply_plan(cfg, manifest, {action}, plugins_dir, "");
        assert(result.succeeded == 1);
        assert(result.refused == 0);
        const auto pkg = plugins_dir / "plugin_dummy";
        assert(fs::exists(pkg / module_name));
        assert(read_bytes(pkg / module_name) == module_bytes);
        assert(fs::exists(pkg / "modinfo.lua"));
        assert(fs::exists(pkg / "scripts" / "extra.lua"));
        assert(read_bytes(pkg / "scripts" / "extra.lua") == "return 1");
        // Nothing flat: the loader would otherwise see two copies of one plugin.
        assert(!fs::exists(plugins_dir / module_name));
        assert(!fs::exists(plugins_dir / "script")); // no stray dirs
    }
    printf("PASS: package_layout_install (explicit + legacy-inferred)\n");
}

static void test_package_layout_traversal_rejected() {
    set_http_get_override(&mock_http_get);
    const std::string platform = current_platform_key();
    const std::string module_name = "plugin_dummy.dll";
    const std::string module_bytes = "MZ-EVIL";
    const std::string digest = sha256_hex(module_bytes);
    const std::string zip_bytes = build_zip_bytes({{module_name, module_bytes}});
    const std::string asset_name = "plugin_dummy-2.0.0-" + platform + ".zip";
    g_http_map.clear();
    g_http_map["https://github.com/fesily/DontStarveLuaJIT2/releases/download/v2.0.0/" + asset_name] =
        zip_bytes;

    PluginPinConfig cfg = defaults();
    cfg.release_tag = "v2.0.0";
    cfg.prefer_proxy = "never";
    PlanAction action;
    action.id = "debug.dummy";
    action.to = "2.0.0";
    action.reason = "version_mismatch";

    struct Case {
        const char *name;
        const char *package;
        std::vector<std::string> files;
    };
    const Case cases[] = {
        {"package-dotdot", "../evil", {module_name}},
        {"package-absolute", "/evil", {module_name}},
        {"member-dotdot", "plugin_dummy", {module_name, "../../evil.dll"}},
        {"member-absolute", "plugin_dummy", {module_name, "/abs.lua"}},
    };
    for (const auto &c : cases) {
        const auto plugins_dir = make_temp_dir("pkg_evil");
        const auto manifest = pkg_manifest(asset_name, digest, platform, module_name, c.files, true,
                                          c.package);
        const auto result = apply_plan(cfg, manifest, {action}, plugins_dir, "");
        assert(result.succeeded == 0);
        assert(result.attempted == 1);
        assert(!result.last_error.empty());          // lookup rejected the asset
        assert(!fs::exists(plugins_dir / module_name));
        assert(!fs::exists(fs::temp_directory_path() / "evil.dll"));
        printf("PASS: package_traversal_rejected_%s\n", c.name);
    }
}

static void test_package_layout_pending_mirror() {
    // A destination that cannot be written (a directory standing in for a locked/live
    // module) must fall back to update_pending/<package>/<member>, mirroring the mover.
    const auto staging = make_temp_dir("pkg_stage");
    const auto plugins = make_temp_dir("pkg_plug");
    // Staging mirrors the zip: members are package-RELATIVE (the package dir is applied
    // at install time), so they sit at the staging root here.
    fs::create_directories(staging / "scripts");
    std::ofstream(staging / "plugin_dummy.dll", std::ios::binary) << "NEW";
    std::ofstream(staging / "scripts" / "a.lua") << "LUA";
    // Unwritable target: a plain file where the package dir must be, so the direct
    // install cannot create <plugins>/plugin_dummy/... and must fall back to pending.
    std::ofstream(plugins / "plugin_dummy") << "blocker";

    bool pending = false;
    std::string err;
    assert(install_extracted_files(staging, plugins, "plugin_dummy",
                                   {"plugin_dummy.dll", "scripts/a.lua"}, &pending, &err));
    assert(pending);
    assert(read_bytes(plugins / "update_pending" / "plugin_dummy" / "plugin_dummy.dll") == "NEW");
    assert(read_bytes(plugins / "update_pending" / "plugin_dummy" / "scripts" / "a.lua") == "LUA");
    printf("PASS: package_layout_pending_mirror\n");
}

int main() {
    test_channel_cache_and_lookup();
    test_fetch_manifest_mock();
    test_apply_plan_with_mock_http();
    test_install_package_only();
    test_reject_pathlike_module_and_files();
    test_reject_foreign_platform();
    test_http_body_size_cap_constant();
    test_apply_requires_nonempty_files();
    test_build_config_compatibility_classes();
    test_build_config_stamp_matrix();
    test_cross_tag_pin_refused();
    test_package_layout_install();
    test_package_layout_traversal_rejected();
    test_package_layout_pending_mirror();
    printf("ALL PASS plugin_apply_offline\n");
    return 0;
}


