#pragma once

// Runtime state shared with the mod: <client save dir>/unsafedata.
//
// DST 759671 sandboxes mod io: a mod's relative "unsafedata/..." resolves under
// the save directory and absolute paths fail with "invalid filepath". The mod
// therefore reaches these files by that relative path, so native code must use
// exactly the same directory - see dir(). Installer-owned files (marker, boot
// log) are written before the game exists and stay under <game>/data/unsafedata.

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

namespace ds::unsafedata {

// <client save dir>/unsafedata. Empty when it cannot be resolved (dedicated
// server without a client save dir, unknown Steam identity); callers then skip
// the guarded work instead of falling back to some other directory.
std::filesystem::path dir();

inline std::filesystem::path sentinel_path() {
    const auto base = dir();
    return base.empty() ? std::filesystem::path() : base / "luajit_crash.json";
}

inline std::filesystem::path config_path() {
    const auto base = dir();
    return base.empty() ? std::filesystem::path() : base / "luajit_config.json";
}

// --- crash sentinel ---------------------------------------------------------
// Armed ("{1}") right before the injector takes over the Lua VM and cleared by
// the mod once the game reaches post-init, so a boot that never gets there
// leaves the record behind.

// Arm record: injection is in flight this boot.
inline constexpr const char *kArmed = "{1}";
// Skip record: the previous armed boot never signalled success.
inline constexpr const char *kSkipped = "{2}";

inline std::string read_sentinel(const std::filesystem::path &path) {
    if (path.empty()) {
        return {};
    }
    std::ifstream fp(path, std::ios::binary);
    if (!fp) {
        return {};
    }
    char buf[32] = {};
    fp.read(buf, 16);
    return std::string{buf, static_cast<size_t>(fp.gcount())};
}

inline void write_sentinel(const std::filesystem::path &path, std::string_view content) {
    if (path.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream fp(path, std::ios::binary | std::ios::trunc);
    fp.write(content.data(), static_cast<std::streamsize>(content.size()));
}

// true: injection may proceed, and the sentinel is armed for this boot.
// A recorded crash skips exactly one boot; the next launch retries, so a stale
// record can never disable the injector for good.
inline bool allow_inject(const std::filesystem::path &path) {
    if (path.empty()) {
        return true;
    }
    if (read_sentinel(path) == kArmed) {
        write_sentinel(path, kSkipped);
        return false;
    }
    write_sentinel(path, kArmed);
    return true;
}

} // namespace ds::unsafedata
