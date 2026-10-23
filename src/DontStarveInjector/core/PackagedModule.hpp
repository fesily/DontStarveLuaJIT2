#pragma once

// Workshop layout: the published item carries every module the game maps as
// "<canonical name>.pkg" (e.g. "Injector.dll.pkg"), never the canonical name
// itself. Steam updates the item by overwriting/deleting the files it published;
// a mapped image can be neither overwritten nor deleted (ERROR_SHARING_VIOLATION /
// ERROR_ACCESS_DENIED), so the mapped filename must not appear in the manifest.
//
// The runtime therefore materializes the canonical name from the ".pkg" twin
// immediately before LoadLibrary. Nothing is renamed away, nothing is left behind:
// the ".pkg" file stays the durable copy, and the canonical file is a local
// derivative that is refreshed by PE build stamp.
//
// A build-tree / zip-install layout has no ".pkg" twin at all: every entry point
// then returns the path unchanged.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <system_error>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#endif

namespace ds::packaged {

inline constexpr const char *kPackageSuffix = ".pkg";
inline constexpr const char *kMaterializeTempSuffix = ".ds_materialize_tmp";

// "<canonical>" -> "<canonical>.pkg"
inline std::filesystem::path packaged_path(const std::filesystem::path &canonical) {
    std::filesystem::path p = canonical;
    p += kPackageSuffix; // path::operator+= appends to the native string (encoding-safe)
    return p;
}

inline std::filesystem::path materialize_temp_path(const std::filesystem::path &canonical) {
    std::filesystem::path p = canonical;
    p += kMaterializeTempSuffix;
    return p;
}

namespace detail {

inline bool is_regular(const std::filesystem::path &p) {
    std::error_code ec;
    return !p.empty() && std::filesystem::is_regular_file(p, ec);
}

struct ImageStamp {
    bool ok = false;
    std::uint32_t time_stamp = 0;
    std::uint32_t size_of_image = 0;
};

// PE TimeDateStamp + SizeOfImage: identical for the same link, different for any rebuild.
inline ImageStamp image_stamp(const std::filesystem::path &p) {
    ImageStamp stamp;
#if defined(_WIN32)
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        return stamp;
    }
    std::uint32_t lfanew = 0;
    in.seekg(0x3C);
    in.read(reinterpret_cast<char *>(&lfanew), sizeof(lfanew));
    if (!in) {
        return stamp;
    }
    char signature[4] = {};
    in.seekg(lfanew);
    in.read(signature, sizeof(signature));
    if (!in || std::memcmp(signature, "PE\0\0", 4) != 0) {
        return stamp;
    }
    std::uint32_t time_stamp = 0;
    in.read(reinterpret_cast<char *>(&time_stamp), sizeof(time_stamp));
    if (!in) {
        return stamp;
    }
    // SizeOfImage sits 56 bytes into the optional header (same offset for PE32/PE32+).
    std::uint32_t size_of_image = 0;
    in.seekg(static_cast<std::streamoff>(lfanew) + 24 + 56);
    in.read(reinterpret_cast<char *>(&size_of_image), sizeof(size_of_image));
    if (!in) {
        return stamp;
    }
    stamp.ok = true;
    stamp.time_stamp = time_stamp;
    stamp.size_of_image = size_of_image;
#endif
    return stamp;
}

// Same build? PE stamp plus byte size when both files are PE, else byte size alone.
inline bool same_image(const std::filesystem::path &a, const std::filesystem::path &b) {
    std::error_code ec;
    const auto fa = std::filesystem::file_size(a, ec);
    if (ec) {
        return false;
    }
    std::error_code ec_b;
    const auto fb = std::filesystem::file_size(b, ec_b);
    if (ec_b || fa != fb) {
        return false;
    }
    const auto sa = image_stamp(a);
    const auto sb = image_stamp(b);
    if (sa.ok && sb.ok) {
        return sa.time_stamp == sb.time_stamp && sa.size_of_image == sb.size_of_image;
    }
    return true; // equal size is all we can compare for non-PE payloads
}

} // namespace detail

// Materialize the canonical name from its ".pkg" twin when they differ.
// Returns true only when the canonical file was (re)written by this call.
// Never throws, never deletes the canonical file: a mapped canonical (another
// process of a shared plugins tree) fails the swap and keeps what is already there.
inline bool materialize(const std::filesystem::path &canonical) {
    std::error_code ec;
    const auto from = packaged_path(canonical);
    if (!detail::is_regular(from)) {
        return false; // dev/zip layout: the canonical file is the shipped file
    }
    const bool have_target = detail::is_regular(canonical);
    if (have_target && detail::same_image(canonical, from)) {
        return false; // already current
    }
    if (!canonical.parent_path().empty()) {
        std::filesystem::create_directories(canonical.parent_path(), ec);
        ec.clear();
    }

    // Stage beside the target so a partial copy can never be loaded.
    const auto tmp = materialize_temp_path(canonical);
    std::filesystem::remove(tmp, ec);
    ec.clear();
    std::filesystem::copy_file(from, tmp, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        std::fprintf(stderr, "[PackagedModule] stage_failed: %s (%s)\n", from.string().c_str(),
                     ec.message().c_str());
        return false;
    }

    ec.clear();
    std::filesystem::rename(tmp, canonical, ec);
    if (!ec) {
        std::fprintf(stderr, "[PackagedModule] materialized: %s\n", canonical.string().c_str());
        return true;
    }

    // Windows cannot rename over an existing file: overwrite in place instead.
    ec.clear();
    std::filesystem::copy_file(tmp, canonical, std::filesystem::copy_options::overwrite_existing, ec);
    std::error_code rm_ec;
    std::filesystem::remove(tmp, rm_ec);
    if (ec) {
        std::fprintf(stderr,
                     "[PackagedModule] kept existing %s (locked by another process?): %s\n",
                     canonical.string().c_str(), ec.message().c_str());
        return false;
    }
    std::fprintf(stderr, "[PackagedModule] materialized: %s\n", canonical.string().c_str());
    return true;
}

// True when the canonical file is present after trying to materialize it.
inline bool exists_or_materialize(const std::filesystem::path &canonical) {
    if (detail::is_regular(canonical)) {
        return true;
    }
    (void)materialize(canonical);
    return detail::is_regular(canonical);
}

// Materialize every "<name>.pkg" directly inside `dir` (used for deps/).
inline size_t materialize_directory(const std::filesystem::path &dir) {
    std::error_code ec;
    if (dir.empty() || !std::filesystem::is_directory(dir, ec)) {
        return 0;
    }
    size_t written = 0;
    for (std::filesystem::directory_iterator it(dir, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            break;
        }
        std::error_code probe_ec;
        if (!it->is_regular_file(probe_ec)) {
            continue;
        }
        const auto name = it->path().filename().string();
        const std::string suffix{kPackageSuffix};
        if (name.size() <= suffix.size() || name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0) {
            continue;
        }
        std::filesystem::path canonical = it->path();
        canonical = canonical.parent_path() / std::filesystem::path(name.substr(0, name.size() - suffix.size()));
        if (materialize(canonical)) {
            ++written;
        }
    }
    return written;
}

// True when `tree` (a plugins root) ships packaged modules at all.
inline bool tree_is_packaged(const std::filesystem::path &tree) {
    std::error_code ec;
    if (tree.empty() || !std::filesystem::is_directory(tree, ec)) {
        return false;
    }
    const std::string suffix{kPackageSuffix};
    for (std::filesystem::recursive_directory_iterator it(tree, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            return false;
        }
        std::error_code probe_ec;
        if (!it->is_regular_file(probe_ec)) {
            continue;
        }
        const auto name = it->path().filename().string();
        if (name.size() > suffix.size() &&
            name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
    }
    return false;
}

// Drop a module this process materialized for a package member that the published
// item no longer ships. Gated on `tree` being packaged: outside one there are no
// ".pkg" twins at all, and a developer's build is never touched.
inline bool prune_unpackaged_module(const std::filesystem::path &tree,
                                   const std::filesystem::path &canonical) {
    if (!tree_is_packaged(tree)) {
        return false;
    }
    if (detail::is_regular(packaged_path(canonical))) {
        return false;
    }
    std::error_code ec;
    if (!std::filesystem::is_regular_file(canonical, ec)) {
        return false;
    }
    std::filesystem::remove(canonical, ec);
    if (ec) {
        return false; // mapped by a live process: keep it, next boot retries
    }
    std::fprintf(stderr, "[PackagedModule] dropped stale derivative (no .pkg): %s\n",
                 canonical.string().c_str());
    return true;
}

} // namespace ds::packaged
