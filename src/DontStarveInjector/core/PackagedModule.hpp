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
// derivative that is refreshed by PE build stamp at every entry point — the twin is
// compared even when the canonical already exists, so replacing "<name>.pkg" alone
// (Steam item update, manual copy) is enough to ship a new build.
//
// A build-tree / zip-install layout has no ".pkg" twin at all: every entry point
// then returns the path unchanged.

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#else
#  include <unistd.h>
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
    // COFF file header: Machine (2), NumberOfSections (2), TimeDateStamp (4) — the stamp
    // sits at lfanew + 8, right behind the 4-byte "PE\0\0" signature.
    in.seekg(static_cast<std::streamoff>(lfanew) + 8);
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

// A file that a copy was cut short on: a PE whose section table points past the end of
// the file, or an ELF whose program/section tables or PT_LOAD segments do. Other
// payloads cannot be validated here and are accepted.
inline bool looks_complete(const std::filesystem::path &p) {
#if defined(_WIN32)
    std::error_code ec;
    const auto total = std::filesystem::file_size(p, ec);
    if (ec) {
        return false;
    }
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        return false;
    }
    char mz[2] = {};
    in.read(mz, sizeof(mz));
    if (!in || mz[0] != 'M' || mz[1] != 'Z') {
        return true; // not a PE: nothing to validate
    }
    std::uint32_t lfanew = 0;
    in.seekg(0x3C);
    in.read(reinterpret_cast<char *>(&lfanew), sizeof(lfanew));
    const auto pe_head = static_cast<std::uint64_t>(lfanew) + 24;
    if (!in || pe_head > total) {
        return false;
    }
    char signature[4] = {};
    in.seekg(lfanew);
    in.read(signature, sizeof(signature));
    std::uint16_t n_sections = 0;
    in.seekg(static_cast<std::streamoff>(lfanew) + 6);
    in.read(reinterpret_cast<char *>(&n_sections), sizeof(n_sections));
    std::uint16_t opt_header = 0;
    in.seekg(static_cast<std::streamoff>(lfanew) + 20);
    in.read(reinterpret_cast<char *>(&opt_header), sizeof(opt_header));
    if (!in || std::memcmp(signature, "PE\0\0", 4) != 0 || n_sections == 0 || n_sections > 96) {
        return false;
    }
    const auto table = pe_head + opt_header;
    if (table + static_cast<std::uint64_t>(n_sections) * 40 > total) {
        return false;
    }
    for (std::uint16_t i = 0; i < n_sections; ++i) {
        std::uint32_t raw_size = 0;
        std::uint32_t raw_ptr = 0;
        in.seekg(static_cast<std::streamoff>(table) + i * 40 + 16);
        in.read(reinterpret_cast<char *>(&raw_size), sizeof(raw_size));
        in.read(reinterpret_cast<char *>(&raw_ptr), sizeof(raw_ptr));
        if (!in) {
            return false;
        }
        if (raw_size != 0 && static_cast<std::uint64_t>(raw_ptr) + raw_size > total) {
            return false; // truncated copy
        }
    }
    return true;
#else
    // ELF (Linux game/module images): every table and PT_LOAD segment must lie inside
    // the file, so a half-written copy cannot be published over a working module.
    std::error_code ec;
    const auto total = std::filesystem::file_size(p, ec);
    if (ec) {
        return false;
    }
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        return false;
    }
    const auto read_at = [&](std::uint64_t offset, void *dst, std::size_t len) {
        if (offset > total || len > total - offset) {
            return false;
        }
        in.clear();
        in.seekg(static_cast<std::streamoff>(offset));
        in.read(static_cast<char *>(dst), static_cast<std::streamsize>(len));
        return static_cast<bool>(in);
    };
    unsigned char ident[16] = {};
    if (!read_at(0, ident, sizeof(ident)) || ident[0] != 0x7f || ident[1] != 'E' ||
        ident[2] != 'L' || ident[3] != 'F') {
        return true; // not ELF (e.g. Mach-O): nothing to validate
    }
    if (ident[4] != 2 /* ELFCLASS64 */ || ident[5] != 1 /* ELFDATA2LSB */) {
        return true; // format we cannot validate here
    }
    std::uint64_t phoff = 0;
    std::uint64_t shoff = 0;
    std::uint16_t phentsize = 0;
    std::uint16_t phnum = 0;
    std::uint16_t shentsize = 0;
    std::uint16_t shnum = 0;
    if (!read_at(32, &phoff, sizeof(phoff)) || !read_at(40, &shoff, sizeof(shoff)) ||
        !read_at(54, &phentsize, sizeof(phentsize)) || !read_at(56, &phnum, sizeof(phnum)) ||
        !read_at(58, &shentsize, sizeof(shentsize)) || !read_at(60, &shnum, sizeof(shnum))) {
        return false;
    }
    if (phnum != 0 &&
        (phentsize < 56 || phoff > total ||
         static_cast<std::uint64_t>(phnum) * phentsize > total - phoff)) {
        return false;
    }
    for (std::uint16_t i = 0; i < phnum; ++i) {
        const auto base = phoff + static_cast<std::uint64_t>(i) * phentsize;
        std::uint32_t type = 0;
        std::uint64_t offset = 0;
        std::uint64_t filesz = 0;
        if (!read_at(base, &type, sizeof(type)) || !read_at(base + 8, &offset, sizeof(offset)) ||
            !read_at(base + 32, &filesz, sizeof(filesz))) {
            return false;
        }
        if (type == 1 /* PT_LOAD */ && (offset > total || filesz > total - offset)) {
            return false; // truncated copy
        }
    }
    if (shnum != 0 &&
        (shentsize < 64 || shoff > total ||
         static_cast<std::uint64_t>(shnum) * shentsize > total - shoff)) {
        return false;
    }
    return true;
#endif
}

// Unique scratch name: two processes materializing the same module must never write the
// same temp file (a shared temp can be promoted half-written by the other process).
inline std::filesystem::path unique_temp_path(const std::filesystem::path &canonical) {
    static std::atomic<unsigned> counter{0};
#if defined(_WIN32)
    const unsigned long pid = static_cast<unsigned long>(GetCurrentProcessId());
#else
    const unsigned long pid = static_cast<unsigned long>(::getpid());
#endif
    std::filesystem::path p = canonical;
    p += kMaterializeTempSuffix;
    p += "_" + std::to_string(pid) + "_" + std::to_string(counter.fetch_add(1));
    return p;
}

// Packaging is per platform: a Windows item ships "*.dll.pkg", a Linux one "*.so.pkg".
// Foreign-platform leftovers must not make this platform's tree look packaged — that
// would delete this platform's canonical modules (there is no twin for them).
#if defined(_WIN32)
inline constexpr const char *kPlatformModuleSuffix = ".dll";
#elif defined(__APPLE__)
inline constexpr const char *kPlatformModuleSuffix = ".dylib";
#else
inline constexpr const char *kPlatformModuleSuffix = ".so";
#endif

inline bool ends_with(const std::string &value, const char *suffix) {
    const std::string tail{suffix};
    return value.size() >= tail.size() &&
           value.compare(value.size() - tail.size(), tail.size(), tail) == 0;
}

// True for "<name><platform module suffix>.pkg" (plus ".so.pkg" on Apple, whose
// loader falls back to .so).
inline bool is_platform_package_twin(const std::string &name) {
    if (!ends_with(name, kPackageSuffix)) {
        return false;
    }
    const auto canonical = name.substr(0, name.size() - std::string{kPackageSuffix}.size());
    if (ends_with(canonical, kPlatformModuleSuffix)) {
        return true;
    }
#if defined(__APPLE__)
    return ends_with(canonical, ".so");
#else
    return false;
#endif
}

} // namespace detail

// Replace `dest` with `src` in one step where the platform allows it, so a concurrent
// reader sees either the old or the new file — never a missing or half-written one.
// Fails (returns false) when `dest` is mapped by another process; the caller keeps it.
inline bool atomic_replace(const std::filesystem::path &src, const std::filesystem::path &dest) {
#if defined(_WIN32)
    if (MoveFileExW(src.wstring().c_str(), dest.wstring().c_str(), MOVEFILE_REPLACE_EXISTING)) {
        return true;
    }
    return false;
#else
    std::error_code ec;
    std::filesystem::rename(src, dest, ec);
    return !ec;
#endif
}

// Materialize the canonical name from its ".pkg" twin when they differ.
// Returns true only when the canonical file was (re)written by this call.
//
// Concurrency: several processes of the same install (client + Master + Caves) may run this
// for the same module at the same time. It is safe because every writer uses a private temp
// file and only the atomic replace publishes it; a replace that loses the race against a
// peer that already promoted the same build is dropped, and a replace that hits a canonical
// another process has mapped fails and keeps the existing file.
inline bool materialize(const std::filesystem::path &canonical) {
    std::error_code ec;
    const auto from = packaged_path(canonical);
    if (!detail::is_regular(from)) {
        return false; // dev/zip layout: the canonical file is the shipped file
    }
    if (detail::is_regular(canonical) && detail::same_image(canonical, from)) {
        return false; // already current
    }
    if (!canonical.parent_path().empty()) {
        std::filesystem::create_directories(canonical.parent_path(), ec);
        ec.clear();
    }

    // Copy into a private temp; retry once when the twin moved under us (an item update
    // rewriting "<name>.pkg" while this boot reads it) or the copy came out incomplete.
    const auto tmp = detail::unique_temp_path(canonical);
    bool staged = false;
    for (int attempt = 0; attempt < 2 && !staged; ++attempt) {
        std::filesystem::remove(tmp, ec);
        ec.clear();
        std::filesystem::copy_file(from, tmp, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            break;
        }
        staged = detail::looks_complete(tmp) && detail::same_image(tmp, from);
    }
    if (!staged) {
        std::error_code rm_ec;
        std::filesystem::remove(tmp, rm_ec);
        std::fprintf(stderr, "[PackagedModule] stage_failed: %s\n", from.string().c_str());
        return false;
    }

    // Publishing: exclusive create when the canonical is absent (the rename fails instead of
    // clobbering a peer's just-promoted file), atomic replace when it is present.
    if (!detail::is_regular(canonical)) {
        std::error_code rn_ec;
        std::filesystem::rename(tmp, canonical, rn_ec); // no replace: loses the race cleanly
        if (!rn_ec) {
            std::fprintf(stderr, "[PackagedModule] materialized: %s\n", canonical.string().c_str());
            return true;
        }
        if (detail::is_regular(canonical) && detail::same_image(canonical, from)) {
            std::error_code rm_ec;
            std::filesystem::remove(tmp, rm_ec); // a peer promoted the same build
            return false;
        }
    }

    // A peer may have published the very same build after our first check.
    if (detail::is_regular(canonical) && detail::same_image(canonical, from)) {
        std::error_code rm_ec;
        std::filesystem::remove(tmp, rm_ec);
        return false;
    }

    if (atomic_replace(tmp, canonical)) {
        std::fprintf(stderr, "[PackagedModule] materialized: %s\n", canonical.string().c_str());
        return true;
    }
    std::error_code rm_ec;
    std::filesystem::remove(tmp, rm_ec);
    std::fprintf(stderr,
                 "[PackagedModule] kept existing %s (mapped by another process)\n",
                 canonical.string().c_str());
    return false;
}

// True when the canonical file is present after trying to materialize it.
//
// The twin is always compared, never taken as "already done" because a canonical file
// exists: replacing "<name>.pkg" (Steam item update, a manual copy) must refresh the
// derivative left behind by the previous build. `materialize` is the cheap no-op here —
// one stat for the twin, then a PE stamp/size compare when both files exist.
inline bool exists_or_materialize(const std::filesystem::path &canonical) {
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

// True when `tree` (a plugins root) ships packaged modules for this platform.
inline bool tree_is_packaged(const std::filesystem::path &tree) {
    std::error_code ec;
    if (tree.empty() || !std::filesystem::is_directory(tree, ec)) {
        return false;
    }
    for (std::filesystem::recursive_directory_iterator it(tree, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            return false;
        }
        std::error_code probe_ec;
        if (!it->is_regular_file(probe_ec)) {
            continue;
        }
        if (detail::is_platform_package_twin(it->path().filename().string())) {
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
