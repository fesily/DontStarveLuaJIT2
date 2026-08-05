#include "PluginZipExtract.hpp"

#include <zip.h>

#include <cctype>
#include <cstring>
#include <fstream>
#include <vector>

namespace ds::plugin_manager {
namespace {

bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

// Normalize separators to '/'; drop leading "./".
std::string normalize_entry_name(std::string_view name) {
    std::string s(name);
    for (char &c : s) {
        if (c == '\\') {
            c = '/';
        }
    }
    while (s.starts_with("./")) {
        s.erase(0, 2);
    }
    // Strip trailing slash (directory markers).
    while (!s.empty() && s.back() == '/') {
        s.pop_back();
    }
    return s;
}

bool has_dotdot_segment(std::string_view path) {
    size_t i = 0;
    while (i < path.size()) {
        size_t j = path.find('/', i);
        if (j == std::string_view::npos) {
            j = path.size();
        }
        const auto seg = path.substr(i, j - i);
        if (seg == "..") {
            return true;
        }
        if (j == path.size()) {
            break;
        }
        i = j + 1;
    }
    return false;
}

bool is_module_basename(std::string_view name) {
    if (!name.starts_with("plugin_")) {
        return false;
    }
    auto ends = [&](std::string_view suf) {
        return name.size() > suf.size() &&
               iequals_ascii(name.substr(name.size() - suf.size()), suf);
    };
    return ends(".dll") || ends(".so") || ends(".dylib");
}

bool is_meta_basename(std::string_view name) {
    constexpr std::string_view suf = ".meta.json";
    return name.starts_with("plugin_") && name.size() > suf.size() && name.ends_with(suf);
}

struct ExtractCtx {
    const std::unordered_set<std::string> *allow = nullptr; // empty => default
    std::filesystem::path dest;
    size_t written = 0;
    std::string *err = nullptr;
};

bool allow_basename(const ExtractCtx &ctx, const std::string &base) {
    if (ctx.allow && !ctx.allow->empty()) {
        return ctx.allow->count(base) > 0;
    }
    return zip_entry_matches_default_allowlist(base);
}

bool write_entry_to_disk(zip_t *za, zip_int64_t index, const std::filesystem::path &out_path,
                         std::string *err) {
    zip_stat_t st{};
    zip_stat_init(&st);
    if (zip_stat_index(za, index, 0, &st) != 0 || (st.valid & ZIP_STAT_SIZE) == 0) {
        if (err) {
            *err = "zip: stat failed";
        }
        return false;
    }
    zip_file_t *zf = zip_fopen_index(za, index, 0);
    if (!zf) {
        if (err) {
            *err = "zip: fopen failed";
        }
        return false;
    }

    std::error_code ec;
    if (!out_path.parent_path().empty()) {
        std::filesystem::create_directories(out_path.parent_path(), ec);
    }
    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        zip_fclose(zf);
        if (err) {
            *err = "zip: cannot open dest for write";
        }
        return false;
    }

    std::vector<char> buf(1 << 15);
    zip_uint64_t remaining = st.size;
    while (remaining > 0) {
        const zip_uint64_t chunk =
            remaining < buf.size() ? remaining : static_cast<zip_uint64_t>(buf.size());
        const zip_int64_t n = zip_fread(zf, buf.data(), chunk);
        if (n < 0) {
            zip_fclose(zf);
            if (err) {
                *err = "zip: fread failed";
            }
            return false;
        }
        if (n == 0) {
            break;
        }
        out.write(buf.data(), static_cast<std::streamsize>(n));
        if (!out) {
            zip_fclose(zf);
            if (err) {
                *err = "zip: write failed";
            }
            return false;
        }
        remaining -= static_cast<zip_uint64_t>(n);
    }
    zip_fclose(zf);
    return true;
}

std::optional<size_t> extract_archive(zip_t *za, const std::filesystem::path &dest_dir,
                                      const std::vector<std::string> &allow_files,
                                      std::string *err) {
    if (!za) {
        if (err) {
            *err = "zip: null archive";
        }
        return std::nullopt;
    }

    std::unordered_set<std::string> allow_set(allow_files.begin(), allow_files.end());
    ExtractCtx ctx;
    ctx.allow = &allow_set;
    ctx.dest = dest_dir;
    ctx.err = err;

    std::error_code ec;
    std::filesystem::create_directories(dest_dir, ec);

    const zip_int64_t n = zip_get_num_entries(za, 0);
    if (n < 0) {
        if (err) {
            *err = "zip: get_num_entries failed";
        }
        return std::nullopt;
    }

    for (zip_int64_t i = 0; i < n; ++i) {
        const char *raw = zip_get_name(za, i, ZIP_FL_ENC_GUESS);
        if (!raw) {
            continue;
        }
        const std::string name = normalize_entry_name(raw);
        if (name.empty()) {
            continue;
        }
        // Directory entries end with / before normalize; skip pure dirs.
        if (std::string_view(raw).ends_with('/') || std::string_view(raw).ends_with('\\')) {
            continue;
        }
        if (zip_entry_is_unsafe(name)) {
            if (err) {
                *err = "zip: rejected unsafe entry: " + name;
            }
            return std::nullopt;
        }
        // Only top-level names (no nested dirs) — packages store basenames only.
        if (name.find('/') != std::string::npos) {
            // Nested path that is not `..` still rejected for plugins (flat layout).
            if (err) {
                *err = "zip: rejected nested entry: " + name;
            }
            return std::nullopt;
        }
        const std::string base = zip_entry_safe_basename(name);
        if (base.empty()) {
            if (err) {
                *err = "zip: rejected entry basename: " + name;
            }
            return std::nullopt;
        }
        if (!allow_basename(ctx, base)) {
            continue; // skip non-allowlisted silently
        }
        const auto out_path = dest_dir / base;
        if (!write_entry_to_disk(za, i, out_path, err)) {
            return std::nullopt;
        }
        ++ctx.written;
    }
    return ctx.written;
}

} // namespace

bool zip_entry_is_unsafe(std::string_view name) {
    if (name.empty()) {
        return true;
    }
    const std::string n = normalize_entry_name(name);
    if (n.empty()) {
        return true;
    }
    // Absolute unix or windows.
    if (n.front() == '/' || n.front() == '\\') {
        return true;
    }
    // Drive letter forms like C: / path
    if (n.size() >= 2 && std::isalpha(static_cast<unsigned char>(n[0])) && n[1] == ':') {
        return true;
    }
    if (has_dotdot_segment(n)) {
        return true;
    }
    // UNC or residual backslash after normalize should not appear; treat as unsafe.
    if (n.find('\\') != std::string::npos) {
        return true;
    }
    return false;
}

std::string zip_entry_safe_basename(std::string_view name) {
    if (zip_entry_is_unsafe(name)) {
        return {};
    }
    const std::string n = normalize_entry_name(name);
    const auto pos = n.rfind('/');
    const std::string base = (pos == std::string::npos) ? n : n.substr(pos + 1);
    if (base.empty() || base == "." || base == "..") {
        return {};
    }
    return base;
}

bool zip_entry_matches_default_allowlist(std::string_view basename) {
    return is_module_basename(basename) || is_meta_basename(basename);
}

std::optional<size_t> extract_plugin_zip(const std::filesystem::path &zip_path,
                                         const std::filesystem::path &dest_dir,
                                         const std::vector<std::string> &allow_files,
                                         std::string *err) {
    int zerr = 0;
    zip_t *za = zip_open(zip_path.string().c_str(), ZIP_RDONLY, &zerr);
    if (!za) {
        if (err) {
            *err = "zip: open failed code " + std::to_string(zerr);
        }
        return std::nullopt;
    }
    auto result = extract_archive(za, dest_dir, allow_files, err);
    zip_close(za);
    return result;
}

std::optional<size_t> extract_plugin_zip_memory(const void *data, size_t size,
                                                const std::filesystem::path &dest_dir,
                                                const std::vector<std::string> &allow_files,
                                                std::string *err) {
    if (!data || size == 0) {
        if (err) {
            *err = "zip: empty buffer";
        }
        return std::nullopt;
    }
    zip_error_t ze;
    zip_error_init(&ze);
    zip_source_t *src = zip_source_buffer_create(data, size, 0, &ze);
    if (!src) {
        if (err) {
            *err = std::string("zip: source_buffer ") + zip_error_strerror(&ze);
        }
        zip_error_fini(&ze);
        return std::nullopt;
    }
    zip_t *za = zip_open_from_source(src, ZIP_RDONLY, &ze);
    if (!za) {
        zip_source_free(src);
        if (err) {
            *err = std::string("zip: open_from_source ") + zip_error_strerror(&ze);
        }
        zip_error_fini(&ze);
        return std::nullopt;
    }
    zip_error_fini(&ze);
    auto result = extract_archive(za, dest_dir, allow_files, err);
    zip_close(za);
    return result;
}

} // namespace ds::plugin_manager
