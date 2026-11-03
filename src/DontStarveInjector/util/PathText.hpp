#pragma once

#include <exception>
#include <filesystem>
#include <string>
#include <string_view>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

namespace ds::util {

// Path <-> text conversions for paths that may contain characters the active
// ANSI code page cannot represent.
//
// `std::filesystem::path::string()` narrows through the ANSI code page and
// throws std::system_error(ERROR_NO_UNICODE_TRANSLATION == 1113, "No mapping for
// the Unicode character exists in the target multi-byte code page") when a
// character has no mapping there. A Klei save root can hold such a name: a GBK
// folder name stored byte-per-character as Latin-1 (U+00B7 U+00E8 U+00BF ...
// U+00FA) is legal on NTFS but impossible in CP936. An uncaught throw during
// plugin/config startup terminates the game process (0xE06D7363), so never
// narrow a path that came from the filesystem or from user data.
//
// The rule this header exists to express: a path becomes text only through
// u8string()/generic_u8string() (total, never throws), and text becomes a path
// only through path_from_utf8() (UTF-8 decode, never the ANSI code page).
// Header-only on purpose: several standalone test/tool targets compile single
// Injector translation units without linking the Injector library.
//
// Logging does NOT need any of this: fmt (and therefore spdlog) has a
// std::filesystem::path formatter that renders the native path as UTF-8 and never
// throws — include <spdlog/fmt/std.h> and pass the path straight to the format
// string. `{:g}` asks for '/' separators. Convert only where the consumer wants a
// std::string: concatenation, keys/maps, JSON/Lua/Steam/libzip payloads.

namespace path_text_detail {

inline std::string u8_to_string(const std::u8string &text) {
    return std::string{reinterpret_cast<const char *>(text.data()), text.size()};
}

} // namespace path_text_detail

// UTF-8 text for a path. Never throws: on Windows wide -> UTF-8 is total.
inline std::string path_to_utf8(const std::filesystem::path &path) {
    if (path.empty()) {
        return {};
    }
    try {
        return path_text_detail::u8_to_string(path.u8string());
    } catch (const std::exception &) {
        return {};
    }
}

// Same, with '/' separators on every platform (the `.generic_string()` role).
// Use for text comparisons, set/map keys and diagnostics that expect one form.
inline std::string path_to_utf8_generic(const std::filesystem::path &path) {
    if (path.empty()) {
        return {};
    }
    try {
        return path_text_detail::u8_to_string(path.generic_u8string());
    } catch (const std::exception &) {
        return {};
    }
}

// Native (ANSI) text when every character maps, UTF-8 otherwise. Only for
// consumers that are themselves narrow and cannot be changed (cmd.exe lines,
// engine/batch interfaces): a readable string beats an exception, and the
// fallback at least keeps the bytes unambiguous.
inline std::string path_to_native_lossy(const std::filesystem::path &path) {
    if (path.empty()) {
        return {};
    }
    try {
        return path.string();
    } catch (const std::exception &) {
        return path_to_utf8(path);
    }
}

// Hash for path-keyed containers. The standard provides std::filesystem::hash_value
// but no std::hash<path> specialization, so sets/maps of paths need this.
struct PathHash {
    size_t operator()(const std::filesystem::path &path) const noexcept {
        return std::filesystem::hash_value(path);
    }
};

// Filesystem path for UTF-8 text. Windows construction from narrow chars
// assumes ANSI, so decode UTF-8 explicitly. Never throws.
inline std::filesystem::path path_from_utf8(std::string_view text) {
#if defined(_WIN32)
    if (text.empty()) {
        return {};
    }
    const int needed = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                             nullptr, 0);
    if (needed <= 0) {
        return std::filesystem::path{std::string{text}};
    }
    std::wstring wide(static_cast<size_t>(needed), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(),
                              needed) != needed) {
        return std::filesystem::path{std::string{text}};
    }
    return std::filesystem::path{wide};
#else
    return std::filesystem::path{std::string{text}};
#endif
}

} // namespace ds::util
