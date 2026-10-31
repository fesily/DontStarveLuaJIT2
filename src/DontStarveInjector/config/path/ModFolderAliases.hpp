#pragma once
#include <array>
#include <string_view>

namespace ds::config::path {

using namespace std::string_view_literals;

inline constexpr auto kPrimaryWorkshopModName = "workshop-3444078585"sv;

// Order is priority for first-match scans (workshop id first, then local/dev names).
// The scan compares path components exactly, so on Linux/macOS these names are
// case-sensitive: every spelling users realistically create is listed explicitly
// (the docs used to say `Luajit`, older installs used `luajit2`), never relying on
// a case-insensitive filesystem to paper over the difference.
inline constexpr auto kModFolderAliases = std::to_array<std::string_view>({
    kPrimaryWorkshopModName,
    "3444078585"sv,
    "luajit"sv,
    "Luajit"sv,
    "luajit2"sv,
    "Luajit2"sv,
    "DontStarveLuaJit2"sv,
    "dontstarveluajit2"sv,
    "DontStarveLuaJIT2"sv,
});

} // namespace ds::config::path
