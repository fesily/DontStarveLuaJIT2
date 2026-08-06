#pragma once
#include <array>
#include <string_view>

namespace ds::config::path {

using namespace std::string_view_literals;

inline constexpr auto kPrimaryWorkshopModName = "workshop-3444078585"sv;

// Order is priority for first-match scans (workshop id first, then local/dev names).
inline constexpr std::array<std::string_view, 6> kModFolderAliases = {
    kPrimaryWorkshopModName,
    "3444078585"sv,
    "luajit"sv,
    "luajit2"sv,
    "DontStarveLuaJit2"sv,
    "DontStarveLuaJIT2"sv,
};

} // namespace ds::config::path
