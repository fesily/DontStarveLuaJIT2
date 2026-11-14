#pragma once
// Pure path mapping for Lua-visible game IO: "../mods/workshop-<id>/<file>"
// names a file under the Workshop content root when the game does not keep a
// copy under <game>/mods. Kept header-only and dependency-free so the mapping
// rules are unit-testable without the injector (frida/Steam/zip stack).

#include <filesystem>
#include <optional>
#include <string_view>

namespace ds::injector::io {

// Both the engine and mods spell mod paths with this prefix.
inline constexpr std::string_view kWorkshopModsPrefix = "../mods/workshop-";

struct WorkshopModPath {
    std::string_view mod_id;    // "3435352667"
    std::string_view relative;  // "main/ia_preparedfoods.lua" (no leading separator)
};

// Splits "../mods/workshop-<id>/<relative>". Accepts either separator.
// Returns nullopt for a bare mod root ("../mods/workshop-123") and for any
// path outside the prefix.
inline std::optional<WorkshopModPath> split_workshop_mod_path(std::string_view path) {
    if (!path.starts_with(kWorkshopModsPrefix)) {
        return std::nullopt;
    }
    const auto rest = path.substr(kWorkshopModsPrefix.size());
    const auto separator = rest.find_first_of("/\\");
    if (separator == std::string_view::npos || separator == 0) {
        return std::nullopt;
    }
    return WorkshopModPath{rest.substr(0, separator), rest.substr(separator + 1)};
}

// "../mods/workshop-<id>/<relative>" -> <workshop_root>/<id>/<relative>.
// The relative part must not carry the id again: the caller already appends it
// through the mod directory, which is what doubled the id in da5b9f0.
inline std::optional<std::filesystem::path> map_workshop_mod_path(
        std::string_view path, const std::filesystem::path &workshop_root) {
    const auto split = split_workshop_mod_path(path);
    if (!split) {
        return std::nullopt;
    }
    auto mapped = workshop_root / std::string{split->mod_id};
    if (!split->relative.empty()) {
        mapped /= std::string{split->relative};
    }
    return mapped;
}

}  // namespace ds::injector::io
