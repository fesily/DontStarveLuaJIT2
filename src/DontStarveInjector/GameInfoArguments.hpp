#pragma once
#include "game_info.hpp"
#include "util/PathText.hpp"

#include <span>
#include <string_view>

// Use the engine's startup options instead of compiler-dependent std::string
// layouts and absolute/RIP address loads.
inline GameInfo game_info_from_arguments(std::span<const std::string> arguments) {
    GameInfo info{".klei/", std::filesystem::path{"DoNotStarveTogether"},
                  std::filesystem::path{"Cluster_1"}, std::filesystem::path{"Master"}};
    for (size_t i = 1; i < arguments.size(); ++i) {
        std::string_view key = arguments[i];
        if (!key.starts_with('-')) continue;
        key.remove_prefix(key.starts_with("--") ? 2 : 1);
        const auto equals = key.find('=');
        const auto name = key.substr(0, equals);
        std::filesystem::path *field = nullptr;
        std::string *text_field = nullptr;
        if (name == "persistent_storage_root") text_field = &info.persist_root;
        else if (name == "config_dir" || name == "conf_dir")
            field = &info.config_dir;
        else if (name == "cluster")
            field = &info.cluster_name;
        else if (name == "shard")
            field = &info.shared_name;
        if (!field && !text_field) continue;
        std::string_view value;
        if (equals != std::string_view::npos) {
            value = key.substr(equals + 1);
        } else if (i + 1 < arguments.size() && !arguments[i + 1].starts_with('-')) {
            value = arguments[++i];
        }
        if (value.empty()) continue;
        // Arguments arrive as UTF-8 text: decode to a path once here, so no call
        // site has to narrow a name back through the ANSI code page.
        if (field) *field = ds::util::path_from_utf8(value);
        else *text_field = std::string{value};
    }
    return info;
}
