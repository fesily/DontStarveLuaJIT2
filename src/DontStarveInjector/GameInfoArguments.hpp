#pragma once
#include "game_info.hpp"
#include <span>
#include <string_view>

// Use the engine's startup options instead of compiler-dependent std::string
// layouts and absolute/RIP address loads.
inline GameInfo game_info_from_arguments(std::span<const std::string> arguments) {
    GameInfo info{".klei/", "DoNotStarveTogether", "Cluster_1", "Master"};
    for (size_t i = 1; i < arguments.size(); ++i) {
        std::string_view key = arguments[i];
        if (!key.starts_with('-')) continue;
        key.remove_prefix(key.starts_with("--") ? 2 : 1);
        const auto equals = key.find('=');
        const auto name = key.substr(0, equals);
        std::string *field = nullptr;
        if (name == "persistent_storage_root") field = &info.persist_root;
        else if (name == "config_dir" || name == "conf_dir")
            field = &info.config_dir;
        else if (name == "cluster")
            field = &info.cluster_name;
        else if (name == "shard")
            field = &info.shared_name;
        if (!field) continue;
        if (equals != std::string_view::npos) {
            const auto value = key.substr(equals + 1);
            if (!value.empty()) *field = value;
        } else if (i + 1 < arguments.size() && !arguments[i + 1].starts_with('-')) {
            *field = arguments[++i];
        }
    }
    return info;
}
