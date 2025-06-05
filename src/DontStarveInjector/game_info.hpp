#pragma once
#include <string>
#include <optional>
struct GameInfo{
    std::string persist_root;
    std::string config_dir;
    std::string cluster_name;
    std::string shared_name;
};

std::optional<GameInfo> readGameInfo();