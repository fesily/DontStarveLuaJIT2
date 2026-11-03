#pragma once
#include <filesystem>
#include <optional>
#include <string>

// Engine startup options that name storage locations.
//
// The three name fields are paths, not text: they are only ever used to build a
// path, so they are decoded from UTF-8 exactly once (argv parse / env override)
// and never narrowed back. `persist_root` stays text on purpose: it can carry the
// "APP:Klei/" scheme prefix, which has to be stripped before it means a path.
struct GameInfo{
    std::string persist_root;
    std::filesystem::path config_dir;
    std::filesystem::path cluster_name;
    std::filesystem::path shared_name;
};

std::optional<GameInfo> readGameInfo();