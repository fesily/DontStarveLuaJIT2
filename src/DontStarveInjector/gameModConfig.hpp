#pragma once
#include "config.hpp"
#include <string>
#include <optional>
struct GameJitModConfig {
    std::string angle_backend;

    static std::optional<GameJitModConfig> instance();
};
DONTSTARVEINJECTOR_API int DS_LUAJIT_set_target_fps(int fps, int tt);