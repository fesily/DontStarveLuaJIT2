#pragma once
#include <string>
#include <optional>
#include <filesystem>

struct luajit_config {
    std::string modmain_path;
    bool server_disable_luajit;
    float logic_fps;
    static std::optional<luajit_config> read_from_file(std::filesystem::path path = {});
};
