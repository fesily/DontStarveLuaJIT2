#pragma once
#include <string>
#include <optional>
#include <filesystem>

struct luajit_config {
    std::string modmain_path;
    std::string modname;
    std::string modid;
    bool server_disable_luajit;
    static std::optional<luajit_config> read_from_file(std::filesystem::path path = {});
};
