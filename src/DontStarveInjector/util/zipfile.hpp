#pragma once

#include <filesystem>
#include <expected>
#include <string>
#include <string_view>
#include <memory>
#include "file_interface.hpp"

using zip_file_interface = file_interface;

struct zip_manager_interface {
    virtual std::expected<std::string, std::string_view> readfile(const std::filesystem::path &p) = 0;

    virtual zip_file_interface *fopen(const std::filesystem::path &p) = 0;
};

std::unique_ptr<zip_manager_interface> create_zip_manager(std::filesystem::path zip_path);