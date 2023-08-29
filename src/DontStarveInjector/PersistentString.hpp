#pragma once
#include <string>
#include <expected>

std::expected<std::string, std::string> GetPersistentString(const std::string_view &filename);
bool SetPersistentString(const std::string_view &filename, const std::string_view &data, bool encode);