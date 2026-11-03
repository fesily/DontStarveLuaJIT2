#pragma once

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

// Klei-formatted persistent string files.
//
// Takes a filesystem path rather than a narrow string: the save root can hold
// names the ANSI code page cannot represent, and Windows opens those through the
// wide path. Nothing here narrows a user-supplied path, so no call can throw
// ERROR_NO_UNICODE_TRANSLATION.
std::expected<std::string, std::string> GetPersistentString(const std::filesystem::path &filename);

bool SetPersistentString(const std::filesystem::path &filename, const std::string_view &data,
                         bool encode);
