#pragma once
// Client save write-back from WriteBackBag (projection of ResolvedConfig).

#include "WriteBackBag.hpp"

#include <filesystem>

namespace ds::config {

bool WriteGameJitModConfigToSaveFile(const std::filesystem::path &path, const WriteBackBag &config);

} // namespace ds::config
