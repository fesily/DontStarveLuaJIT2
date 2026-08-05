#pragma once
// Client save write-back for the GameJitModConfig projection bag.
// Load path remains config/sources/*; this is write-only.

#include "gameModConfig.hpp"

#include <filesystem>

// Returns true if the save table was written successfully.
bool WriteGameJitModConfigToSaveFile(const std::filesystem::path &path,
                                     const GameJitModConfig &config);
