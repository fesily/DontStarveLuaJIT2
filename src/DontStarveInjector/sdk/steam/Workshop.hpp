#pragma once

#include "config/InjectorHostConfig.hpp"
#include <filesystem>
#include <optional>

namespace ds::sdk::steam {

// Called by the host Steam UGC hook; null leaves the current directory unchanged.
void SetWorkshopDirectory(const char *folder);

// Content directory, with -ugc_directory taking precedence over the SDK path.
// References remain valid until the next SetWorkshopDirectory call.
DS_INJECTOR_CXX_API const std::optional<std::filesystem::path> &GetWorkshopDirectory();

} // namespace ds::sdk::steam

DONTSTARVEINJECTOR_API const char *DS_LUAJIT_get_workshop_dir();
