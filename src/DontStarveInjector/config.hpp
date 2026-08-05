#pragma once
// Re-export: process/host config lives under config/.
// Game-option cascade: ConfigSchema + ConfigSession (separate).
// InjectorConfig flags do NOT go through option schema registration.
#include "config/InjectorHostConfig.hpp"
