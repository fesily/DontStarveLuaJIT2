#pragma once
#ifdef ENABLE_STEAM_SUPPORT
#include <filesystem>
#define MODIDS(id) \
constexpr auto modid = id; \
constexpr auto modid_name = "workshop-"#id;
std::optional<int64_t> getUserId();
bool isModNeedUpdated();
#endif
