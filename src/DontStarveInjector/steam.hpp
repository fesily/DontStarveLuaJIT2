#pragma once
#include <filesystem>
#define MODIDS(id) \
constexpr auto modid = id; \
constexpr auto modid_name = "workshop-"#id;
MODIDS(3010545764)
std::optional<std::filesystem::path> getModDir();
std::optional<int64_t> getUserId();
bool isModNeedUpdated();