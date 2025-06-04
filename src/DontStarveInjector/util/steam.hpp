#pragma once
#ifdef ENABLE_STEAM_SUPPORT
#include <filesystem>
#include <optional>
#include <stdint.h>
#include <functional>
#define MODIDS(id) \
constexpr auto modid = id; \
constexpr auto modid_name = "workshop-"#id;
constexpr auto GAME_APP_ID = 322330U;

std::optional<int64_t> getUserId();
bool isModNeedUpdated();
std::optional<std::filesystem::path> getUgcDir();
void registerUgcDirCallback(std::function<void(const std::filesystem::path&)> callback);
#endif
