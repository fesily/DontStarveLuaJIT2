#pragma once
#ifdef ENABLE_STEAM_SUPPORT
#include <optional>
#include <stdint.h>
#define MODIDS(id) \
constexpr auto modid = id; \
constexpr auto modid_name = "workshop-"#id;
constexpr auto GAME_APP_ID = 322330U;

std::optional<int64_t> getUserId();
bool isSteamRunning();
#endif
