#include <steam_api.h>
#include <optional>
#include <string_view>
#include "steam.hpp"

using namespace std::string_view_literals;
#ifndef MAX_PATH
#define MAX_PATH 256
#endif
struct SteamApiInterface {
};

static SteamApiInterface *get() {
    static SteamApiInterface *api = []() -> SteamApiInterface * {
        auto env = getenv("SteamEnv");
        if (!env || env != "1"sv)
            return nullptr;
        if (SteamAPI_Init())
            return new SteamApiInterface{};
        return nullptr;
    }();
    return api;
}

std::optional<int64_t> getUserId() {
    if (!get()) {
        return std::nullopt;
    }
    return SteamUser()->GetSteamID().GetAccountID();
}