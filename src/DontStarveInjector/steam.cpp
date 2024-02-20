#include <steam_api.h>

#include "steam.hpp"
#include <optional>
#include <string_view>
using namespace std::string_view_literals;
#ifndef MAX_PATH
#define MAX_PATH 256
#endif
struct SteamApiInterface
{
};

static SteamApiInterface *get()
{
    static SteamApiInterface *api = []() -> SteamApiInterface *
    {   
        auto env = getenv("SteamEnv");
        if (!env || env != "1"sv)
            return nullptr;
        if (SteamAPI_Init())
            return new SteamApiInterface{};
        return nullptr;
    }();
    return api;
}

std::optional<std::filesystem::path> getModDir()
{
    if (!get())
    {
        return std::nullopt;
    }
    uint64_t punSizeOnDisk;
    uint32_t punTimeStamp;
    char path[MAX_PATH];
    if (SteamUGC()->GetItemInstallInfo(modid, &punSizeOnDisk, path, 255, &punTimeStamp))
    {
        return path;
    }
    return std::nullopt;
}

bool isModNeedUpdated() {
    if (!get())
        return false;
    return SteamUGC()->GetItemState(modid) & k_EItemStateNeedsUpdate;
}

std::optional<int64_t> getUserId()
{
    if (!get())
    {
        return -1;
    }
    return SteamUser()->GetSteamID().GetAccountID();
}