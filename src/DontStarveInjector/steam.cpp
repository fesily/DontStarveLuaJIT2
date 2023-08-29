#include <steam_api.h>

#include "steam.hpp"

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
        if (SteamAPI_Init())
            return new SteamApiInterface{};
        return nullptr;
    }();
    return api;
}

std::filesystem::path getModDir()
{
    if (!get())
    {
        return {};
    }
    uint64_t punSizeOnDisk;
    uint32_t punTimeStamp;
    char path[MAX_PATH];
    if (SteamUGC()->GetItemInstallInfo(modid, &punSizeOnDisk, path, 255, &punTimeStamp))
    {
        return path;
    }
    return {};
}

int64_t getUserId()
{
    if (!get())
    {
        return -1;
    }
    return SteamUser()->GetSteamID().GetAccountID();
}