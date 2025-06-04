#ifdef ENABLE_STEAM_SUPPORT
#include "steam.hpp"
#include "steam_gameserver.h"
#include <optional>
#include <steam_api.h>
#include <string_view>
#include <filesystem>
#include <functional>
#include <vector>

using namespace std::string_view_literals;
#ifndef MAX_PATH
#define MAX_PATH 256
#endif
struct SteamApiInterface {
};

static SteamApiInterface *get() {
    static SteamApiInterface api;
    return &api;
}

std::optional<int64_t> getUserId() {
    if (!get()) {
        return std::nullopt;
    }
    return SteamUser()->GetSteamID().GetAccountID();
}

static std::optional<std::filesystem::path> getItemInstallPath(PublishedFileId_t publishedFileId) {
    ISteamUGC* ugc = SteamUGC();
    if (!ugc) ugc = SteamGameServerUGC();
    char folder[MAX_PATH];
    if (ugc->GetItemInstallInfo(publishedFileId, nullptr, folder, sizeof(folder), nullptr)) {
        return std::filesystem::path(folder);
    }
    return std::nullopt;
}

std::optional<std::filesystem::path> getUgcDir() {
    if (!get()) {
        return std::nullopt;
    }
    ISteamUGC* ugc = SteamUGC();
    if (!ugc) ugc = SteamGameServerUGC();
    ugc->BInitWorkshopForGameServer(GAME_APP_ID, NULL);
    uint32 numSubscribed = ugc->GetNumSubscribedItems();
    std::vector<PublishedFileId_t> subscribedItems(numSubscribed);
    ugc->GetSubscribedItems(subscribedItems.data(), numSubscribed);
    for (auto subscribedItem: subscribedItems) {
        if (ugc->GetItemState(subscribedItem) & k_EItemStateInstalled) {
            return getItemInstallPath(subscribedItem);
        }
    }
    return std::nullopt;
}
class SteamApiListener
{
public:
    STEAM_CALLBACK(SteamApiListener, OnItemInstalled, ItemInstalled_t);
    void Update()
    {
        SteamAPI_RunCallbacks();
    }
    std::function<void(const std::filesystem::path&)> callback;
};

void SteamApiListener::OnItemInstalled(ItemInstalled_t *pCallback)
{
    if (!callback) return;
    if (pCallback->m_unAppID == GAME_APP_ID)
    {
        PublishedFileId_t publishedFileId = pCallback->m_nPublishedFileId;
        auto p = getItemInstallPath(publishedFileId);
        if (p) 
        {
            callback(p.value());
        }
    }
}
void registerUgcDirCallback(std::function<void(const std::filesystem::path&)> callback)
{
    static SteamApiListener listener;
    listener.callback = callback;
}
#endif