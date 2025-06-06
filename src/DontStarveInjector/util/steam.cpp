#ifdef ENABLE_STEAM_SUPPORT
#include "steam.hpp"
#include "steam_gameserver.h"
#include <frida-gum.h>
#include <functional>
#include <optional>
#include <spdlog/spdlog.h>
#include <steam_api.h>
#include <string_view>
#include <vector>

using namespace std::string_view_literals;

struct SteamInterface {
    decltype(&SteamInternal_ContextInit) My_SteamInternal_ContextInit = nullptr;
    decltype(&SteamAPI_GetHSteamUser) My_SteamAPI_GetHSteamUser = nullptr;
    decltype(&SteamGameServer_GetHSteamUser) My_SteamGameServer_GetHSteamUser = nullptr;
    decltype(&SteamInternal_FindOrCreateUserInterface) My_SteamInternal_FindOrCreateUserInterface = nullptr;
    decltype(&SteamInternal_FindOrCreateGameServerInterface) My_SteamInternal_FindOrCreateGameServerInterface = nullptr;
    GumModule *steam_module = nullptr;
    SteamInterface() {
        init();
    }

    bool find_module() {
        gum_process_enumerate_modules(
                +[](GumModule *module, gpointer user_data) -> gboolean {
                    auto steaminterface = (SteamInterface *) user_data;
                    auto module_name = gum_module_get_name(module);
                    if (std::string_view(module_name).contains("steam_api")) {
                        steaminterface->steam_module = module;
                        return false;// Stop enumerating modules
                    }
                    return true;// Continue enumerating
                },
                this);
    }
    void init() {
        steam_module = gum_process_find_module_by_name("steam_api");
        if (!steam_module) {
            spdlog::error("Failed to find steam_api module");
            return;
        }
        My_SteamInternal_ContextInit = (decltype(My_SteamInternal_ContextInit)) gum_module_find_export_by_name(steam_module, "SteamInternal_ContextInit");
        My_SteamAPI_GetHSteamUser = (decltype(My_SteamAPI_GetHSteamUser)) gum_module_find_export_by_name(steam_module, "SteamAPI_GetHSteamUser");
        My_SteamGameServer_GetHSteamUser = (decltype(My_SteamGameServer_GetHSteamUser)) gum_module_find_export_by_name(steam_module, "SteamGameServer_GetHSteamUser");
        My_SteamInternal_FindOrCreateUserInterface = (decltype(My_SteamInternal_FindOrCreateUserInterface)) gum_module_find_export_by_name(steam_module, "SteamInternal_FindOrCreateUserInterface");
        My_SteamInternal_FindOrCreateGameServerInterface = (decltype(My_SteamInternal_FindOrCreateGameServerInterface)) gum_module_find_export_by_name(steam_module, "SteamInternal_FindOrCreateGameServerInterface");
    }

    operator bool() const {
        return My_SteamInternal_ContextInit && My_SteamAPI_GetHSteamUser &&
               My_SteamGameServer_GetHSteamUser && My_SteamInternal_FindOrCreateUserInterface &&
               My_SteamInternal_FindOrCreateGameServerInterface && steam_module;
    }
};

SteamInterface &getSteamInterface() {
    static SteamInterface steamInterface;
    return steamInterface;
}

#define MY_STEAM_DEFINE_INTERFACE_ACCESSOR(type, name, expr, kind, version)                             \
    inline void S_CALLTYPE My_SteamInternal_Init_##name(type *p) { *p = (type) (expr); }                \
    STEAM_CLANG_ATTR("interface_accessor_kind:" kind ";interface_accessor_version:" version ";")        \
    inline type my_##name() {                                                                                \
        static void *s_CallbackCounterAndContext[3] = {(void *) &My_SteamInternal_Init_##name, 0, 0};   \
        return *(type *) getSteamInterface().My_SteamInternal_ContextInit(s_CallbackCounterAndContext); \
    }

#define MY_STEAM_DEFINE_USER_INTERFACE_ACCESSOR(type, name, version) \
    MY_STEAM_DEFINE_INTERFACE_ACCESSOR(type, name, getSteamInterface().My_SteamInternal_FindOrCreateUserInterface(getSteamInterface().My_SteamAPI_GetHSteamUser(), version), "user", version)
#define MY_STEAM_DEFINE_GAMESERVER_INTERFACE_ACCESSOR(type, name, version) \
    MY_STEAM_DEFINE_INTERFACE_ACCESSOR(type, name, getSteamInterface().My_SteamInternal_FindOrCreateGameServerInterface(getSteamInterface().My_SteamGameServer_GetHSteamUser(), version), "gameserver", version)

MY_STEAM_DEFINE_USER_INTERFACE_ACCESSOR(ISteamUser *, SteamUser, STEAMUSER_INTERFACE_VERSION);

std::optional<int64_t> getUserId() {
    if (!isSteamRunning()) {
        return std::nullopt;
    }
    return my_SteamUser()->GetSteamID().GetAccountID();
}

bool isSteamRunning() {
    return getSteamInterface();
}
#endif
