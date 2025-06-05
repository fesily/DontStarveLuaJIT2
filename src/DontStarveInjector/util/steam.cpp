#ifdef ENABLE_STEAM_SUPPORT
#include "steam.hpp"
#include "steam_gameserver.h"
#include <frida-gum.h>
#include <functional>
#include <optional>
#include <steam_api.h>
#include <string_view>
#include <vector>

using namespace std::string_view_literals;

std::optional<int64_t> getUserId() {
    if (!isSteamRunning()) {
        return std::nullopt;
    }
    return SteamUser()->GetSteamID().GetAccountID();
}

bool isSteamRunning() {
    bool ret = false;
    gum_process_enumerate_modules(
            +[](GumModule *module, gpointer user_data) -> gboolean {
                auto &ret = *(bool *) user_data;
                auto module_name = gum_module_get_name(module);
                if (std::string_view(module_name).contains("steamclient")) {
                    ret = true;
                    return false;// Stop enumerating modules
                }
                return true;// Continue enumerating
            },
            nullptr);
    return ret;
}
#endif