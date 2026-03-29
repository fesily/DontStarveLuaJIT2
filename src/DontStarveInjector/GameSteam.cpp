
#include "util/steam_sdk.hpp"
#include "util/gum_platform.hpp"
#include "gameio.h"
#include "config.hpp"
#include <bit>
#include <cstdint>
#include <string_view>
#include <frida-gum.h>
#include <spdlog/spdlog.h>
using namespace std::string_view_literals;

static void *get_plt_ita_address(const std::string_view &target) {
    std::pair args = {target, (void *) 0};
    gum_module_enumerate_imports_ext(gum_process_get_main_module(), +[](const GumImportDetails *details, gpointer user_data) -> gboolean {
        auto pargs = (decltype(args) *) user_data;
        if (details->type == GUM_IMPORT_FUNCTION && details->name && details->name == pargs->first) {
            pargs->second = (void *) details->slot;
            return false;// stop enumeration
        }
        return true;// continue enumeration
    },
                                     (gpointer) &args);
    return args.second;
}

template<typename T>
bool memory_protect_write(T *addr, T value) {
    GumPageProtection prot;
    if (gum_memory_query_protection(addr, &prot)) {
        if (gum_try_mprotect(addr, sizeof(T), prot | GUM_PAGE_WRITE)) {
            *addr = value;
            gum_mprotect(addr, sizeof(T), prot);
            return true;
        }
    }
    return false;
}

static void hook_plt_ita(const std::string_view &target, void *new_func) {
    auto address = (void **) get_plt_ita_address(target);
    if (address == nullptr) {
        spdlog::error("Failed to find PLT ITA address for {}", target);
        return;
    }
    memory_protect_write(address, new_func);
}

void *(*SteamInternal_FindOrCreateGameServerInterface_fn)(uint32_t hSteamUser, const char *pszVersion);

namespace {

// For this pure virtual interface, the vtable slot matches the declaration order in isteamugc016.h.
// Deriving the slot from a member-function pointer is not portable across ABIs or compilers.
constexpr size_t kISteamUGC016_BInitWorkshopForGameServerIndex = 73;

template<typename Fn>
Fn get_vtable_function(void *obj, size_t index) {
    auto vtable = *reinterpret_cast<std::uintptr_t *const *>(obj);
    return std::bit_cast<Fn>(vtable[index]);
}

template<typename Fn>
bool replace_vtable_function(void *obj, size_t index, Fn replacement) {
    auto vtable = *reinterpret_cast<std::uintptr_t **>(obj);
    return memory_protect_write(&vtable[index], std::bit_cast<std::uintptr_t>(replacement));
}

}


bool (*BInitWorkshopForGameServer)(void *self, DepotId_t unWorkshopDepotID, const char *pszFolder);
static bool BInitWorkshopForGameServer_hook(void *self, DepotId_t unWorkshopDepotID, const char *pszFolder) {
    BInitWorkshopForGameServerHook(unWorkshopDepotID, pszFolder);
    return BInitWorkshopForGameServer(self, unWorkshopDepotID, pszFolder);
}

static void *SteamInternal_FindOrCreateGameServerInterface_hook(uint32_t hSteamUser, const char *pszVersion) {
    void *obj = SteamInternal_FindOrCreateGameServerInterface_fn(hSteamUser, pszVersion);
    if (pszVersion == nullptr) return obj;
    constexpr auto ugc_interface_version_prefix = "STEAMUGC_INTERFACE_VERSION"sv;
    if (std::string_view{pszVersion}.starts_with(ugc_interface_version_prefix)) {
        auto version = std::string_view{pszVersion}.substr(ugc_interface_version_prefix.size());
        if (version == "016") {
            auto current = get_vtable_function<decltype(BInitWorkshopForGameServer)>(obj, kISteamUGC016_BInitWorkshopForGameServerIndex);
            if (current == BInitWorkshopForGameServer_hook) {
                return obj;// already hooked
            }

            BInitWorkshopForGameServer = current;
            if (!replace_vtable_function(obj, kISteamUGC016_BInitWorkshopForGameServerIndex, BInitWorkshopForGameServer_hook)) {
                spdlog::error("Failed to hook ISteamUGC016::BInitWorkshopForGameServer");
            }
        }
    }
    return obj;
}

void HookSteamGameServerInterface() {
    auto path = get_module_path("steam_api");
    if (path.empty()) {
        spdlog::error("Failed to find steam_api module");
        return;
    }
    
    if (!InjectorCtx::instance()->DontStarveInjectorIsClient) {
        constexpr auto api_name = "SteamInternal_FindOrCreateGameServerInterface";
        auto m = gum_process_find_module_by_name(path.c_str());
        SteamInternal_FindOrCreateGameServerInterface_fn = (decltype(SteamInternal_FindOrCreateGameServerInterface_fn)) gum_module_find_export_by_name(m, api_name);
        if (SteamInternal_FindOrCreateGameServerInterface_fn == nullptr) {
            spdlog::error("Failed to find {} in steam_api module", api_name);
            return;
        }
        hook_plt_ita(api_name, (void *) SteamInternal_FindOrCreateGameServerInterface_hook);
    }
    // get user account id
    auto steamuser = SteamUser();
    if (steamuser) {
        InjectorCtx::instance()->steam_account_id = steamuser->GetSteamID().GetAccountID();
    }
}
