// ClientPingApi.cpp — GameInjector export for network.stats.
//
//   DS_LUAJIT_net_client_ping(userid) -> milliseconds, -1 unknown/disabled
//
// That single value is the plugin's whole published surface; everything else a
// consumer needs (client enumeration, names, netscore, ...) comes from the Lua
// side (TheNet:GetClientTable et al).

#include "config/InjectorHostConfig.hpp"

#include "ClientPingHook.hpp"

#include <cstdint>

DONTSTARVEINJECTOR_GAME_API int32_t DS_LUAJIT_net_client_ping(const char *userid) {
    return ds::net_stats::client_ping_lookup(userid);
}
