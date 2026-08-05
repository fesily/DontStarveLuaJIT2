#pragma once

#include "config/InjectorHostConfig.hpp"
#include "core/PluginHost.hpp"

// network.rpc plugin (plugin_network_rpc) — RPC4 / entity channel hooks.
DONTSTARVEINJECTOR_GAME_API void GameNetWorkHookRpc4();

// Register GAME_API symbols into the Host service table (called from module_init).
void RegisterNetworkRpcHostServices(ds::plugin::PluginHost *host);

extern "C" void DS_LUAJIT_SetNextRpcInfo_C(const int *prio, const int *rel, const int *ch);
