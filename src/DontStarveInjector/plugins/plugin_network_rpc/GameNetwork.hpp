#pragma once

#include "config.hpp"

// network.rpc plugin (plugin_network_rpc) — RPC4 / entity channel hooks.
DONTSTARVEINJECTOR_GAME_API void GameNetWorkHookRpc4();

// Register GAME_API symbols into the Host service table (called from module_init).
void RegisterNetworkRpcHostServices();
