#pragma once

namespace ds::sdk::steam {

// Attach to the game's initialized SDK before loading plugins or resolving config.
void Initialize(bool is_client);

} // namespace ds::sdk::steam
