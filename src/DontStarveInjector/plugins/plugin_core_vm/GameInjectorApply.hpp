#pragma once
struct lua_State;
namespace ds::core_vm {
void apply_game_injector_exports(lua_State *L, int table_idx);
}
