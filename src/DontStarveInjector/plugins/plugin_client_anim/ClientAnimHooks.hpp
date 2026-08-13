#pragma once

// Win x64 client.anim native face.
bool client_anim_install_hooks();
void client_anim_set_local_player_entity(void *entity);
void client_anim_set_own(bool on);
bool client_anim_get_own();
bool client_anim_is_installed();
int client_anim_enter_count();
int client_anim_xor_patched();
int client_anim_match_count();
