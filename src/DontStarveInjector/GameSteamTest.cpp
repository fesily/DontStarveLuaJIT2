#include <stdint.h>
#include <steam_sdk/steam_api.h>
#include <steam_sdk/isteamgameserver014.h>
#include <steam_sdk/isteamugc016.h>
#include <steam_sdk/isteamuser021.h>
#include <steam_sdk/isteamfriends017.h>

ISteamGameServer014* gameserver;
ISteamGameServer014 *SteamGameServer014() {
    return gameserver;
}

ISteamUGC016* ugc;
ISteamUGC016 *SteamUGC016() {
    return ugc;
}

ISteamUser021* user;
ISteamUser021 *SteamUser021() {
    return user;
}

ISteamFriends017* friends;
ISteamFriends017 *SteamFriends017() {
    return friends;
}
