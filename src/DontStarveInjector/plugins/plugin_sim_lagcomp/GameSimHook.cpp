#include "config.hpp"
#include "GameLua.hpp"

#include <cstdint>
#include <cmath>
#include <cstring>
#include <chrono>

// ---------------------------------------------------------------------------
// Entity layout (Windows x64, confirmed via QueryPred::operator() analysis)
// Source binary: dontstarve_steam_x64.exe (Windows x64)
// Reference:     dontstarve_steam (macOS 32-bit, full symbols)
//
//   entity+0x1f0  float  worldPosX   (macOS 32-bit: +0xe8)
//   entity+0x1f4  float  worldPosY   (macOS 32-bit: +0xec)
//   entity+0x1f8  float  worldPosZ   (macOS 32-bit: +0xf0)
//
// inst.entity Lua unwrap (Lunar<EntityLuaProxy> full userdata):
//   void* ud   = lua_touserdata(L, -1)  →  EntityLuaProxy**
//   char* proxy = *(char**)ud            →  EntityLuaProxy*
//   char* ent   = *(char**)proxy         →  cEntity* (proxy+0x00)
// ---------------------------------------------------------------------------

#ifdef _WIN32

static constexpr int ENTITY_WORLD_POS_X = 0x1f0;
static constexpr int ENTITY_WORLD_POS_Y = 0x1f4;
static constexpr int ENTITY_WORLD_POS_Z = 0x1f8;

struct Vec3 {
    float x = 0, y = 0, z = 0;
};

struct EntitySnapshot {
    Vec3   pos;
    Vec3   vel;
    Vec3   extrapolated;
    double last_time = 0.0;
    float  half_rtt  = 0.0f;
    char*  entity    = nullptr;
    bool   valid     = false;
};

static int             g_max_slots = 0;
static EntitySnapshot* g_snapshots = nullptr;

static double now_seconds() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

static constexpr float MAX_EXTRAP_DIST = 1.5f;

static char* UnwrapEntity(void* ud) {
    if (!ud) return nullptr;
    char* proxy = *reinterpret_cast<char**>(ud);
    if (!proxy) return nullptr;
    return *reinterpret_cast<char**>(proxy);
}

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_entity_get_raw_ptr(lua_State* L) {
    auto& api = GetGameLuaContext().api;
    if (api._lua_type(L, 1) != LUA_TUSERDATA) {
        api._lua_pushnil(L);
        return 1;
    }
    void* ud = api._lua_touserdata(L, 1);
    char* ent = UnwrapEntity(ud);
    if (ent) {
        api._lua_pushlightuserdata(L, ent);
    } else {
        api._lua_pushnil(L);
    }
    return 1;
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_lag_comp_init(int max_slots) {
    delete[] g_snapshots;
    g_max_slots = max_slots > 0 ? max_slots : 0;
    g_snapshots = g_max_slots > 0 ? new EntitySnapshot[g_max_slots]{} : nullptr;
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_lag_comp_clear_slot(int slot) {
    if (g_snapshots && slot >= 0 && slot < g_max_slots) {
        std::memset(&g_snapshots[slot], 0, sizeof(EntitySnapshot));
    }
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_lag_comp_update_snapshot(
    void* entity_ptr, int slot, float half_rtt_s)
{
    auto ent = static_cast<char*>(entity_ptr);
    if (!ent || !g_snapshots || slot < 0 || slot >= g_max_slots) return;

    const float cx = *reinterpret_cast<float*>(ent + ENTITY_WORLD_POS_X);
    const float cy = *reinterpret_cast<float*>(ent + ENTITY_WORLD_POS_Y);
    const float cz = *reinterpret_cast<float*>(ent + ENTITY_WORLD_POS_Z);

    auto& snap = g_snapshots[slot];
    const double now = now_seconds();

    if (snap.last_time > 0.0) {
        const double dt = now - snap.last_time;
        if (dt > 0.001) {
            snap.vel.x = (cx - snap.pos.x) / static_cast<float>(dt);
            snap.vel.z = (cz - snap.pos.z) / static_cast<float>(dt);
        }
    }
    snap.pos = {cx, cy, cz};
    snap.last_time = now;
    snap.half_rtt  = half_rtt_s;
    snap.entity    = ent;

    float ex = cx + snap.vel.x * half_rtt_s;
    float ez = cz + snap.vel.z * half_rtt_s;

    const float dx = ex - cx;
    const float dz = ez - cz;
    const float dist2 = dx * dx + dz * dz;
    if (dist2 > MAX_EXTRAP_DIST * MAX_EXTRAP_DIST) {
        const float inv = MAX_EXTRAP_DIST / std::sqrtf(dist2);
        ex = cx + dx * inv;
        ez = cz + dz * inv;
    }

    snap.extrapolated = {ex, cy, ez};
    snap.valid = (half_rtt_s > 0.0f && (snap.vel.x != 0.0f || snap.vel.z != 0.0f));
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_lag_comp_apply_all() {
    if (!g_snapshots) return;
    for (int i = 0; i < g_max_slots; ++i) {
        auto& snap = g_snapshots[i];
        if (!snap.valid || !snap.entity) continue;
        *reinterpret_cast<float*>(snap.entity + ENTITY_WORLD_POS_X) = snap.extrapolated.x;
        *reinterpret_cast<float*>(snap.entity + ENTITY_WORLD_POS_Z) = snap.extrapolated.z;
    }
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_lag_comp_restore_all() {
    if (!g_snapshots) return;
    for (int i = 0; i < g_max_slots; ++i) {
        auto& snap = g_snapshots[i];
        if (!snap.valid || !snap.entity) continue;
        *reinterpret_cast<float*>(snap.entity + ENTITY_WORLD_POS_X) = snap.pos.x;
        *reinterpret_cast<float*>(snap.entity + ENTITY_WORLD_POS_Y) = snap.pos.y;
        *reinterpret_cast<float*>(snap.entity + ENTITY_WORLD_POS_Z) = snap.pos.z;
    }
}

#endif
