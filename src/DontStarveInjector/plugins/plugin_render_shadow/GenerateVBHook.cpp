#include "GenerateVBHook.hpp"
#include "SunModel.hpp"

#include "MemorySignature.hpp"
#include "config/InjectorHostConfig.hpp"
#include "gum_plugin_export.hpp"
#include "util/frida_gum_interceptor.hpp"

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstring>
#ifdef _WIN32

namespace ds::shadow {
namespace {

using GenerateVB_fn = uint32_t(__fastcall *)(void *self, void *list);
using GetVertDesc_fn = void *(__fastcall *)(void *cache, uint32_t handle);
using AllocVerts_fn = void *(__fastcall *)(size_t bytes);
using FreeVerts_fn = void(__fastcall *)(void *block);
using PopulateQuad_fn = void(__fastcall *)(void *self, void *dest, float *pos, float *size,
                                           float *dir);
using CreateVB_fn = uint32_t(__fastcall *)(void *renderer, uint32_t type, int vert_count,
                                           uint16_t fmt, void *verts, uint8_t unk);

GenerateVB_fn original_GenerateVB = nullptr;
GetVertDesc_fn get_vert_desc = nullptr;
AllocVerts_fn alloc_verts = nullptr;
FreeVerts_fn free_verts = nullptr;
PopulateQuad_fn populate_quad = nullptr;
CreateVB_fn create_vb = nullptr;

bool installed = false;
bool enabled = false;
double length_boost = 1.0;

function_relocation::MemorySignature GenerateVB_sig{
    "48 89 5C 24 18 48 89 6C 24 20 56 57 41 54 48 83 EC 50 48 8B 41 20 48 8B FA 48 8B F1 8B 90 D4 "
    "00 00 00",
    0};

function_relocation::MemorySignature PopulateQuad_sig{
    "4C 8B DC 48 81 EC A8 00 00 00 48 8B 84 24 D0 00 00 00", 0};

void *Rel32Target(const uint8_t *call) {
    if (call == nullptr || call[0] != 0xE8) {
        return nullptr;
    }
    int32_t rel = 0;
    std::memcpy(&rel, call + 1, sizeof(rel));
    return const_cast<uint8_t *>(call + 5 + rel);
}

bool ResolveHelpers() {
    auto *base = reinterpret_cast<const uint8_t *>(GenerateVB_sig.target_address);
    get_vert_desc = reinterpret_cast<GetVertDesc_fn>(Rel32Target(base + 0x32));
    alloc_verts = reinterpret_cast<AllocVerts_fn>(Rel32Target(base + 0xAB));
    populate_quad = reinterpret_cast<PopulateQuad_fn>(Rel32Target(base + 0x157));
    create_vb = reinterpret_cast<CreateVB_fn>(Rel32Target(base + 0x1A9));
    free_verts = reinterpret_cast<FreeVerts_fn>(Rel32Target(base + 0x1B9));
    if (get_vert_desc == nullptr || alloc_verts == nullptr || populate_quad == nullptr ||
        create_vb == nullptr || free_verts == nullptr) {
        return false;
    }
    if (reinterpret_cast<uintptr_t>(populate_quad) != PopulateQuad_sig.target_address) {
        spdlog::error("[render.shadow] PopulateQuad call target mismatch {:#x} vs {:#x}",
                      reinterpret_cast<uintptr_t>(populate_quad),
                      PopulateQuad_sig.target_address);
        return false;
    }
    return true;
}

bool HelpersReady() noexcept {
    return get_vert_desc != nullptr && alloc_verts != nullptr && populate_quad != nullptr &&
           create_vb != nullptr && free_verts != nullptr;
}

void LogStockOnce(const char *why) {
    static const char *last = nullptr;
    static uint32_t n = 0;
    ++n;
    if (why != last || n <= 4) {
        last = why;
        spdlog::info("[render.shadow] GenerateVB STOCK why={} n={}", why, n);
    }
}

void LogSun(const SunSample &sample, int nents, int drawn, const float dir[2], const XZ &off) {
    static uint32_t last_yaw = 0xFFFFFFFFu;
    static uint32_t n = 0;
    ++n;
    const auto bits = std::bit_cast<uint32_t>(sample.yaw_rad);
    if (bits != last_yaw || n <= 5) {
        last_yaw = bits;
        spdlog::info("[render.shadow] GenerateVB SUN n={} ents={} drawn={} yaw={:.1f}deg "
                     "scale={:.2f} dir=({:.3f},{:.3f}) off=({:.2f},{:.2f})",
                     n, nents, drawn, sample.yaw_rad * 57.2957795f, sample.length_scale, dir[0],
                     dir[1], off.x, off.z);
    }
}

uint32_t GenerateVBSun(void *self, void *list, const SunSample &sample) {
    auto *mgr = static_cast<uint8_t *>(self);
    auto *shadow_renderer = *reinterpret_cast<uint8_t **>(mgr + 0x20);
    auto *renderer = *reinterpret_cast<uint8_t **>(mgr + 0x28);
    if (shadow_renderer == nullptr || renderer == nullptr) {
        LogStockOnce("null-renderer");
        return original_GenerateVB(self, list);
    }
    void *cache = *reinterpret_cast<void **>(renderer + 0x1A0);
    const uint32_t desc_handle = *reinterpret_cast<uint32_t *>(shadow_renderer + 0xD4);
    void *vert_desc = get_vert_desc(cache, desc_handle);
    if (vert_desc == nullptr) {
        LogStockOnce("null-vertdesc");
        return original_GenerateVB(self, list);
    }

    auto *lbase = static_cast<uint8_t *>(list);
    auto *begin = *reinterpret_cast<uint8_t **>(lbase + 0x08);
    auto *end = *reinterpret_cast<uint8_t **>(lbase + 0x10);
    if (begin == nullptr || end == nullptr || end < begin) {
        return 0xFFFFFFFFu;
    }
    const auto bytes_list = static_cast<size_t>(end - begin);
    if (bytes_list > 0x100000u || (bytes_list % sizeof(void *)) != 0) {
        LogStockOnce("bad-list");
        return original_GenerateVB(self, list);
    }
    const auto n = bytes_list / sizeof(void *);
    const auto max_verts = static_cast<int>(n * 6);
    const size_t alloc_bytes = static_cast<size_t>(max_verts) * 0x14u + 4u;
    auto *block = static_cast<int32_t *>(alloc_verts(alloc_bytes));
    if (block == nullptr) {
        return 0xFFFFFFFFu;
    }
    *block = max_verts;
    auto *verts = reinterpret_cast<uint8_t *>(block + 1);
    for (int i = 0; i < max_verts; ++i) {
        auto *v = verts + static_cast<size_t>(i) * 0x14u;
        *reinterpret_cast<uint32_t *>(v + 0x0C) = 0;
        *reinterpret_cast<uint32_t *>(v + 0x10) = 0;
    }

    float dir[2];
    FillSunDir(dir, sample.yaw_rad);
    XZ first_off{0.f, 0.f};
    bool have_off = false;

    auto *dest = verts;
    for (auto *it = begin; it < end; it += sizeof(void *)) {
        auto *comp = *reinterpret_cast<uint8_t **>(it);
        if (comp == nullptr || comp[0x28] == 0) {
            continue;
        }
        auto *entity = *reinterpret_cast<uint8_t **>(comp + 0x18);
        if (entity == nullptr || entity[0x1B4] != 0) {
            continue;
        }
        const float sx = *reinterpret_cast<float *>(comp + 0x20);
        const float sy = *reinterpret_cast<float *>(comp + 0x24);
        if (!std::isfinite(sx) || !std::isfinite(sy)) {
            continue;
        }
        float size[2] = {sx * sample.length_scale, sy};
        const XZ off = CastCenterOffset(sx, sample.length_scale, sample.yaw_rad);
        if (!have_off) {
            first_off = off;
            have_off = true;
        }
        float pos[3] = {
            *reinterpret_cast<float *>(entity + 0x1F0) + off.x,
            *reinterpret_cast<float *>(entity + 0x1F4),
            *reinterpret_cast<float *>(entity + 0x1F8) + off.z,
        };
        populate_quad(self, dest, pos, size, dir);
        dest += 0x78;
    }

    const int drawn = static_cast<int>((dest - verts) / 0x14 / 6);
    LogSun(sample, static_cast<int>(n), drawn, dir, first_off);

    uint32_t vb = 0xFFFFFFFFu;
    if (dest != verts) {
        const int count = static_cast<int>((dest - verts) / 0x14);
        const uint16_t fmt = *reinterpret_cast<uint16_t *>(static_cast<uint8_t *>(vert_desc) + 8);
        vb = create_vb(renderer, 10, count, fmt, verts, 0);
    }
    free_verts(block);
    return vb;
}

uint32_t __fastcall hooked_GenerateVB(void *self, void *list) {
    if (original_GenerateVB == nullptr) {
        return 0xFFFFFFFFu;
    }
    if (self == nullptr || list == nullptr) {
        LogStockOnce("null-args");
        return original_GenerateVB != nullptr ? original_GenerateVB(self, list) : 0xFFFFFFFFu;
    }
    if (!enabled) {
        LogStockOnce("disabled");
        return original_GenerateVB(self, list);
    }
    if (!HelpersReady()) {
        LogStockOnce("no-helpers");
        return original_GenerateVB(self, list);
    }
    const SunSample sample = LoadPublished();
    if (!sample.visible) {
        LogStockOnce("invisible");
        return original_GenerateVB(self, list);
    }
    return GenerateVBSun(self, list, sample);
}

} // namespace

bool InstallGenerateVBHook() {
    if (installed) {
        return true;
    }
    auto *ictx = InjectorCtx::instance();
    if (ictx == nullptr || !ictx->DontStarveInjectorIsClient) {
        spdlog::info("[render.shadow] skip hook: not client");
        return false;
    }
    const auto *mainPath = gum_module_get_path(gum_process_get_main_module());
    if (mainPath == nullptr || !GenerateVB_sig.scan(mainPath)) {
        spdlog::error("[render.shadow] GenerateVB signature miss");
        return false;
    }
    if (std::strstr(mainPath, "dedicated") != nullptr ||
        std::strstr(mainPath, "nullrenderer") != nullptr) {
        spdlog::info("[render.shadow] skip hook: dedicated/nullrenderer module");
        return false;
    }
    if (!PopulateQuad_sig.scan(mainPath)) {
        spdlog::error("[render.shadow] PopulateQuad signature miss");
        return false;
    }
    if (!ResolveHelpers()) {
        spdlog::error("[render.shadow] GenerateVB helper CALL resolve failed");
        return false;
    }

    auto *interceptor = InjectorCtx::instance()->GetGumInterceptor();
    if (interceptor == nullptr) {
        spdlog::error("[render.shadow] GumInterceptor unavailable");
        return false;
    }
    const auto r = ds::gum::replace(interceptor,
                                    reinterpret_cast<void *>(GenerateVB_sig.target_address),
                                    reinterpret_cast<void *>(&hooked_GenerateVB),
                                    reinterpret_cast<void **>(&original_GenerateVB));
    if (r != GUM_REPLACE_OK) {
        spdlog::error("[render.shadow] gum replace GenerateVB failed: {}", static_cast<int>(r));
        original_GenerateVB = nullptr;
        return false;
    }
    installed = true;
    spdlog::info("[render.shadow] GenerateVB reimplemented @ {:#x} PopulateQuad={:#x} "
                 "get_vert_desc={:#x} alloc={:#x} create_vb={:#x} free={:#x}",
                 GenerateVB_sig.target_address, PopulateQuad_sig.target_address,
                 reinterpret_cast<uintptr_t>(get_vert_desc),
                 reinterpret_cast<uintptr_t>(alloc_verts), reinterpret_cast<uintptr_t>(create_vb),
                 reinterpret_cast<uintptr_t>(free_verts));
    return true;
}

bool IsHookInstalled() noexcept { return installed; }

void SetSunDriveEnabled(bool on) {
    enabled = on;
    if (on) {
        (void)InstallGenerateVBHook();
    }
}

void SetLengthBoost(double boost) noexcept {
    length_boost = std::clamp(boost, 0.5, 2.0);
}

double GetLengthBoost() noexcept { return length_boost; }

} // namespace ds::shadow

#else

namespace ds::shadow {

bool InstallGenerateVBHook() { return false; }
bool IsHookInstalled() noexcept { return false; }
void SetSunDriveEnabled(bool) {}
void SetLengthBoost(double) noexcept {}
double GetLengthBoost() noexcept { return 1.0; }

} // namespace ds::shadow

#endif
