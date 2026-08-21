#include "GenerateVBHook.hpp"
#include "SunModel.hpp"



#include "MemorySignature.hpp"
#include "config/InjectorHostConfig.hpp"
#include "gum_plugin_export.hpp"
#include "util/frida_gum_interceptor.hpp"

#include <frida-gum.h>
#include <spdlog/spdlog.h>
#include "ShadowLog.hpp"


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
using GetCam_fn = void *(__fastcall *)(void *sim);

GenerateVB_fn original_GenerateVB = nullptr;
GetVertDesc_fn get_vert_desc = nullptr;
AllocVerts_fn alloc_verts = nullptr;
FreeVerts_fn free_verts = nullptr;
PopulateQuad_fn populate_quad = nullptr;
CreateVB_fn create_vb = nullptr;
GetCam_fn get_cam = nullptr;


bool installed = false;
bool enabled = false;
bool ellipse_enabled = true;


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
    get_cam = reinterpret_cast<GetCam_fn>(Rel32Target(base + 0x57));
    return true;
}

bool HelpersReady() noexcept { return original_GenerateVB != nullptr; }


void LogStockOnce(const char *why) {
    static const char *last = nullptr;
    static uint32_t n = 0;
    ++n;
    if (why != last || n <= 4) {
        last = why;
        SHADOW_TRACE("[render.shadow] GenerateVB STOCK why={} n={}", why, n);
    }
}

void *SimFromList(void *list) {
    auto *lbase = static_cast<uint8_t *>(list);
    auto *begin = *reinterpret_cast<uint8_t **>(lbase + 0x08);
    auto *end = *reinterpret_cast<uint8_t **>(lbase + 0x10);
    if (begin == nullptr || end == nullptr || end <= begin) {
        return nullptr;
    }
    auto *comp = *reinterpret_cast<uint8_t **>(begin);
    if (comp == nullptr) {
        return nullptr;
    }
    auto *entity = *reinterpret_cast<uint8_t **>(comp + 0x18);
    if (entity == nullptr) {
        return nullptr;
    }
    return *reinterpret_cast<void **>(entity + 0xE0);
}

uint32_t GenerateVBHeadingWrap(void *self, void *list, const SunSample &sample) {
    struct SavedSz {
        float *slot;
        float prev;
    };
    SavedSz sizes[512];
    int nsz = 0;
    auto *lbase = static_cast<uint8_t *>(list);
    auto *begin = *reinterpret_cast<uint8_t **>(lbase + 0x08);
    auto *end = *reinterpret_cast<uint8_t **>(lbase + 0x10);
    if (begin && end && end >= begin) {
        for (auto *it = begin; it < end && nsz < 512; it += sizeof(void *)) {
            auto *comp = *reinterpret_cast<uint8_t **>(it);
            if (comp == nullptr || comp[0x28] == 0) {
                continue;
            }
            auto *slot = reinterpret_cast<float *>(comp + 0x20);
            sizes[nsz++] = {slot, slot[0]};
            slot[0] *= sample.length_scale;
        }
    }

    float *heading = nullptr;
    float saved_h = 0.f;
    if (get_cam != nullptr) {
        if (void *sim = SimFromList(list)) {
            if (void *cam = get_cam(sim)) {
                heading = reinterpret_cast<float *>(static_cast<uint8_t *>(cam) + 0x30);
                saved_h = *heading;
                *heading = HeadingDegreesFromSunYaw(sample.yaw_rad);
            }
        }
    }

    const uint32_t h = original_GenerateVB(self, list);

    if (heading != nullptr) {
        *heading = saved_h;
    }
    for (int i = 0; i < nsz; ++i) {
        sizes[i].slot[0] = sizes[i].prev;
    }
    static uint32_t n = 0;
    ++n;
    if (n <= 5 || (n % 60u) == 0) {
        SHADOW_TRACE("[render.shadow] GenerateVB WRAP n={} yaw={:.1f}deg scale={:.2f} heading={}",
                     n, sample.yaw_rad * 57.2957795f, sample.length_scale,
                     heading != nullptr ? 1 : 0);
    }
    return h;
}


uint32_t __fastcall hooked_GenerateVB(void *self, void *list) {
    if (original_GenerateVB == nullptr) {
        return 0xFFFFFFFFu;
    }
    if (!ellipse_enabled) {
        return 0xFFFFFFFFu;
    }
    if (self == nullptr || list == nullptr) {
        LogStockOnce("null-args");
        return original_GenerateVB(self, list);
    }
    if (!enabled) {
        LogStockOnce("disabled");
        return original_GenerateVB(self, list);
    }
    const SunSample sample = LoadPublished();
    if (!sample.visible) {
        LogStockOnce("invisible");
        return original_GenerateVB(self, list);
    }
    return GenerateVBHeadingWrap(self, list, sample);
}



} // namespace

bool InstallGenerateVBHook() {
    if (installed) {
        return true;
    }
    auto *ictx = InjectorCtx::instance();
    if (ictx == nullptr || !ictx->DontStarveInjectorIsClient) {
        SHADOW_TRACE("[render.shadow] skip hook: not client");
        return false;
    }
    const auto *mainPath = gum_module_get_path(gum_process_get_main_module());
    if (mainPath == nullptr || !GenerateVB_sig.scan(mainPath)) {
        spdlog::error("[render.shadow] GenerateVB signature miss");
        return false;
    }
    if (std::strstr(mainPath, "dedicated") != nullptr ||
        std::strstr(mainPath, "nullrenderer") != nullptr) {
        SHADOW_TRACE("[render.shadow] skip hook: dedicated/nullrenderer module");
        return false;
    }
    (void)PopulateQuad_sig.scan(mainPath);
    (void)ResolveHelpers();


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
    SHADOW_TRACE("[render.shadow] GenerateVB thin wrap @ {:#x} get_cam={:#x}",
                 GenerateVB_sig.target_address, reinterpret_cast<uintptr_t>(get_cam));

    return true;
}

bool IsHookInstalled() noexcept { return installed; }
uintptr_t GetGenerateVBAddress() noexcept {
    return installed ? GenerateVB_sig.target_address : 0;
}

void SetSunDriveEnabled(bool on) {
    enabled = on;
    if (on) {
        (void)InstallGenerateVBHook();
    }
}

void SetEllipseEnabled(bool on) noexcept {
    ellipse_enabled = on;
    if (!on) {
        (void)InstallGenerateVBHook();
    }
}

bool IsEllipseEnabled() noexcept { return ellipse_enabled; }





} // namespace ds::shadow

#else

namespace ds::shadow {

bool InstallGenerateVBHook() { return false; }
bool IsHookInstalled() noexcept { return false; }
uintptr_t GetGenerateVBAddress() noexcept { return 0; }
void SetSunDriveEnabled(bool) {}
void SetEllipseEnabled(bool) noexcept {}
bool IsEllipseEnabled() noexcept { return true; }




} // namespace ds::shadow

#endif
