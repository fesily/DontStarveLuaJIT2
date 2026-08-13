#include "GenerateVBHook.hpp"
#include "SunModel.hpp"

#include "MemorySignature.hpp"
#include "config/InjectorHostConfig.hpp"
#include "gum_plugin_export.hpp"
#include "util/frida_gum_interceptor.hpp"

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

#ifdef _WIN32

namespace ds::shadow {
namespace {

using GenerateVB_fn = uint32_t(__fastcall *)(void *self, void *list);
using PopulateQuad_fn = void(__fastcall *)(void *self, void *dest, const float *pos,
                                           const float *size, const float *dir);
using CreateVB_fn = uint32_t(__fastcall *)(void *renderer, int type, int count, uint16_t stride,
                                           void *verts, bool flag);
using LookupVD_fn = void *(__fastcall *)(void *mgr, uint32_t handle);

GenerateVB_fn original_GenerateVB = nullptr;
PopulateQuad_fn original_PopulateQuad = nullptr;
CreateVB_fn original_CreateVB = nullptr;
LookupVD_fn original_LookupVD = nullptr;

bool installed = false;
bool enabled = false;
double length_boost = 1.0;

function_relocation::MemorySignature GenerateVB_sig{
    "48 89 5C 24 18 48 89 6C 24 20 56 57 41 54 48 83 EC 50 48 8B 41 20 48 8B FA 48 8B F1 8B 90 D4 "
    "00 00 00",
    0};
function_relocation::MemorySignature PopulateQuad_sig{
    "4C 8B DC 48 81 EC A8 00 00 00 48 8B 84 24 D0 00 00 00", 0};

constexpr intptr_t kCallLookupVD = 0x32;     // CALL FUN_1403dc420
constexpr intptr_t kCallPopulateQuad = 0x157; // CALL PopulateQuad
constexpr intptr_t kCallCreateVB = 0x1A9;    // CALL CreateVB

void *rel32_target(const uint8_t *call_site) {
    if (call_site == nullptr || call_site[0] != 0xE8) {
        return nullptr;
    }
    int32_t rel = 0;
    std::memcpy(&rel, call_site + 1, sizeof(rel));
    return const_cast<uint8_t *>(call_site + 5 + rel);
}

struct ComponentListView {
    void *pad0;
    void **begin;
    void **end;
};

uint32_t __fastcall hooked_GenerateVB(void *self, void *list) {
    if (!enabled || original_GenerateVB == nullptr) {
        return original_GenerateVB ? original_GenerateVB(self, list) : 0xFFFFFFFFu;
    }
    const SunSample sample = LoadPublished();
    if (!sample.visible) {
        return original_GenerateVB(self, list);
    }
    if (original_PopulateQuad == nullptr || original_CreateVB == nullptr || self == nullptr ||
        list == nullptr) {
        return original_GenerateVB(self, list);
    }

    auto *view = static_cast<ComponentListView *>(list);
    if (view->begin == nullptr || view->end == nullptr || view->end < view->begin) {
        return original_GenerateVB(self, list);
    }
    const auto count = static_cast<size_t>(view->end - view->begin);
    if (count == 0 || count > 100000) {
        return original_GenerateVB(self, list);
    }

    const float dir[2] = {std::cos(sample.yaw_rad), std::sin(sample.yaw_rad)};
    constexpr size_t kVertStride = 0x14;
    constexpr size_t kVertsPer = 6;
    std::vector<uint8_t> buf(count * kVertsPer * kVertStride, 0);
    uint8_t *dest = buf.data();
    uint8_t *const dest0 = dest;

    for (void **it = view->begin; it != view->end; ++it) {
        auto *comp = static_cast<uint8_t *>(*it);
        if (comp == nullptr) {
            continue;
        }
        if (comp[0x28] == 0) {
            continue;
        }
        auto *entity = *reinterpret_cast<uint8_t **>(comp + 0x18);
        if (entity == nullptr || entity[0x1B4] != 0) {
            continue;
        }
        float size[2];
        std::memcpy(&size[0], comp + 0x20, sizeof(float));
        std::memcpy(&size[1], comp + 0x24, sizeof(float));
        size[0] *= sample.length_scale; // flSizeX along dir (O3)
        float pos[3];
        std::memcpy(pos, entity + 0x1F0, sizeof(pos));
        original_PopulateQuad(self, dest, pos, size, dir);
        dest += kVertsPer * kVertStride;
    }

    if (dest == dest0) {
        return 0xFFFFFFFFu;
    }

    auto *renderer = *reinterpret_cast<void **>(static_cast<uint8_t *>(self) + 0x28);
    auto *shadow_r = *reinterpret_cast<uint8_t **>(static_cast<uint8_t *>(self) + 0x20);
    uint16_t stride = static_cast<uint16_t>(kVertStride);
    if (original_LookupVD != nullptr && renderer != nullptr && shadow_r != nullptr) {
        auto *mgr = *reinterpret_cast<void **>(static_cast<uint8_t *>(renderer) + 0x1A0);
        uint32_t handle = 0;
        std::memcpy(&handle, shadow_r + 0xD4, sizeof(handle));
        if (void *vd = original_LookupVD(mgr, handle)) {
            std::memcpy(&stride, static_cast<uint8_t *>(vd) + 8, sizeof(stride));
        }
    }

    const auto nbytes = static_cast<size_t>(dest - dest0);
    const int vert_count = static_cast<int>(nbytes / kVertStride);
    return original_CreateVB(renderer, 10, vert_count, stride, dest0, false);
}

} // namespace

bool InstallGenerateVBHook() {
    if (installed) {
        return true;
    }
    const auto *mainPath = gum_module_get_path(gum_process_get_main_module());
    if (mainPath == nullptr || !GenerateVB_sig.scan(mainPath)) {
        spdlog::error("[render.shadow] GenerateVB signature miss");
        return false;
    }
    const auto *base = reinterpret_cast<const uint8_t *>(GenerateVB_sig.target_address);
    original_PopulateQuad = reinterpret_cast<PopulateQuad_fn>(rel32_target(base + kCallPopulateQuad));
    original_CreateVB = reinterpret_cast<CreateVB_fn>(rel32_target(base + kCallCreateVB));
    original_LookupVD = reinterpret_cast<LookupVD_fn>(rel32_target(base + kCallLookupVD));
    if (original_PopulateQuad == nullptr || original_CreateVB == nullptr) {
        spdlog::error("[render.shadow] GenerateVB call-site parse failed");
        return false;
    }
    if (PopulateQuad_sig.scan(mainPath) &&
        PopulateQuad_sig.target_address != reinterpret_cast<uintptr_t>(original_PopulateQuad)) {
        spdlog::warn("[render.shadow] PopulateQuad pattern/call-site mismatch; using call-site");
    }

    auto *interceptor = InjectorCtx::instance()->GetGumInterceptor();
    if (interceptor == nullptr) {
        spdlog::error("[render.shadow] GumInterceptor unavailable");
        return false;
    }
    const auto r = ds::gum::replace(
        interceptor, reinterpret_cast<void *>(GenerateVB_sig.target_address),
        reinterpret_cast<void *>(&hooked_GenerateVB),
        reinterpret_cast<void **>(&original_GenerateVB));
    if (r != GUM_REPLACE_OK) {
        spdlog::error("[render.shadow] gum replace GenerateVB failed: {}", static_cast<int>(r));
        original_GenerateVB = nullptr;
        return false;
    }
    installed = true;
    spdlog::info("[render.shadow] GenerateVB hooked @ {:#x}", GenerateVB_sig.target_address);
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
