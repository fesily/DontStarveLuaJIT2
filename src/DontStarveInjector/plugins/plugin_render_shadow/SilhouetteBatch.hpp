#pragma once

#include "SunModel.hpp"

#include <cstdint>

namespace ds::shadow {

void SetSilhouetteEnabled(bool on) noexcept;
bool IsSilhouetteEnabled() noexcept;
bool IsSilhouetteHealthy() noexcept;
void SetSilhouetteHealthy(bool ok) noexcept;
bool MarkSilhouetted(void *entity);
bool IsSilhouetted(const void *entity) noexcept;
void ClearSilhouetted() noexcept;

// Rel32 from Anim DCR / Shadow DCR / GenerateVB. MustBind: set_tex, set_vd
// (+0x2C effect), set_vb, create_vb, get_ds_list, get_vert_desc, shadow Draw.
bool BindSilhouetteHelpers(uintptr_t anim_dcr, uintptr_t shadow_dcr, uintptr_t generate_vb);
void BindGetAnimFrame(uintptr_t fn) noexcept;
void BindHwEffectBind(uintptr_t fn) noexcept;
void BindAnimDraw(uintptr_t fn) noexcept;

bool BindProgramPinned() noexcept;

void NoteGameAnimManager(void *game) noexcept;

bool LoadSilShader() noexcept;
bool LoadSilFromRenderer(void *game_renderer) noexcept;

uint32_t SilEffectHandle() noexcept;
uint32_t SilVertDescHandle() noexcept;

// Win64 Draw: +0x1C = vert-desc, +0x2C = effect (RE_NOTES S0).
inline constexpr size_t kRendererEffectHandleOff = 0x2C;
inline constexpr size_t kRendererVertDescHandleOff = 0x1C;

inline void WriteRendererEffectHandle(void *renderer, uint32_t handle) noexcept {
    *reinterpret_cast<uint32_t *>(static_cast<uint8_t *>(renderer) + kRendererEffectHandleOff) =
        handle;
}

inline void WriteRendererVertDescHandle(void *renderer, uint32_t handle) noexcept {
    *reinterpret_cast<uint32_t *>(static_cast<uint8_t *>(renderer) + kRendererVertDescHandleOff) =
        handle;
}

struct SilVert {
    float x, z, u, v;
};

bool ReadableUserPtr(const void *p, size_t bytes = 8) noexcept;

// P11: 24B UV source at sBuild+0x90. XY-only +0x88 is not enough.
inline bool BuildHasUvSource(const uint8_t *sbuild) noexcept {
    if (!ReadableUserPtr(sbuild, 0x94)) {
        return false;
    }
    auto *sec = *reinterpret_cast<const uint8_t *const *>(sbuild + 0x90);
    return sec != nullptr && ReadableUserPtr(sec, 24);
}

void *EntityFromTdcViaDsList(void *tdc) noexcept;
bool PackFromTdc(void *tdc, void *entity, const SunSample &sample);

void FlushSilhouettes(void *game_renderer);
void BeginSilhouetteFrame() noexcept;
void PackFailCounts(uint32_t *no_fn, uint32_t *no_uv, uint32_t *no_frame, uint32_t *no_elems,
                    uint32_t *no_added) noexcept;


bool SilhouetteBudgetHit() noexcept;
size_t SilhouettedCount() noexcept;
size_t BatchVertCount() noexcept;
size_t BatchRunCount() noexcept;

} // namespace ds::shadow
