#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace ds::shadow {

struct BatchVert {
  float x, y, z, u, v;
  uint32_t rgba;
};

// Local anim vert (lx,ly,lz) → ground: rotate yaw in XZ, scale along yaw, y=0, +origin.
void FlattenPoint(float lx, float ly, float lz, float yaw_rad, float stretch,
                  float origin_x, float origin_z, float *ox, float *oy,
                  float *oz) noexcept;




// 4x4 row-major, p' = M * p. World (wx,wy,wz) through
// FlattenPoint(wx-ent_x, wy, wz-ent_z, yaw, stretch, origin).
void FlattenMatrix(float yaw_rad, float stretch, float origin_x, float origin_z,
                   float ent_x, float ent_z, float m[16]) noexcept;

// Row-major. W = T(origin) * ShearY(yaw, stretch) * elemFinal.
// elemFinal is camera-facing (pass * aff). Then Y flattens along the sun.
void ComposeShadowW(const float elem_final[16], float yaw_rad, float stretch,
                    float origin_x, float origin_z, float w[16]) noexcept;







// RGB=0, A unchanged (alpha in high byte)
uint32_t BlackKeepAlpha(uint32_t rgba) noexcept;

// BlackKeepAlpha, then A *= sample.alpha (clamped 0..1).
uint32_t ApplyShadowAlpha(uint32_t rgba, float alpha) noexcept;

// Coverage mask: any source A > 0 → black * sample.alpha. Ignores texel gray.
uint32_t ShadowCoverageAlpha(uint32_t rgba, float alpha) noexcept;

// Overlapping layers union to one cover, then * sample.alpha once.

// TDC+0x160 map node (FUN_1400eea40): Left/Parent/Right, key hash @+0x18,
// value @+0x28. Walk stops at header sentinel, not a guessed _Isnil byte.
inline uint32_t MsvcMapKey(const uint8_t *n) noexcept {
  uint32_t k = 0;
  if (n != nullptr) {
    std::memcpy(&k, n + 0x18, sizeof(k));
  }
  return k;
}
inline uint8_t *MsvcMapValue(uint8_t *n) noexcept {
  return n != nullptr ? n + 0x28 : nullptr;
}
uint32_t UnionThenTint(const uint32_t *layers, size_t n, float alpha) noexcept;

// Win64 sSymbolOverrides (obj = map node+0x28).
// flags@0 bit0 hide, bit4 has-build; sBuild* @+0x58; dest hash @+0x70.
struct SymbolOverride {
  bool skip = false;
  uint32_t symbol = 0;
  uint8_t *build = nullptr;
};

inline SymbolOverride ReadSymbolOverride(const uint8_t *obj) noexcept {
  SymbolOverride o{};
  if (obj == nullptr) {
    return o;
  }
  const uint8_t flags = obj[0];
  if ((flags & 1u) != 0) {
    o.skip = true;
    return o;
  }
  if ((flags & 0x10u) != 0) {
    std::memcpy(&o.build, obj + 0x58, sizeof(o.build));
  }
  std::memcpy(&o.symbol, obj + 0x70, sizeof(o.symbol));
  return o;
}



// Stash sample.alpha in unused affine W[2][3] (row-major index 14).
// sil.ksh VS reads MatrixW[2][3]; POS2D z is 0 so clip w stays W[3][3].
void StashShadowAlpha(float w[16], float alpha) noexcept;

struct BildVert {
  float x, y, z, u, v;
  uint32_t rgba;
};

// BILD v6 file verts (24B). FUN_14016ec80 drops z and packs
// {x, y, bitcast(rgba)*2+u, v} into the GPU 16B VB.
bool ParseBildVerts(const uint8_t *data, size_t nbytes, BildVert *out, size_t *inout_count) noexcept;

inline void BildUv(const BildVert &v, float *u, float *vv) noexcept {
  *u = v.u;
  *vv = v.v;
}


// SetEffect only writes a handle. BindProgram is healthy only when the
// HWEffect src_data pointer changes to a different non-null blob.
inline bool BindProgramUpdatesSrcData(const void *src_before, const void *src_after) noexcept {
  return src_after != nullptr && src_after != src_before;
}

// HWEffect_Bind copies renderer+0x2C → +0x28 after glUseProgram.
inline bool BindCopiedDesiredHandle(uint32_t bound_after, uint32_t desired) noexcept {
  return desired != 0 && bound_after == desired;
}



// 6 XZ pairs: tip, wingL, notch, tip, notch, wingR. Points along +yaw.
// Pipeline probe only — not anim geometry.
void DebugChevronXZ(float origin_x, float origin_z, float yaw_rad,
                    float xz[12]) noexcept;

// 6 XZ pairs: two CCW tris. Along +yaw, perp is left of yaw.
// half_along / half_perp in world units. Pipeline probe, not anim.
void DebugRectXZ(float origin_x, float origin_z, float yaw_rad,
                 float half_along, float half_perp, float xz[12]) noexcept;



} // namespace ds::shadow
