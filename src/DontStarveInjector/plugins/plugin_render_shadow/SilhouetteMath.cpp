#include "SilhouetteMath.hpp"

#include <cmath>
#include <cstring>


namespace ds::shadow {

void FlattenPoint(float lx, float ly, float lz, float yaw_rad, float stretch,
                  float origin_x, float origin_z, float *ox, float *oy,
                  float *oz) noexcept {
    (void)ly;
    const float c = std::cos(yaw_rad), s = std::sin(yaw_rad);
    const float along = lx * stretch;
    const float perp = lz;
    if (ox) {
        *ox = origin_x + along * c - perp * s;
    }
    if (oy) {
        *oy = 0.f;
    }
    if (oz) {
        *oz = origin_z + along * s + perp * c;
    }
}





void FlattenMatrix(float yaw_rad, float stretch, float origin_x, float origin_z,
                   float ent_x, float ent_z, float m[16]) noexcept {
    if (m == nullptr) {
        return;
    }
    const float c = std::cos(yaw_rad), s = std::sin(yaw_rad);
    // T_origin * FlattenXZ(yaw, stretch) * T_{-entity.xz}; y row is 0.
    m[0] = stretch * c;
    m[1] = 0.f;
    m[2] = -s;
    m[3] = origin_x - stretch * c * ent_x + s * ent_z;
    m[4] = 0.f;
    m[5] = 0.f;
    m[6] = 0.f;
    m[7] = 0.f;
    m[8] = stretch * s;
    m[9] = 0.f;
    m[10] = c;
    m[11] = origin_z - stretch * s * ent_x - c * ent_z;
    m[12] = 0.f;
    m[13] = 0.f;
    m[14] = 0.f;
    m[15] = 1.f;
}

void ComposeShadowW(const float elem_final[16], float yaw_rad, float stretch,
                    float origin_x, float origin_z, float w[16]) noexcept {
  if (elem_final == nullptr || w == nullptr) {
    return;
  }
  if (!(stretch >= 0.f) || !std::isfinite(stretch)) {
    stretch = 0.f;
  }
  const float c = std::cos(yaw_rad);
  const float s = std::sin(yaw_rad);
  float sh[16]{};
  sh[0] = 1.f;
  sh[1] = stretch * c;
  sh[9] = stretch * s;
  sh[10] = 1.f;
  sh[15] = 1.f;
  for (int row = 0; row < 4; ++row) {
    for (int col = 0; col < 4; ++col) {
      w[row * 4 + col] = sh[row * 4 + 0] * elem_final[0 * 4 + col] +
                         sh[row * 4 + 1] * elem_final[1 * 4 + col] +
                         sh[row * 4 + 2] * elem_final[2 * 4 + col] +
                         sh[row * 4 + 3] * elem_final[3 * 4 + col];
    }
  }
  w[3] += origin_x;
  w[11] += origin_z;
}








uint32_t BlackKeepAlpha(uint32_t rgba) noexcept { return rgba & 0xFF000000u; }

uint32_t ApplyShadowAlpha(uint32_t rgba, float alpha) noexcept {
  if (!(alpha > 0.f)) {
    return 0u;
  }
  if (alpha > 1.f) {
    alpha = 1.f;
  }
  const uint32_t a = (BlackKeepAlpha(rgba) >> 24) & 0xFFu;
  uint32_t na = static_cast<uint32_t>(static_cast<float>(a) * alpha + 0.5f);
  if (na > 255u) {
    na = 255u;
  }
  return na << 24;
}

uint32_t ShadowCoverageAlpha(uint32_t rgba, float alpha) noexcept {
  if ((BlackKeepAlpha(rgba) >> 24) == 0u) {
    return 0u;
  }
  if (!(alpha > 0.f)) {
    return 0u;
  }
  if (alpha > 1.f) {
    alpha = 1.f;
  }
  uint32_t na = static_cast<uint32_t>(alpha * 255.f + 0.5f);
  if (na > 255u) {
    na = 255u;
  }
  return na << 24;
}

uint32_t UnionThenTint(const uint32_t *layers, size_t n, float alpha) noexcept {
  if (layers == nullptr || n == 0) {
    return 0u;
  }
  for (size_t i = 0; i < n; ++i) {
    if ((BlackKeepAlpha(layers[i]) >> 24) != 0u) {
      return ShadowCoverageAlpha(0xFF000000u, alpha);
    }
  }
  return 0u;
}



void StashShadowAlpha(float w[16], float alpha) noexcept {
  if (w == nullptr) {
    return;
  }
  if (!(alpha > 0.f)) {
    w[14] = 0.f;
    return;
  }
  w[14] = alpha > 1.f ? 1.f : alpha;
}

void DebugChevronXZ(float origin_x, float origin_z, float yaw_rad,
                    float xz[12]) noexcept {
  if (xz == nullptr) {
    return;
  }
  const float c = std::cos(yaw_rad);
  const float s = std::sin(yaw_rad);
  const auto put = [&](int i, float along, float perp) {
    xz[static_cast<unsigned>(i) * 2u] = origin_x + along * c - perp * s;
    xz[static_cast<unsigned>(i) * 2u + 1u] = origin_z + along * s + perp * c;
  };
  put(0, 8.f, 0.f);
  put(1, -3.f, -3.5f);
  put(2, 0.f, 0.f);
  put(3, 8.f, 0.f);
  put(4, 0.f, 0.f);
  put(5, -3.f, 3.5f);
}

void DebugRectXZ(float origin_x, float origin_z, float yaw_rad,
                 float half_along, float half_perp, float xz[12]) noexcept {
  if (xz == nullptr) {
    return;
  }
  const float c = std::cos(yaw_rad);
  const float s = std::sin(yaw_rad);
  const auto put = [&](int i, float along, float perp) {
    xz[static_cast<unsigned>(i) * 2u] = origin_x + along * c - perp * s;
    xz[static_cast<unsigned>(i) * 2u + 1u] = origin_z + along * s + perp * c;
  };
  put(0, -half_along, -half_perp);
  put(1, half_along, -half_perp);
  put(2, half_along, half_perp);
  put(3, -half_along, -half_perp);
  put(4, half_along, half_perp);
  put(5, -half_along, half_perp);
}


bool ParseBildVerts(const uint8_t *data, size_t nbytes, BildVert *out,
                    size_t *inout_count) noexcept {
  if (data == nullptr || inout_count == nullptr || nbytes < 24) {
    return false;
  }
  if (std::memcmp(data, "BILD", 4) != 0) {
    return false;
  }
  auto rd_i = [&](size_t off, int32_t *v) -> bool {
    if (off + 4 > nbytes) {
      return false;
    }
    std::memcpy(v, data + off, 4);
    return true;
  };
  size_t off = 4;
  int32_t ver = 0, nsym = 0, nfr = 0;
  if (!rd_i(off, &ver) || !rd_i(off + 4, &nsym) || !rd_i(off + 8, &nfr)) {
    return false;
  }
  off += 12;
  if (ver < 5 || ver > 7 || nsym < 0 || nsym > 0x10000) {
    return false;
  }
  int32_t nlen = 0;
  if (!rd_i(off, &nlen) || nlen < 0 || off + 4 + static_cast<size_t>(nlen) > nbytes) {
    return false;
  }
  off += 4 + static_cast<size_t>(nlen);
  int32_t natlas = 0;
  if (!rd_i(off, &natlas) || natlas < 0 || natlas > 64) {
    return false;
  }
  off += 4;
  for (int32_t i = 0; i < natlas; ++i) {
    int32_t alen = 0;
    if (!rd_i(off, &alen) || alen < 0 || off + 4 + static_cast<size_t>(alen) > nbytes) {
      return false;
    }
    off += 4 + static_cast<size_t>(alen);
  }
  for (int32_t s = 0; s < nsym; ++s) {
    int32_t nf = 0;
    if (off + 8 > nbytes || !rd_i(off + 4, &nf) || nf < 0 || nf > 0x10000) {
      return false;
    }
    off += 8 + static_cast<size_t>(nf) * 32u;
    if (off > nbytes) {
      return false;
    }
  }
  int32_t nvert = 0;
  if (!rd_i(off, &nvert) || nvert < 0 || nvert > 0x100000) {
    return false;
  }
  off += 4;
  const size_t need = static_cast<size_t>(nvert) * 24u;
  if (off + need > nbytes) {
    return false;
  }
  const size_t cap = *inout_count;
  const size_t ncopy = static_cast<size_t>(nvert) < cap ? static_cast<size_t>(nvert) : cap;
  if (out != nullptr) {
    for (size_t i = 0; i < ncopy; ++i) {
      const uint8_t *src = data + off + i * 24u;
      std::memcpy(&out[i].x, src + 0, 4);
      std::memcpy(&out[i].y, src + 4, 4);
      std::memcpy(&out[i].z, src + 8, 4);
      std::memcpy(&out[i].u, src + 12, 4);
      std::memcpy(&out[i].v, src + 16, 4);
      std::memcpy(&out[i].rgba, src + 20, 4);
    }
  }
  *inout_count = static_cast<size_t>(nvert);
  return ncopy == static_cast<size_t>(nvert) || out == nullptr;
}



} // namespace ds::shadow
