#include "SilhouetteMath.hpp"
#include "SilhouetteBatch.hpp"
#include "SunModel.hpp"
#include <cmath>
#include <cstring>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include "support/test_assert.hpp"


static bool near(float a, float b) { return std::fabs(a - b) < 1e-4f; }

// test_shadow_matrix does not link SilhouetteBatch.cpp. Stand-in for the
// VirtualQuery ReadableUserPtr so the header-inline UV gate can run.
bool ds::shadow::ReadableUserPtr(const void *p, size_t bytes) noexcept {
    return p != nullptr && bytes != 0;
}


int main() {
  using namespace ds::shadow;

  // scale==1 → offset 0
  auto o = CastCenterOffset(1.5f, 1.0f, 0.8f);
  DS_REQUIRE(near(o.x, 0.f) && near(o.z, 0.f));

  // extra length along +X yaw=0: size 2, scale 2 → off.x = 1.0, off.z = 0
  o = CastCenterOffset(2.0f, 2.0f, 0.0f);
  DS_REQUIRE(near(o.x, 1.0f) && near(o.z, 0.f));

  float x, y, z;
  FlattenPoint(1.f, 2.f, 0.f, 0.f, 2.f, 10.f, 20.f, &x, &y, &z);
  DS_REQUIRE(near(y, 0.f));
  DS_REQUIRE(near(x, 12.f)); // stretch along yaw 0 = +X; origin 10 + 2*1
  DS_REQUIRE(near(z, 20.f));

  // Alpha in the high byte (0xAARRGGBB): RGB=0, A unchanged.

  float m[16];
  FlattenMatrix(0.f, 2.f, 10.f, 20.f, 0.f, 0.f, m);
  DS_REQUIRE(near(m[0] * 1.f + m[3], 12.f));
  DS_REQUIRE(near(m[4] * 1.f + m[7], 0.f));
  DS_REQUIRE(near(m[8] * 1.f + m[11], 20.f));

  FlattenMatrix(0.f, 2.f, 10.f, 20.f, 3.f, 4.f, m);
  float fx, fy, fz;
  FlattenPoint(1.f - 3.f, 2.f, 0.f - 4.f, 0.f, 2.f, 10.f, 20.f, &fx, &fy, &fz);
  DS_REQUIRE(near(m[0] * 1.f + m[1] * 2.f + m[3], fx));
  DS_REQUIRE(near(m[4] * 1.f + m[5] * 2.f + m[7], fy));
  DS_REQUIRE(near(m[8] * 1.f + m[9] * 2.f + m[11], fz));
  DS_REQUIRE(BlackKeepAlpha(0xFF123456u) == 0xFF000000u);
  DS_REQUIRE(ApplyShadowAlpha(0xFF123456u, 1.f) == 0xFF000000u);
  DS_REQUIRE(ApplyShadowAlpha(0xFF123456u, 0.5f) == 0x80000000u);
  DS_REQUIRE(ApplyShadowAlpha(0x80000000u, 0.5f) == 0x40000000u);
  DS_REQUIRE(ApplyShadowAlpha(0xFF000000u, 0.f) == 0u);
  DS_REQUIRE(ApplyShadowAlpha(0xFF000000u, 2.f) == 0xFF000000u);
  DS_REQUIRE(ApplyShadowAlpha(0xFF000000u, -1.f) == 0u);
  DS_REQUIRE(ApplyShadowAlpha(0x01000000u, 0.4f) == 0u);
  DS_REQUIRE(ShadowCoverageAlpha(0x00000000u, 0.5f) == 0u);
  DS_REQUIRE(ShadowCoverageAlpha(0xFF123456u, 0.5f) == 0x80000000u);
  DS_REQUIRE(ShadowCoverageAlpha(0x80000000u, 0.5f) == 0x80000000u);
  DS_REQUIRE(ShadowCoverageAlpha(0x01000000u, 0.5f) == 0x80000000u);
  DS_REQUIRE(ShadowCoverageAlpha(0xFF000000u, 0.f) == 0u);
  DS_REQUIRE(ShadowCoverageAlpha(0xFF000000u, 2.f) == 0xFF000000u);
  DS_REQUIRE(ShadowCoverageAlpha(0xFF000000u, -1.f) == 0u);
  {
    const uint32_t one[] = {0xFF000000u};
    DS_REQUIRE(UnionThenTint(one, 1, 0.5f) == 0x80000000u);
    const uint32_t two[] = {0xFF000000u, 0xFF000000u};
    DS_REQUIRE(UnionThenTint(two, 2, 0.5f) == 0x80000000u);
    const uint32_t none[] = {0u, 0u};
    DS_REQUIRE(UnionThenTint(none, 2, 0.5f) == 0u);
    const uint32_t mix[] = {0u, 0x01000000u};
    DS_REQUIRE(UnionThenTint(mix, 2, 0.5f) == 0x80000000u);
  }

  {
    uint8_t obj[0x80]{};
    obj[0] = 0x10;
    uint8_t fake_build{};
    uint8_t *bp = &fake_build;
    std::memcpy(obj + 0x58, &bp, sizeof(bp));
    const uint32_t dest = 0xA5A5A5A5u;
    std::memcpy(obj + 0x70, &dest, sizeof(dest));
    const auto ov = ReadSymbolOverride(obj);
    DS_REQUIRE(!ov.skip);
    DS_REQUIRE(ov.build == bp);
    DS_REQUIRE(ov.symbol == dest);

    obj[0] = 0x01;
    DS_REQUIRE(ReadSymbolOverride(obj).skip);

    uint8_t empty[0x80]{};
    const auto none = ReadSymbolOverride(empty);
    DS_REQUIRE(!none.skip);
    DS_REQUIRE(none.build == nullptr);
    DS_REQUIRE(none.symbol == 0);
  }

  {
    uint8_t node[0x30]{};
    const uint32_t key = 0x7788u;
    std::memcpy(node + 0x18, &key, sizeof(key));
    DS_REQUIRE(MsvcMapKey(node) == key);
    DS_REQUIRE(MsvcMapValue(node) == node + 0x28);
  }




  {
    float xz[12];
    DebugChevronXZ(0.f, 0.f, 0.f, xz);
    DS_REQUIRE(xz[0] > 0.f && near(xz[1], 0.f)); // tip along +X
    DS_REQUIRE(xz[2] < 0.f && xz[3] < 0.f);     // wingL
    DS_REQUIRE(xz[10] < 0.f && xz[11] > 0.f);   // wingR
    DebugChevronXZ(10.f, 20.f, 1.57079632679f, xz);
    DS_REQUIRE(near(xz[0], 10.f) && xz[1] > 20.f); // tip along +Z
  }



  {
    uint8_t fake[0x98]{};
    DS_REQUIRE(!BuildHasUvSource(fake));
    DS_REQUIRE(!BuildHasUvSource(nullptr));
  }
  {
    uint8_t fake[0x40]{};
    fake[0x1C] = 0x11;
    WriteRendererEffectHandle(fake, 0xABu);
    DS_REQUIRE(*reinterpret_cast<uint32_t *>(fake + 0x2C) == 0xABu);
    DS_REQUIRE(*reinterpret_cast<uint32_t *>(fake + 0x1C) == 0x11u);
  }

  // SetEffect handle write leaves src_data on the previous pass (splat).
  const int splat = 1;
  const int sil = 2;
  DS_REQUIRE(!ds::shadow::BindProgramUpdatesSrcData(&splat, &splat));
  DS_REQUIRE(!ds::shadow::BindProgramUpdatesSrcData(&splat, nullptr));
  DS_REQUIRE(ds::shadow::BindProgramUpdatesSrcData(&splat, &sil));
  // Bind mutates renderer+0x28 (bound handle), not HWEffect+0xB8.
  // Sampling the same sil blob before/after is not a bind proof.
  DS_REQUIRE(!ds::shadow::BindProgramUpdatesSrcData(&sil, &sil));
  DS_REQUIRE(ds::shadow::BindProgramUpdatesSrcData(nullptr, &sil));
  DS_REQUIRE(ds::shadow::BindCopiedDesiredHandle(0x3f, 0x3f));
  DS_REQUIRE(!ds::shadow::BindCopiedDesiredHandle(0, 0x3f));
  DS_REQUIRE(!ds::shadow::BindCopiedDesiredHandle(0x9, 0x3f));


  {
    std::vector<unsigned char> blob;
    auto push_i = [&](uint32_t v) {
      blob.push_back(uint8_t(v));
      blob.push_back(uint8_t(v >> 8));
      blob.push_back(uint8_t(v >> 16));
      blob.push_back(uint8_t(v >> 24));
    };
    auto push_f = [&](float f) {
      uint32_t v;
      std::memcpy(&v, &f, 4);
      push_i(v);
    };
    blob.insert(blob.end(), {'B', 'I', 'L', 'D'});
    push_i(6);
    push_i(0);
    push_i(0);
    push_i(0);
    push_i(0);
    push_i(1);
    push_f(0.f);
    push_f(1.f);
    push_f(2.f);
    push_f(0.25f);
    push_f(0.75f);
    push_i(0x11223344u);
    BildVert vert{};
    size_t n = 1;
    DS_REQUIRE(ParseBildVerts(blob.data(), blob.size(), &vert, &n));
    DS_REQUIRE(n == 1);
    DS_REQUIRE(near(vert.u, 0.25f) && near(vert.v, 0.75f));
    DS_REQUIRE(near(vert.x, 0.f) && near(vert.y, 1.f) && near(vert.z, 2.f));
    DS_REQUIRE(vert.rgba == 0x11223344u);
    float u = 0, vv = 0;
    BildUv(vert, &u, &vv);
    DS_REQUIRE(near(u, 0.25f) && near(vv, 0.75f));
  }

  {
    float xz[12]{};
    DebugRectXZ(10.f, 20.f, 0.f, 2.f, 1.f, xz);
    // yaw=0: along +X, perp +Z. Two CCW tris.
    DS_REQUIRE(near(xz[0], 8.f) && near(xz[1], 19.f));
    DS_REQUIRE(near(xz[2], 12.f) && near(xz[3], 19.f));
    DS_REQUIRE(near(xz[4], 12.f) && near(xz[5], 21.f));
    DS_REQUIRE(near(xz[6], 8.f) && near(xz[7], 19.f));
    DS_REQUIRE(near(xz[8], 12.f) && near(xz[9], 21.f));
    DS_REQUIRE(near(xz[10], 8.f) && near(xz[11], 21.f));
  }

  {
    auto apply = [](const float w[16], float lx, float ly, float lz, float *x, float *y,
                    float *z) {
      *x = w[0] * lx + w[1] * ly + w[2] * lz + w[3];
      *y = w[4] * lx + w[5] * ly + w[6] * lz + w[7];
      *z = w[8] * lx + w[9] * ly + w[10] * lz + w[11];
    };
    float I[16]{};
    I[0] = I[5] = I[10] = I[15] = 1.f;
    float w[16]{};
    ComposeShadowW(I, 0.f, 2.f, 0.f, 0.f, w);
    float x, y, z;
    // After facing camera, Y shears along the sun. Width (local X) stays.
    apply(w, 0.f, 1.f, 0.f, &x, &y, &z);
    DS_REQUIRE(near(x, 2.f) && near(y, 0.f) && near(z, 0.f));
    apply(w, -1.f, 0.f, 0.f, &x, &y, &z);
    DS_REQUIRE(near(x, -1.f) && near(y, 0.f) && near(z, 0.f));
    apply(w, 1.f, 0.f, 0.f, &x, &y, &z);
    DS_REQUIRE(near(x, 1.f) && near(y, 0.f) && near(z, 0.f));

    // Billboard then Y: camera-up (0.5, 0.866, 0), stretch=1 yaw=0.
    float B[16]{};
    B[0] = 1.f;
    B[1] = 0.5f;
    B[5] = 0.8660254f;
    B[10] = 1.f;
    B[15] = 1.f;
    ComposeShadowW(B, 0.f, 1.f, 0.f, 0.f, w);
    apply(w, 1.f, 0.f, 0.f, &x, &y, &z);
    DS_REQUIRE(near(x, 1.f) && near(y, 0.f) && near(z, 0.f));
    apply(w, 0.f, 2.f, 0.f, &x, &y, &z);
    DS_REQUIRE(near(x, 2.7320508f) && near(y, 0.f) && near(z, 0.f));

    float E[16]{};
    E[0] = E[5] = E[10] = E[15] = 1.f;
    E[3] = 10.f;
    E[7] = 5.f;
    E[11] = 20.f;
    ComposeShadowW(E, 0.f, 2.f, 0.f, 0.f, w);
    apply(w, 0.f, 0.f, 0.f, &x, &y, &z);
    DS_REQUIRE(near(x, 20.f) && near(y, 0.f) && near(z, 20.f));

    ComposeShadowW(I, 0.f, 2.f, -170.f, 45.f, w);
    apply(w, 0.f, 0.f, 0.f, &x, &y, &z);
    DS_REQUIRE(near(x, -170.f) && near(y, 0.f) && near(z, 45.f));
    DS_REQUIRE(near(w[14], 0.f) && near(w[15], 1.f));
    StashShadowAlpha(w, 0.4f);
    DS_REQUIRE(near(w[14], 0.4f) && near(w[15], 1.f));
    apply(w, 0.f, 1.f, 0.f, &x, &y, &z);
    DS_REQUIRE(near(x, -168.f) && near(y, 0.f) && near(z, 45.f));
    StashShadowAlpha(w, 2.f);
    DS_REQUIRE(near(w[14], 1.f));
    StashShadowAlpha(w, -0.2f);
    DS_REQUIRE(near(w[14], 0.f));

  }










  std::puts("test_shadow_matrix OK");
  return 0;
}
