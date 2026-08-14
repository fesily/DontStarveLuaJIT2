#include "SunModel.hpp"
#include <cmath>
#include <cassert>
#include <cstdio>

static bool near_eq(float a, float b, float eps = 1e-3f) {
  return std::fabs(a - b) <= eps;
}

int main() {
  using ds::shadow::Evaluate;
  using ds::shadow::Phase;

  // Default northern: yaw = -2πp (clockwise). Southern is the opposite sign.
  auto dawn = Evaluate(Phase::Day, 0.0f, false, 1.0f, true);
  auto noon = Evaluate(Phase::Day, 0.25f, false, 1.0f, true);
  auto dusk_day = Evaluate(Phase::Day, 0.50f, false, 1.0f, true);
  assert(dawn.visible && noon.visible && dusk_day.visible);
  assert(noon.length_scale < dawn.length_scale);
  assert(noon.length_scale < dusk_day.length_scale);
  assert(near_eq(dawn.yaw_rad, 0.0f));
  assert(near_eq(noon.yaw_rad, -1.5707963f, 2e-2f));
  assert(near_eq(dusk_day.yaw_rad, -3.14159265f, 2e-2f));
  auto midn = Evaluate(Phase::Night, 0.75f, true, 1.0f, true);
  assert(midn.visible);
  assert(near_eq(midn.yaw_rad, -4.7123889f, 2e-2f));

  auto noon_s = Evaluate(Phase::Day, 0.25f, false, 1.0f, false);
  assert(near_eq(noon_s.yaw_rad, 1.5707963f, 2e-2f));
  assert(near_eq(noon_s.length_scale, noon.length_scale));

  // Continuous: nearby times have nearby (not equal) yaw.
  auto q0 = Evaluate(Phase::Day, 0.13f, false, 1.0f, true);
  auto q1 = Evaluate(Phase::Day, 0.14f, false, 1.0f, true);
  assert(!near_eq(q0.yaw_rad, q1.yaw_rad));
  assert(q1.yaw_rad < q0.yaw_rad); // northern: more time → more negative
  auto q2 = Evaluate(Phase::Day, 0.16f, false, 1.0f, true);
  assert(q2.yaw_rad < q1.yaw_rad);

  auto night = Evaluate(Phase::Night, 0.5f, false, 1.0f, true);
  assert(!night.visible);

  auto moon = Evaluate(Phase::Night, 0.5f, true, 1.0f, true);
  assert(moon.visible);

  auto b1 = Evaluate(Phase::Day, 0.25f, false, 1.0f, true);
  auto b2 = Evaluate(Phase::Day, 0.25f, false, 2.0f, true);
  assert(near_eq(b2.length_scale, b1.length_scale * 2.0f, 1e-3f));

  // Cast offset: noon (scale=1) stays centered on feet.
  auto o_noon = ds::shadow::CastCenterOffset(2.0f, 1.0f, 0.0f);
  assert(near_eq(o_noon.x, 0.0f));
  assert(near_eq(o_noon.z, 0.0f));

  // Extra length goes along +yaw; feet stay at near edge inset 0.5*unscaled.
  // scale=3, size=2, yaw=0 → extra = 0.5*2*(3-1) = 2 along +X
  auto o_x = ds::shadow::CastCenterOffset(2.0f, 3.0f, 0.0f);
  assert(near_eq(o_x.x, 2.0f));
  assert(near_eq(o_x.z, 0.0f));

  auto o_z = ds::shadow::CastCenterOffset(2.0f, 3.0f, 1.57079632679f);
  assert(near_eq(o_z.x, 0.0f));
  assert(near_eq(o_z.z, 2.0f));

  float dir[2] = {99.f, 99.f};
  ds::shadow::FillSunDir(dir, 0.0f);
  assert(near_eq(dir[0], 1.0f));
  assert(near_eq(dir[1], 0.0f));
  ds::shadow::FillSunDir(dir, 1.57079632679f);
  assert(near_eq(dir[0], 0.0f));
  assert(near_eq(dir[1], 1.0f));

  // Publish/load
  ds::shadow::Publish(noon);
  auto loaded = ds::shadow::LoadPublished();
  assert(near_eq(loaded.yaw_rad, noon.yaw_rad));
  assert(near_eq(loaded.length_scale, noon.length_scale));
  assert(loaded.visible == noon.visible);

  std::puts("test_sun_model OK");
  return 0;
}
