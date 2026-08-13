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

  // Day noon-ish: shorter than dawn
  auto dawn = Evaluate(Phase::Day, 0.05f, false, 1.0f);
  auto noon = Evaluate(Phase::Day, 0.50f, false, 1.0f);
  auto dusk_day = Evaluate(Phase::Day, 0.95f, false, 1.0f);
  assert(dawn.visible && noon.visible && dusk_day.visible);
  assert(noon.length_scale < dawn.length_scale);
  assert(noon.length_scale < dusk_day.length_scale);

  // Yaw changes across day (not constant)
  assert(!near_eq(dawn.yaw_rad, dusk_day.yaw_rad, 0.05f));

  // Night without fullmoon: not visible for sun drive
  auto night = Evaluate(Phase::Night, 0.5f, false, 1.0f);
  assert(!night.visible);

  // Fullmoon night: visible
  auto moon = Evaluate(Phase::Night, 0.5f, true, 1.0f);
  assert(moon.visible);

  // Boost multiplies length
  auto b1 = Evaluate(Phase::Day, 0.5f, false, 1.0f);
  auto b2 = Evaluate(Phase::Day, 0.5f, false, 2.0f);
  assert(near_eq(b2.length_scale, b1.length_scale * 2.0f, 1e-3f));

  // Publish/load
  ds::shadow::Publish(noon);
  auto loaded = ds::shadow::LoadPublished();
  assert(near_eq(loaded.yaw_rad, noon.yaw_rad));
  assert(near_eq(loaded.length_scale, noon.length_scale));
  assert(loaded.visible == noon.visible);

  std::puts("test_sun_model OK");
  return 0;
}
