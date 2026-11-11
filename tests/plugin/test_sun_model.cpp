#include "SunModel.hpp"
#include <cmath>
#include <doctest/doctest.h>

static bool near_eq(float a, float b, float eps = 1e-3f) {
  return std::fabs(a - b) <= eps;
}

TEST_CASE("test_sun_model/all") {
  using ds::shadow::Evaluate;
  using ds::shadow::Phase;
  using ds::shadow::Season;
  using ds::shadow::SunInput;

  SunInput base{};
  base.phase = Phase::Day;
  base.time = 1.f;
  base.length_boost = 1.f;
  base.northern = true;

  base.timeinphase = 0.f;
  auto dawn = Evaluate(base);
  REQUIRE(dawn.visible);
  REQUIRE(near_eq(dawn.length_scale, 3.8810f, 1e-3f));
  REQUIRE(near_eq(dawn.yaw_rad, -1.3102f, 2e-2f));
  REQUIRE(near_eq(dawn.alpha, 0.5f));

  base.timeinphase = 0.5f;
  auto noon = Evaluate(base);
  REQUIRE(near_eq(noon.length_scale, 1.0f));
  REQUIRE(near_eq(noon.yaw_rad, 0.f));

  base.timeinphase = 1.f;
  auto day_end = Evaluate(base);
  REQUIRE(near_eq(day_end.length_scale, 3.8810f, 1e-3f));
  REQUIRE(near_eq(day_end.yaw_rad, 1.3102f, 2e-2f));

  base.phase = Phase::Dusk;
  base.timeinphase = 0.3f;
  auto dusk = Evaluate(base);
  REQUIRE(near_eq(dusk.length_scale, 3.8810f, 1e-3f));
  REQUIRE(near_eq(dusk.yaw_rad, 1.3102f, 2e-2f));
  REQUIRE(near_eq(dusk.alpha, 0.5f * 0.7f));

  base.phase = Phase::Night;
  base.moonlit = false;
  auto night = Evaluate(base);
  REQUIRE_FALSE(night.visible);
  REQUIRE_EQ(night.alpha, 0.f);

  base.moonlit = true;
  base.timeinphase = 0.5f;
  auto moon = Evaluate(base);
  REQUIRE(moon.visible);
  REQUIRE(near_eq(moon.length_scale, 1.0f));
  REQUIRE(near_eq(moon.yaw_rad, 0.f));

  base.phase = Phase::Day;
  base.timeinphase = 0.5f;
  base.northern = false;
  auto noon_s = Evaluate(base);
  REQUIRE(near_eq(noon_s.yaw_rad, 0.f));
  base.timeinphase = 0.f;
  auto dawn_s = Evaluate(base);
  REQUIRE(near_eq(dawn_s.yaw_rad, 1.3102f, 2e-2f));

  base.northern = true;
  base.timeinphase = 0.5f;
  base.season = Season::Winter;
  REQUIRE(near_eq(Evaluate(base).alpha, 0.5f * 0.8f));
  base.season = Season::None;
  base.wet = true;
  REQUIRE(near_eq(Evaluate(base).alpha, 0.5f * 0.8f));
  base.wet = false;
  base.length_boost = 2.f;
  REQUIRE(near_eq(Evaluate(base).length_scale, 2.0f));

  base.length_boost = 1.f;
  base.time = 0.f;
  base.timeinphase = 0.5f;
  auto fade0 = Evaluate(base);
  REQUIRE(near_eq(fade0.alpha, 0.f));
  REQUIRE(fade0.visible);
  REQUIRE(near_eq(fade0.length_scale, 1.0f));

  auto o_noon = ds::shadow::CastCenterOffset(2.0f, 1.0f, 0.0f);
  REQUIRE(near_eq(o_noon.x, 0.0f));
  REQUIRE(near_eq(o_noon.z, 0.0f));

  auto o_x = ds::shadow::CastCenterOffset(2.0f, 3.0f, 0.0f);
  REQUIRE(near_eq(o_x.x, 2.0f));
  REQUIRE(near_eq(o_x.z, 0.0f));

  auto o_z = ds::shadow::CastCenterOffset(2.0f, 3.0f, 1.57079632679f);
  REQUIRE(near_eq(o_z.x, 0.0f));
  REQUIRE(near_eq(o_z.z, 2.0f));

  float dir[2] = {99.f, 99.f};
  ds::shadow::FillSunDir(dir, 0.0f);
  REQUIRE(near_eq(dir[0], 1.0f));
  REQUIRE(near_eq(dir[1], 0.0f));
  ds::shadow::FillSunDir(dir, 1.57079632679f);
  REQUIRE(near_eq(dir[0], 0.0f));
  REQUIRE(near_eq(dir[1], 1.0f));

  ds::shadow::Publish(noon);
  auto loaded = ds::shadow::LoadPublished();
  REQUIRE(near_eq(loaded.yaw_rad, noon.yaw_rad));
  REQUIRE(near_eq(loaded.length_scale, noon.length_scale));
  REQUIRE_EQ(loaded.visible, noon.visible);
  REQUIRE(near_eq(loaded.alpha, noon.alpha));

  REQUIRE(near_eq(ds::shadow::HeadingDegreesFromSunYaw(0.0f), -90.0f));
  REQUIRE(near_eq(ds::shadow::HeadingDegreesFromSunYaw(1.57079632679f), 0.0f));
  REQUIRE(near_eq(ds::shadow::HeadingDegreesFromSunYaw(-1.57079632679f), -180.0f));
}
