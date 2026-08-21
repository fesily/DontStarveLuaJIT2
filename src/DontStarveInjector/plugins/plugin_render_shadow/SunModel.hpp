#pragma once

namespace ds::shadow {

enum class Phase : int { Day = 0, Dusk = 1, Night = 2 };
enum class Season : int { None = 0, Winter = 1, Summer = 2 };

struct SunInput {
  Phase phase = Phase::Day;
  float timeinphase = 0.f;
  float time = 0.f;
  bool moonlit = false;
  float length_boost = 1.f;
  bool northern = true;
  Season season = Season::None;
  bool wet = false;
};

struct SunSample {
  float yaw_rad = 0.f;
  float length_scale = 0.f;
  float alpha = 0.f;
  bool visible = false;
};

struct XZ {
  float x;
  float z;
};

// Shift PopulateQuad center so extra length (scale-1) extends along yaw
// and the unscaled half-extent stays under the feet. scale==1 → {0,0}.
XZ CastCenterOffset(float unscaled_size_x, float length_scale, float yaw_rad) noexcept;

// dir[0]=cos(yaw), dir[1]=sin(yaw) — PopulateQuad stretch axis
void FillSunDir(float dir[2], float yaw_rad) noexcept;

// Stock GenerateVB: angle = (heading_deg + 90) * pi/180.
// Poke heading so that stock angle equals sun yaw.
inline float HeadingDegreesFromSunYaw(float yaw_rad) noexcept {
  return yaw_rad * 57.29577951308232f - 90.0f;
}

// Terminus Light right-triangle day cycle. Hooks only LoadPublished.
SunSample Evaluate(const SunInput &in) noexcept;

void SetLengthBoost(float boost) noexcept;
float LengthBoost() noexcept;
void SetNorthernHemisphere(bool northern) noexcept;
bool IsNorthernHemisphere() noexcept;

// Thread-safe snapshot for render hook
void Publish(const SunSample &s) noexcept;
SunSample LoadPublished() noexcept;

} // namespace ds::shadow
