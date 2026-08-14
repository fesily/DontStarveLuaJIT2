#pragma once

namespace ds::shadow {

enum class Phase : int { Day = 0, Dusk = 1, Night = 2 };

struct SunSample {
  float yaw_rad;       // world shadow stretch direction
  float length_scale;  // >= 0; multiply length axis
  bool visible;        // false → caller uses stock path or skips
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

// progress = full-day clock time ∈ [0,1], continuous. yaw = ±2πp.
// northern: yaw = -2πp (clockwise from +X). southern: yaw = +2πp.
// Night is visible when moonlit (not new moon). Cave should pass moonlit=false.
SunSample Evaluate(Phase phase, float progress, bool moonlit, float length_boost,
                   bool northern) noexcept;

void SetNorthernHemisphere(bool northern) noexcept;
bool IsNorthernHemisphere() noexcept;

// Thread-safe snapshot for render hook
void Publish(const SunSample &s) noexcept;
SunSample LoadPublished() noexcept;

} // namespace ds::shadow
