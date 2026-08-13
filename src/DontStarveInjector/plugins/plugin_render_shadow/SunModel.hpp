#pragma once

namespace ds::shadow {

enum class Phase : int { Day = 0, Dusk = 1, Night = 2 };

struct SunSample {
  float yaw_rad;       // world shadow stretch direction
  float length_scale;  // >= 0; multiply length axis
  bool visible;        // false → caller uses stock path or skips
};

// progress in [0,1]; fullmoon only matters for Night
SunSample Evaluate(Phase phase, float progress, bool fullmoon, float length_boost) noexcept;

// Thread-safe snapshot for render hook
void Publish(const SunSample &s) noexcept;
SunSample LoadPublished() noexcept;

} // namespace ds::shadow
