#include "SunModel.hpp"

#include <atomic>
#include <bit>
#include <cmath>
#include <cstdint>

namespace ds::shadow {
namespace {

// Simplified engine day/night: one key light spins 360° over clock `time` ∈ [0,1].
// p=0 dawn, 0.25 noon (short), 0.5 dusk, 0.75 midnight (moon, short).
// Continuous in p — Lua rejects client clock teleports. Length uses |cos|.
constexpr float kMaxLeg = 3.0f;
constexpr float kMinLeg = 0.8f;
constexpr float kPi = 3.14159265358979323846f;

float Clamp01(float p) noexcept {
  if (p < 0.0f) {
    return 0.0f;
  }
  if (p > 1.0f) {
    return 1.0f;
  }
  return p;
}

SunSample EvaluateCycle(float progress, float length_boost, bool visible, bool northern) noexcept {
  const float p = Clamp01(progress);
  const float turn = p * 2.0f * kPi;
  const float horiz = std::fabs(std::cos(turn));
  SunSample s{};
  s.yaw_rad = northern ? -turn : turn;
  s.length_scale = (hypotf(horiz * kMaxLeg, kMinLeg) / kMinLeg) * length_boost;
  s.visible = visible;
  return s;
}

std::atomic<uint32_t> g_yaw_bits{0};
std::atomic<uint32_t> g_len_bits{0};
std::atomic<uint32_t> g_visible{0};
std::atomic<int> g_northern{1};

} // namespace

void SetNorthernHemisphere(bool northern) noexcept {
  g_northern.store(northern ? 1 : 0, std::memory_order_release);
}

bool IsNorthernHemisphere() noexcept {
  return g_northern.load(std::memory_order_acquire) != 0;
}

SunSample Evaluate(Phase phase, float progress, bool moonlit, float length_boost,
                   bool northern) noexcept {
  const bool visible = (phase != Phase::Night) || moonlit;
  return EvaluateCycle(progress, length_boost, visible, northern);
}

void Publish(const SunSample &s) noexcept {
  g_yaw_bits.store(std::bit_cast<uint32_t>(s.yaw_rad), std::memory_order_relaxed);
  g_len_bits.store(std::bit_cast<uint32_t>(s.length_scale), std::memory_order_relaxed);
  g_visible.store(s.visible ? 1u : 0u, std::memory_order_release);
}

SunSample LoadPublished() noexcept {
  SunSample s{};
  s.visible = g_visible.load(std::memory_order_acquire) != 0;
  s.yaw_rad = std::bit_cast<float>(g_yaw_bits.load(std::memory_order_relaxed));
  s.length_scale = std::bit_cast<float>(g_len_bits.load(std::memory_order_relaxed));
  return s;
}

XZ CastCenterOffset(float unscaled_size_x, float length_scale, float yaw_rad) noexcept {
  if (!(unscaled_size_x > 0.0f) || !(length_scale > 0.0f)) {
    return XZ{0.0f, 0.0f};
  }
  const float extra = 0.5f * unscaled_size_x * (length_scale - 1.0f);
  return XZ{extra * std::cos(yaw_rad), extra * std::sin(yaw_rad)};
}

void FillSunDir(float dir[2], float yaw_rad) noexcept {
  if (dir == nullptr) {
    return;
  }
  dir[0] = std::cos(yaw_rad);
  dir[1] = std::sin(yaw_rad);
}

} // namespace ds::shadow
