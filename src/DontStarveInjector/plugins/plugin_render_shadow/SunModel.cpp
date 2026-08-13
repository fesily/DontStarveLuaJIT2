#include "SunModel.hpp"

#include <atomic>
#include <bit>
#include <cmath>
#include <cstdint>

namespace ds::shadow {
namespace {

constexpr float kMinLeg = 0.8f;

float Clamp01(float p) noexcept {
  if (p < 0.0f) {
    return 0.0f;
  }
  if (p > 1.0f) {
    return 1.0f;
  }
  return p;
}

SunSample EvaluateDayLike(float progress, float length_boost) noexcept {
  const float p = Clamp01(progress);
  const float leg = 2.0f * (p - 0.5f);
  SunSample s{};
  s.yaw_rad = atan2f(leg, kMinLeg);
  const float raw_len = hypotf(leg, kMinLeg);
  s.length_scale = (raw_len / kMinLeg) * length_boost;
  s.visible = true;
  return s;
}

std::atomic<uint32_t> g_yaw_bits{0};
std::atomic<uint32_t> g_len_bits{0};
std::atomic<uint32_t> g_visible{0};

} // namespace

SunSample Evaluate(Phase phase, float progress, bool fullmoon, float length_boost) noexcept {
  switch (phase) {
  case Phase::Day:
    return EvaluateDayLike(progress, length_boost);
  case Phase::Dusk: {
    SunSample s{};
    s.yaw_rad = atan2f(1.0f, kMinLeg);
    s.length_scale = (hypotf(1.0f, kMinLeg) / kMinLeg) * length_boost;
    s.visible = progress < 0.99f;
    return s;
  }
  case Phase::Night:
    if (!fullmoon) {
      return SunSample{0.0f, 0.0f, false};
    }
    return EvaluateDayLike(progress, length_boost);
  }
  return SunSample{0.0f, 0.0f, false};
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

} // namespace ds::shadow
