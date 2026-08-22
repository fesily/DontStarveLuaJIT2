#include "SunModel.hpp"

#include <atomic>
#include <bit>
#include <cmath>
#include <cstdint>

namespace ds::shadow {
namespace {

constexpr float kMaxLeg = 3.0f;
constexpr float kMinLeg = 0.8f;
constexpr float kAlpha0 = 0.5f;
constexpr float kFade = 10.0f / 480.0f;
constexpr float kTlToEngineYaw = 0.0f;

float Clamp01(float p) noexcept {
  if (p < 0.0f) {
    return 0.0f;
  }
  if (p > 1.0f) {
    return 1.0f;
  }
  return p;
}

std::atomic<uint32_t> g_yaw_bits{0};
std::atomic<uint32_t> g_len_bits{0};
std::atomic<uint32_t> g_alpha_bits{0};
std::atomic<uint32_t> g_visible{0};
std::atomic<int> g_northern{1};
std::atomic<uint32_t> g_boost_bits{0x3f800000u}; // 1.0f

} // namespace

void SetLengthBoost(float boost) noexcept {
  if (boost < 0.5f) {
    boost = 0.5f;
  } else if (boost > 2.0f) {
    boost = 2.0f;
  }
  g_boost_bits.store(std::bit_cast<uint32_t>(boost), std::memory_order_release);
}

float LengthBoost() noexcept {
  return std::bit_cast<float>(g_boost_bits.load(std::memory_order_acquire));
}

void SetNorthernHemisphere(bool northern) noexcept {
  g_northern.store(northern ? 1 : 0, std::memory_order_release);
}

bool IsNorthernHemisphere() noexcept {
  return g_northern.load(std::memory_order_acquire) != 0;
}

SunSample Evaluate(const SunInput &in) noexcept {
  SunSample s{};
  const float p = Clamp01(in.timeinphase);
  const float t = Clamp01(in.time);
  const bool night = in.phase == Phase::Night;
  const bool dusk = in.phase == Phase::Dusk;
  const bool day = in.phase == Phase::Day;
  s.visible = day || dusk || (night && in.moonlit);
  if (!s.visible) {
    return s;
  }

  float scale_y = kMinLeg;
  float theta = 0.f;
  if (dusk) {
    scale_y = std::hypot(kMaxLeg, kMinLeg);
    theta = std::atan(kMaxLeg / kMinLeg);
  } else {
    const float leg1 = 2.f * kMaxLeg * (p - 0.5f);
    scale_y = std::hypot(leg1, kMinLeg);
    theta = std::atan(leg1 / kMinLeg);
  }

  float boost = in.length_boost;
  if (boost < 0.f) {
    boost = 0.f;
  }
  s.length_scale = (scale_y / kMinLeg) * boost;
  s.yaw_rad = theta + kTlToEngineYaw;
  if (!in.northern) {
    s.yaw_rad = -s.yaw_rad;
  }

  float a = 0.f;
  if (dusk) {
    a = kAlpha0 * (1.f - p);
  } else if (night && in.moonlit) {
    const float fade_p = p < kFade ? p / kFade : 1.f;
    a = kAlpha0 * fade_p;
  } else {
    const float fade_t = t < kFade ? t / kFade : 1.f;
    a = kAlpha0 * fade_t;
  }

  if (in.season == Season::Winter) {
    a *= 0.8f;
  } else if (in.season == Season::Summer) {
    a *= 1.2f;
  }
  if (in.wet) {
    a *= 0.8f;
  }
  s.alpha = a;
  return s;
}

void Publish(const SunSample &s) noexcept {
  g_yaw_bits.store(std::bit_cast<uint32_t>(s.yaw_rad), std::memory_order_relaxed);
  g_len_bits.store(std::bit_cast<uint32_t>(s.length_scale), std::memory_order_relaxed);
  g_alpha_bits.store(std::bit_cast<uint32_t>(s.alpha), std::memory_order_relaxed);
  g_visible.store(s.visible ? 1u : 0u, std::memory_order_release);
}

SunSample LoadPublished() noexcept {
  SunSample s{};
  s.visible = g_visible.load(std::memory_order_acquire) != 0;
  s.yaw_rad = std::bit_cast<float>(g_yaw_bits.load(std::memory_order_relaxed));
  s.length_scale = std::bit_cast<float>(g_len_bits.load(std::memory_order_relaxed));
  s.alpha = std::bit_cast<float>(g_alpha_bits.load(std::memory_order_relaxed));
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
