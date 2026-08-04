#pragma once
#include <cstdint>
namespace ds::config {
enum class ConfigSource : uint8_t {
    None           = 0,
    ModinfoDefault = 1u << 0,
    LuajitConfig   = 1u << 1,
    SaveFile       = 1u << 2,
    EnvOrCmd       = 1u << 3,
};
using ConfigSourceMask = uint8_t;
constexpr ConfigSourceMask kConfigSourceAll =
    static_cast<ConfigSourceMask>(ConfigSource::ModinfoDefault) |
    static_cast<ConfigSourceMask>(ConfigSource::LuajitConfig) |
    static_cast<ConfigSourceMask>(ConfigSource::SaveFile) |
    static_cast<ConfigSourceMask>(ConfigSource::EnvOrCmd);

inline ConfigSourceMask effective_sources(ConfigSourceMask m) {
    return m == 0 ? kConfigSourceAll : m;
}
inline bool source_allowed(ConfigSourceMask allowed, ConfigSource src) {
    const auto bit = static_cast<ConfigSourceMask>(src);
    return (effective_sources(allowed) & bit) != 0;
}
} // namespace ds::config
