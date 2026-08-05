#pragma once
// render.angle domain helper — read cascade AngleBackend without L0 accessors.
#include "AngleOptionKeys.hpp"
#include "config/ResolvedConfig.hpp"

#include <string_view>

namespace ds::render_angle {

inline std::string_view angle_backend(const ds::config::ResolvedConfig &rc) {
    auto it = rc.view.find(std::string{ds::config::keys::kAngleBackend});
    if (it != rc.view.end() && it->second.type == ds::plugin::ConfigValueType::String &&
        !it->second.s.empty()) {
        return it->second.s;
    }
    return "auto";
}

} // namespace ds::render_angle
