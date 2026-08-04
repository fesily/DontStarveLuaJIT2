#pragma once
// Mod identity helpers for config cascade path discovery (CF-S3).
#include <string>
#include <vector>

namespace ds::config::path {

struct ResolvedModIdentity {
    std::string canonical_modname;
    std::string modname;
    std::string modid;
    std::vector<std::string> aliases;
};

ResolvedModIdentity build_mod_identity();

} // namespace ds::config::path
