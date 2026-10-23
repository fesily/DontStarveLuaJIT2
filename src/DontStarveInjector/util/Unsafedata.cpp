#include "util/Unsafedata.hpp"

#include "config/InjectorHostConfig.hpp"
#include "config/path/ConfigPaths.hpp"

#include <string>

namespace ds::unsafedata {
namespace {

std::filesystem::path resolve_dir() {
    const auto account_id = InjectorCtx::instance()->steam_account_id;
    const auto ownid = account_id != 0 ? std::to_string(account_id) : std::string{};
    const auto save_dir = ds::config::path::GetClientSaveDir(ownid);
    if (save_dir.empty()) {
        return {};
    }
    return save_dir / "unsafedata";
}

} // namespace

std::filesystem::path dir() {
    // Resolved lazily: the Steam account id only exists after sdk::steam::Initialize,
    // and an unresolved lookup (dedicated server) must not be cached as a decision.
    static std::filesystem::path cached;
    if (!cached.empty()) {
        return cached;
    }
    auto resolved = resolve_dir();
    if (!resolved.empty()) {
        cached = resolved;
    }
    return resolved;
}

} // namespace ds::unsafedata
