#pragma once
#include "ConfigSource.hpp"
#include "core/PluginTypes.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ds::config {

struct CascadeContext {
    bool is_client = false;
    uint32_t steam_account_id = 0;
    // filled as layers run / pre-pass:
    std::string modname;
    std::string modid;
    std::string modmain_path;
    std::vector<std::string> aliases;
    // optional path hints for server
    std::optional<std::string> ownerdir_hint;
    // client write-back path (filled by SaveFileSource when known)
    std::optional<std::string> save_file;
};

struct ConfigPartial {
    ds::plugin::ConfigView values;
};

struct IConfigSource {
    virtual ~IConfigSource() = default;
    virtual ConfigSource id() const = 0;
    // May use identity/paths from previous layers (e.g. modname for save path).
    // Non-const so sources may update CascadeContext identity fields.
    virtual ConfigPartial read(CascadeContext &ctx) const = 0;
};

} // namespace ds::config
