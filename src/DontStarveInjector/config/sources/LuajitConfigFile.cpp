#include "LuajitConfigFile.hpp"
#include "config/BaseOptionKeys.hpp"
#include "plugins/plugin_core_vm/VmOptionKeys.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

#include "util/Unsafedata.hpp"
namespace nlohmann {
    void to_json(json& j, const luajit_config& s) {
        using ds::config::keys::kDisableJITWhenServer;
        using ds::config::keys::kModmainPath;
        j = json{{std::string{kModmainPath}, s.modmain_path},
                  {std::string{kDisableJITWhenServer}, s.server_disable_luajit}};
    }

    void from_json(const json& j, luajit_config& s) {
        using ds::config::keys::kDisableJITWhenServer;
        using ds::config::keys::kModmainPath;
        j.at(std::string{kModmainPath}).get_to(s.modmain_path);

        if (j.contains(std::string{kDisableJITWhenServer})) {
            j.at(std::string{kDisableJITWhenServer}).get_to(s.server_disable_luajit);
        } else if (j.contains("server_disable_luajit")) {
            j.at("server_disable_luajit").get_to(s.server_disable_luajit);
        }
    }
}

std::optional<luajit_config> luajit_config::read_from_file(std::filesystem::path path) {
    if (path.empty()) {
        path = ds::unsafedata::config_path();
    }
    if (path.empty() || !std::filesystem::exists(path))
        return std::nullopt;
    std::ifstream sf(path.string().c_str());
    if (!sf.is_open())
        return std::nullopt;
    try {
        nlohmann::json j;
        sf >> j;
        return j.get<luajit_config>();
    } catch (...) {
        return std::nullopt;
    }
}
