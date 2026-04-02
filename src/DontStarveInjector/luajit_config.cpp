#include "luajit_config.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

#include "util/platform.hpp"
static std::filesystem::path getGameDir() {
    static std::filesystem::path p = getExePath().parent_path().parent_path();
    return p;
}
namespace nlohmann {
    void to_json(json& j, const luajit_config& s) {
        j = json{{"modmain_path", s.modmain_path},
                  {"DisableJITWhenServer", s.server_disable_luajit},
                  {"AlwaysEnableMod", s.always_enable_mod}};
    }

    void from_json(const json& j, luajit_config& s) {
        j.at("modmain_path").get_to(s.modmain_path);
        j.at("DisableJITWhenServer").get_to(s.server_disable_luajit);
        j.at("AlwaysEnableMod").get_to(s.always_enable_mod);
    }
}

std::optional<luajit_config> luajit_config::read_from_file(std::filesystem::path path) {
    if (path.empty()) {
        path = getGameDir() / "data" / "unsafedata";
        if (!std::filesystem::exists(path)) {
            std::filesystem::create_directories(path);
        }
        path = path / "luajit_config.json";
    }
    if (!std::filesystem::exists(path))
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
