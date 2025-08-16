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
                  {"server_disable_luajit", s.server_disable_luajit},
                  {"always_enable_mod", s.always_enable_mod}};
    }

    void from_json(const json& j, luajit_config& s) {
        j.at("modmain_path").get_to(s.modmain_path);
        if (j.contains("server_disable_luajit")) {
            j.at("server_disable_luajit").get_to(s.server_disable_luajit);
        }
        if (j.contains("always_enable_mod")) {
            j.at("always_enable_mod").get_to(s.always_enable_mod);
        }
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
        using namespace std::literals::string_view_literals;
        constexpr auto workshop_prefix = "workshop-"sv;

        nlohmann::json j;
        sf >> j;
        auto res = j.get<luajit_config>();
        auto inGameRoot = res.modmain_path.contains("mods");
        auto modmain_path = std::filesystem::path{res.modmain_path};
        auto modroot = modmain_path.parent_path();
        res.modname = modroot.filename().string();

        res.modid = res.modname;
        if (!inGameRoot) {
            res.modname = std::string(workshop_prefix) + res.modname;
        } else {
            if (res.modname.starts_with(workshop_prefix)) {
                res.modid = res.modname.substr(workshop_prefix.size());
            }
        }
        return res;
    } catch (...) {
        return std::nullopt;
    }
}
