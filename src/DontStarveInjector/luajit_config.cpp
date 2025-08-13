#include "luajit_config.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

#include "util/platform.hpp"
static std::filesystem::path getGameDir() {
    static std::filesystem::path p = getExePath().parent_path().parent_path();
    return p;
}

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(luajit_config, modmain_path, server_disable_luajit);
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
