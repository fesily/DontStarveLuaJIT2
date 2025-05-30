#include "luajit_config.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

#include "util/platform.hpp"
static std::filesystem::path getGameDir() {
    static std::filesystem::path p = getExePath().parent_path().parent_path();
    return p;
}

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(luajit_config, modmain_path, server_disable_luajit, logic_fps);
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
    try
    {
        nlohmann::json j;
        sf >> j;
        return j.get<luajit_config>();
    }
    catch(...)
    {
        return std::nullopt;
    }
}
