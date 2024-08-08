#include "luajit_config.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

#ifdef _WIN32
std::filesystem::path getGameDir();
#else
std::filesystem::path getGameDir() {
    static std::filesystem::path p = getExePath().parent_path().parent_path();
    return p;
}
#endif
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(luajit_config, modmain_path, server_disable_luajit);
std::optional<luajit_config> luajit_config::read_from_file(std::filesystem::path path) {
    if (path.empty())
        path = getGameDir() / "data" / "luajit_config.json";
    std::ifstream sf(path.string().c_str());
    if (!sf.is_open())
        return std::nullopt;
    nlohmann::json j;
    sf >> j;
    return j.get<luajit_config>();
}
