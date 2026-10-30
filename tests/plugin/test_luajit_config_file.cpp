#include "config/sources/LuajitConfigFile.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <fstream>

// 本测试显式传入临时文件；不访问游戏或玩家的默认配置目录。
namespace ds::unsafedata {
std::filesystem::path dir() { return {}; }
}

int main() {
    const auto file = std::filesystem::temp_directory_path() /
        ("ds_luajit_config_test_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + ".json");
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code ec; std::filesystem::remove(path, ec); }
    } cleanup{file};
    auto write = [&](const char *data) { std::ofstream(file, std::ios::binary) << data; };

    for (const char *data : {
             R"({"modmain_path":"mods/test/modmain.lua","DisableJITWhenServer":true})",
             R"({"modmain_path":"mods/test/modmain.lua","DisableJITWhenServer":true,"AlwaysEnableMod":false})",
             R"({"modmain_path":"mods/test/modmain.lua","server_disable_luajit":true,"always_enable_mod":false})",
             R"({"modmain_path":"mods/test/modmain.lua","DisableJITWhenServer":true,"AlwaysEnableMod":"obsolete"})"}) {
        write(data);
        const auto config = luajit_config::read_from_file(file);
        assert(config);
        assert(config->modmain_path == "mods/test/modmain.lua");
        assert(config->server_disable_luajit);
    }
    write(R"({"modmain_path":"mods/test/modmain.lua"})");
    assert(!luajit_config::read_from_file(file)->server_disable_luajit);
    write("{invalid");
    assert(!luajit_config::read_from_file(file));
    assert(!luajit_config::read_from_file());
    puts("PASS: luajit_config_file ignores retired options and preserves remaining configuration");
}
