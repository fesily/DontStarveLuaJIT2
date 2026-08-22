#include "PluginPackModinfo.hpp"

#include <fstream>
#include <iterator>
#include <sol/sol.hpp>

namespace ds::plugin {

PluginPackModinfo parse_plugin_pack_modinfo(const std::filesystem::path &modinfo_path) {
    PluginPackModinfo out;
    std::ifstream in(modinfo_path, std::ios::binary);
    if (!in) {
        out.parse_error = "open_failed";
        return out;
    }
    std::string content{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};

    try {
        sol::state lua;
        // Minimal sandbox: base only — no os/io/package loaders.
        lua.open_libraries(sol::lib::base);

        sol::environment env(lua, sol::create, lua.globals());
        env["folder_name"] = modinfo_path.parent_path().filename().string();
        env["locale"] = "";
        env["ChooseTranslationTable"] = [](sol::table t) -> sol::object {
            if (!t.valid()) {
                return sol::lua_nil;
            }
            return t[1];
        };

        // Run as a chunk with setfenv-style environment so assignments land in env.
        auto result = lua.safe_script(content, env, sol::script_pass_on_error);
        if (!result.valid()) {
            sol::error err = result;
            out.ok = false;
            out.parse_error = err.what();
            return out;
        }

        out.ok = true;
        if (env["luajit_plugin_pack"].valid()) {
            sol::object pack = env["luajit_plugin_pack"];
            if (pack.get_type() == sol::type::boolean) {
                out.luajit_plugin_pack = pack.as<bool>();
            }
        }
        if (env["plugin_id"].valid()) {
            sol::object id = env["plugin_id"];
            if (id.get_type() == sol::type::string) {
                out.plugin_id = id.as<std::string>();
            }
        }
    } catch (const std::exception &e) {
        out.ok = false;
        out.parse_error = e.what();
    } catch (...) {
        out.ok = false;
        out.parse_error = "unknown_error";
    }
    return out;
}

bool external_pack_trust_ok(const PluginPackModinfo &info) {
    return info.ok && info.luajit_plugin_pack && !info.plugin_id.empty();
}

} // namespace ds::plugin
