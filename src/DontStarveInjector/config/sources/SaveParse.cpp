#include "SaveParse.hpp"

#include "util/PersistentString.hpp"

#include <cmath>
#include <fstream>
#include <spdlog/spdlog.h>
#include <sol/sol.hpp>

namespace ds::config::save_parse {
namespace {

bool is_nil_object(const sol::object &object) {
    return !object.valid() || object.get_type() == sol::type::lua_nil;
}

sol::object get_saved_value(const sol::table &option) {
    auto saved_client = option["saved_client"].get<sol::object>();
    if (!is_nil_object(saved_client)) {
        return saved_client;
    }
    return option["saved"].get<sol::object>();
}

bool try_coerce_saved_value(const sol::object &raw, const ds::plugin::OptionSchemaEntry &schema,
                            ds::plugin::ConfigValue &out) {
    if (!raw.valid() || raw.get_type() == sol::type::lua_nil) {
        return false;
    }
    switch (raw.get_type()) {
    case sol::type::boolean:
        return ds::plugin::TryCoerceSavedBool(raw.as<bool>(), schema, out);
    case sol::type::number: {
        const double numeric = raw.as<double>();
        if (schema.type == ds::plugin::ConfigValueType::String && !schema.allowed.empty() &&
            std::floor(numeric) == numeric) {
            const auto index = static_cast<long long>(numeric);
            if (index >= 0 && index < static_cast<long long>(schema.allowed.size())) {
                return ds::plugin::TryCoerceSavedString(schema.allowed[static_cast<size_t>(index)],
                                                        schema, out);
            }
            return false;
        }
        return ds::plugin::TryCoerceSavedNumber(numeric, schema, out);
    }
    case sol::type::string:
        return ds::plugin::TryCoerceSavedString(raw.as<std::string>(), schema, out);
    default:
        return false;
    }
}

bool load_save_config_table(const std::filesystem::path &path, sol::state &lua, sol::table &root) {
    const auto persistent_string = GetPersistentString(path.string());
    if (!persistent_string) {
        spdlog::error("failed to load mod configuration from {}: {}", path.string(),
                      persistent_string.error());
        return false;
    }
    try {
        auto config = lua.safe_script(persistent_string.value());
        if (config.get_type() != sol::type::table) {
            spdlog::warn("mod configuration at {} is not a table", path.string());
            return false;
        }
        root = config;
        return true;
    } catch (const std::exception &e) {
        spdlog::error("failed to parse mod configuration from {}: {}", path.string(), e.what());
        return false;
    }
}

bool load_plain_lua_table(const std::filesystem::path &path, sol::state &lua, sol::table &root) {
    std::ifstream file(path);
    if (!file.is_open()) {
        spdlog::error("failed to open lua table file {}", path.string());
        return false;
    }
    const std::string content{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
    try {
        auto config = lua.safe_script(content);
        if (config.get_type() != sol::type::table) {
            spdlog::warn("lua table file at {} is not a table", path.string());
            return false;
        }
        root = config;
        return true;
    } catch (const std::exception &e) {
        spdlog::error("failed to parse lua table file {}: {}", path.string(), e.what());
        return false;
    }
}

bool find_mod_override_entry(const sol::table &root, const std::vector<std::string> &aliases,
                             sol::table &entry) {
    for (const auto &alias : aliases) {
        auto object = root[alias].get<sol::object>();
        if (is_nil_object(object) || object.get_type() != sol::type::table) {
            continue;
        }
        entry = object.as<sol::table>();
        spdlog::info("matched server mod overrides entry by alias {}", alias);
        return true;
    }
    return false;
}

} // namespace

bool read_save_file(const std::filesystem::path &path,
                    const ds::plugin::ConfigSchemaRegistry &schema,
                    ds::plugin::ConfigView &out) {
    sol::state lua;
    sol::table root = lua.create_table();
    if (!load_save_config_table(path, lua, root)) {
        return false;
    }
    for (const auto &[key, value] : root) {
        if (value.get_type() != sol::type::table) {
            continue;
        }
        auto option = value.as<sol::table>();
        const auto option_name = option["name"].get_or<std::string>("");
        if (option_name.empty()) {
            continue;
        }
        const auto *sch = schema.find(option_name);
        if (!sch) {
            continue;
        }
        const auto saved_value = get_saved_value(option);
        if (is_nil_object(saved_value)) {
            continue;
        }
        ds::plugin::ConfigValue v;
        if (!try_coerce_saved_value(saved_value, *sch, v)) {
            spdlog::error("invalid value for option {}", option_name);
            continue;
        }
        out[option_name] = std::move(v);
    }
    return true;
}

bool read_modoverrides(const std::filesystem::path &path,
                       const std::vector<std::string> &aliases,
                       const ds::plugin::ConfigSchemaRegistry &schema,
                       ds::plugin::ConfigView &out) {
    sol::state lua;
    sol::table root = lua.create_table();
    if (!load_plain_lua_table(path, lua, root)) {
        return false;
    }
    sol::table mod_entry = lua.create_table();
    if (!find_mod_override_entry(root, aliases, mod_entry)) {
        spdlog::warn("no matching mod entry found in server mod overrides {}", path.string());
        return false;
    }
    auto options_object = mod_entry["configuration_options"].get<sol::object>();
    if (is_nil_object(options_object) || options_object.get_type() != sol::type::table) {
        spdlog::warn("server mod overrides entry at {} has no configuration_options table",
                     path.string());
        return true;
    }
    auto options = options_object.as<sol::table>();
    for (const auto &[key, value] : options) {
        if (key.get_type() != sol::type::string) {
            continue;
        }
        const auto option_name = key.as<std::string>();
        const auto *sch = schema.find(option_name);
        if (!sch) {
            continue;
        }
        sol::object raw = value;
        if (value.get_type() == sol::type::table) {
            raw = get_saved_value(value.as<sol::table>());
        }
        if (is_nil_object(raw)) {
            continue;
        }
        ds::plugin::ConfigValue v;
        if (!try_coerce_saved_value(raw, *sch, v)) {
            spdlog::error("invalid value for option {}", option_name);
            continue;
        }
        out[option_name] = std::move(v);
    }
    return true;
}

} // namespace ds::config::save_parse
