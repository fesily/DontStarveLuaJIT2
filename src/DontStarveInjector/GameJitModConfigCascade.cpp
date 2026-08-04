// GameJitModConfig cascade loaders (L0). Split from GameLuaModule so core.vm can own luaopen.
#include "gameModConfig.hpp"
#include "config.hpp"
#include "config/ConfigSchema.hpp"
#include "config/CascadeEngine.hpp"
#include "core/PluginConfigBridge.hpp"
#include "core/PluginTypes.hpp"
#include "config/sources/LuajitConfigFile.hpp"

#include <cmath>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <spdlog/spdlog.h>
#include <sol/sol.hpp>
#include "util/PersistentString.hpp"

#include "../modinfo.hpp"

namespace {

// Schema used by cascade save/overrides parse (core + builtin business keys).
// Host plugins re-register the business keys later for BuildConfigView.
const ds::plugin::ConfigSchemaRegistry &cascade_option_schema() {
	static const ds::plugin::ConfigSchemaRegistry schema = [] {
		ds::plugin::ConfigSchemaRegistry r;
		ds::plugin::RegisterCoreOptionSchema(r);
		ds::plugin::RegisterBuiltinBusinessOptionSchema(r);
		return r;
	}();
	return schema;
}

// Apply a coerced schema value into GameJitModConfig (core fields or business map).
void apply_schema_value_to_config(const std::string &name, const ds::plugin::ConfigValue &v,
								  GameJitModConfig &resolved, GameJitConfigSource source) {
	if (name == ModConfigurationOptions::AlwaysEnableMod.name) {
		if (v.type == ds::plugin::ConfigValueType::Bool) {
			resolved.AlwaysEnableMod = v.b;
			resolved.AlwaysEnableModSource = source;
		}
		return;
	}
	if (name == ModConfigurationOptions::DisableJITWhenServer.name) {
		if (v.type == ds::plugin::ConfigValueType::Bool) {
			resolved.DisableJITWhenServer = v.b;
			resolved.DisableJITWhenServerSource = source;
		}
		return;
	}
	if (name == ModConfigurationOptions::LuaVmType.name) {
		if (v.type == ds::plugin::ConfigValueType::String) {
			resolved.LuaVmType = v.s;
			resolved.LuaVmTypeSource = source;
		}
		return;
	}
	if (name == ModConfigurationOptions::EnabledGenGC.name) {
		if (v.type == ds::plugin::ConfigValueType::Bool) {
			resolved.EnabledGenGC = v.b;
			resolved.EnabledGenGCSource = source;
		}
		return;
	}
	// Business / plugin-owned keys: whitelist via shared apply_partial (CF-S1).
	ds::plugin::ConfigView partial;
	partial[name] = v;
	std::unordered_map<std::string, ds::config::ConfigSource> prov;
	(void)ds::config::apply_partial(cascade_option_schema(),
									ds::config::ConfigSource::SaveFile, partial,
									resolved.business_options, prov);
}

// sol::object → ConfigValue via pure schema coerce helpers (C-S6).
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
		// String options in modoverrides may store the 0-based index into allowed.
		if (schema.type == ds::plugin::ConfigValueType::String && !schema.allowed.empty() &&
			std::floor(numeric) == numeric) {
			const auto index = static_cast<long long>(numeric);
			if (index >= 0 && index < static_cast<long long>(schema.allowed.size())) {
				return ds::plugin::TryCoerceSavedString(schema.allowed[static_cast<size_t>(index)], schema, out);
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
} // namespace

GameJitModConfig make_default_game_mod_config() {
    GameJitModConfig resolved;
    resolved.LuaVmType = std::string{ModConfigurationOptions::LuaVmType.default_value};
    resolved.AlwaysEnableMod = ModConfigurationOptions::AlwaysEnableMod.default_value;
    resolved.DisableJITWhenServer = ModConfigurationOptions::DisableJITWhenServer.default_value;

    // Business defaults live in plugin schema / ConfigView, not core struct.
    // Seed known business keys so write-back and early consumers have a value.
    resolved.business_options["AngleBackend"] =
            ds::plugin::ConfigValue::string(std::string{ModConfigurationOptions::AngleBackend.default_value});
    resolved.business_options["EnableVBPool"] =
            ds::plugin::ConfigValue::boolean(ModConfigurationOptions::EnableVBPool.default_value);

    resolved.LuaVmTypeSource = GameJitConfigSource::modinfo_default;
    resolved.AlwaysEnableModSource = GameJitConfigSource::modinfo_default;
    resolved.DisableJITWhenServerSource = GameJitConfigSource::modinfo_default;
    return resolved;
}

using namespace std::string_view_literals;

static bool is_supported_lua_vm_type(std::string_view value) {
	return value == "jit"sv || value == "game"sv || value == "lua51"sv || value == "51"sv || value == "5.1"sv ||
		   value == "jit_gen"sv || value == "_51"sv;
}


static bool is_nil_object(const sol::object &object) {
	return !object.valid() || object.get_type() == sol::type::lua_nil;
}

// try_get_string/bool/option_string removed: save/overrides use try_coerce_saved_value.


static sol::object get_saved_value(const sol::table &option) {
	auto saved_client = option["saved_client"].get<sol::object>();
	if (!is_nil_object(saved_client)) {
		return saved_client;
	}
	return option["saved"].get<sol::object>();
}

static bool load_save_config_table(const std::filesystem::path &path, sol::state &lua, sol::table &root) {
	const auto persistent_string = GetPersistentString(path.string());
	if (!persistent_string) {
		spdlog::error("failed to load mod configuration from {}: {}", path.string(), persistent_string.error());
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

static bool load_plain_lua_table(const std::filesystem::path &path, sol::state &lua, sol::table &root) {
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

static std::string escape_lua_string(std::string_view value) {
	std::string escaped;
	escaped.reserve(value.size() + 8);
	for (unsigned char ch: value) {
		switch (ch) {
		case '\\':
			escaped += "\\\\";
			break;
		case '"':
			escaped += "\\\"";
			break;
		case '\n':
			escaped += "\\n";
			break;
		case '\r':
			escaped += "\\r";
			break;
		case '\t':
			escaped += "\\t";
			break;
		default:
			escaped.push_back(static_cast<char>(ch));
			break;
		}
	}
	return escaped;
}

static std::string serialize_lua_value(const sol::object &value, int indent);

static std::string serialize_lua_key(const sol::object &key) {
	if (key.get_type() == sol::type::string) {
		return std::string{"[\""}.append(escape_lua_string(key.as<std::string>())).append("\"]");
	}
	if (key.get_type() == sol::type::number) {
		auto number = key.as<double>();
		if (std::floor(number) == number) {
			return std::string{"["}.append(std::to_string(static_cast<long long>(number))).append("]");
		}
		std::ostringstream stream;
		stream << std::setprecision(17) << number;
		return std::string{"["}.append(stream.str()).append("]");
	}
	return std::string{"["}.append(serialize_lua_value(key, 0)).append("]");
}

static std::string serialize_lua_table(const sol::table &table, int indent) {
	const auto indent_text = std::string(static_cast<size_t>(indent * 4), ' ');
	const auto child_indent_text = std::string(static_cast<size_t>((indent + 1) * 4), ' ');

	std::string serialized{"{"};
	bool first = true;
	for (const auto &[key, value]: table) {
		if (first) {
			serialized.push_back('\n');
			first = false;
		} else {
			serialized += ",\n";
		}
		serialized += child_indent_text;
		serialized += serialize_lua_key(key);
		serialized += " = ";
		serialized += serialize_lua_value(value, indent + 1);
	}
	if (!first) {
		serialized.push_back('\n');
		serialized += indent_text;
	}
	serialized.push_back('}');
	return serialized;
}

static std::string serialize_lua_value(const sol::object &value, int indent) {
	switch (value.get_type()) {
	case sol::type::lua_nil:
		return "nil";
	case sol::type::boolean:
		return value.as<bool>() ? "true" : "false";
	case sol::type::number: {
		const auto number = value.as<double>();
		if (std::floor(number) == number) {
			return std::to_string(static_cast<long long>(number));
		}
		std::ostringstream stream;
		stream << std::setprecision(17) << number;
		return stream.str();
	}
	case sol::type::string:
		return std::string{"\""}.append(escape_lua_string(value.as<std::string>())).append("\"");
	case sol::type::table:
		return serialize_lua_table(value.as<sol::table>(), indent);
	default:
		return "nil";
	}
}

static std::string serialize_lua_chunk(const sol::object &value) {
	return std::string{"return "}.append(serialize_lua_value(value, 0));
}

static sol::table find_or_create_option(sol::state &lua, sol::table root, std::string_view option_name) {
	lua_Integer next_index = 1;
	for (const auto &[key, value]: root) {
		if (key.get_type() == sol::type::number) {
			next_index = std::max(next_index, static_cast<lua_Integer>(key.as<double>()) + 1);
		}
		if (value.get_type() != sol::type::table) {
			continue;
		}
		auto option = value.as<sol::table>();
		if (option["name"].get_or<std::string>("") == option_name) {
			return option;
		}
	}

	auto option = lua.create_table();
	option["name"] = std::string{option_name};
	root[next_index] = option;
	return option;
}

static bool find_mod_override_entry(const sol::table &root, const std::vector<std::string> &aliases, sol::table &entry) {
	for (const auto &alias: aliases) {
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

bool LoadGameJitModConfigFromSaveFile(const std::filesystem::path &path, GameJitModConfig &resolved) {
	sol::state lua;
	sol::table root = lua.create_table();
	if (!load_save_config_table(path, lua, root)) {
		return false;
	}

	const auto &schema = cascade_option_schema();
	for (const auto &[key, value]: root) {
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
			// Unknown keys ignored (C-S6).
			continue;
		}
		const auto saved_value = get_saved_value(option);
		if (is_nil_object(saved_value)) {
			// Absent/nil saved value: keep prior/default, do not error-log.
			continue;
		}
		ds::plugin::ConfigValue v;
		if (!try_coerce_saved_value(saved_value, *sch, v)) {
			spdlog::error("invalid value for option {}", option_name);
			continue; // keep prior/default
		}
		apply_schema_value_to_config(option_name, v, resolved, GameJitConfigSource::save_file);
	}
	return true;
}

bool LoadGameJitModConfigFromModOverridesFile(const std::filesystem::path &path,
									  const std::vector<std::string> &aliases,
									  GameJitModConfig &resolved) {
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
		spdlog::warn("server mod overrides entry at {} has no configuration_options table", path.string());
		return true;
	}

	auto options = options_object.as<sol::table>();
	const auto &schema = cascade_option_schema();
	for (const auto &[key, value]: options) {
		if (key.get_type() != sol::type::string) {
			continue;
		}
		const auto option_name = key.as<std::string>();
		const auto *sch = schema.find(option_name);
		if (!sch) {
			// Unknown keys ignored (C-S6).
			continue;
		}
		// configuration_options values may be scalars or {saved=...} tables.
		sol::object raw = value;
		if (value.get_type() == sol::type::table) {
			raw = get_saved_value(value.as<sol::table>());
		}
		if (is_nil_object(raw)) {
			// Absent/nil saved value: keep prior/default, do not error-log.
			continue;
		}
		ds::plugin::ConfigValue v;
		if (!try_coerce_saved_value(raw, *sch, v)) {
			spdlog::error("invalid value for option {}", option_name);
			continue; // keep prior/default
		}
		apply_schema_value_to_config(option_name, v, resolved, GameJitConfigSource::save_file);
	}
	return true;
}

bool WriteGameJitModConfigToSaveFile(const std::filesystem::path &path, const GameJitModConfig &config) {
	sol::state lua;
	sol::table root = lua.create_table();
	std::string serialized_before = "return {}";
	if (std::filesystem::exists(path)) {
		if (!load_save_config_table(path, lua, root)) {
			return false;
		}
		serialized_before = serialize_lua_chunk(sol::make_object(lua, root));
	}

	std::string angle_backend{ModConfigurationOptions::AngleBackend.default_value};
	if (auto it = config.business_options.find("AngleBackend");
	    it != config.business_options.end() && it->second.type == ds::plugin::ConfigValueType::String) {
		angle_backend = it->second.s;
	}
	auto angle_backend_opt = find_or_create_option(lua, root, ModConfigurationOptions::AngleBackend.name);
	angle_backend_opt["saved"] = angle_backend;
	angle_backend_opt["saved_client"] = angle_backend;

	auto lua_vm_type = find_or_create_option(lua, root, ModConfigurationOptions::LuaVmType.name);
	lua_vm_type["saved"] = config.LuaVmType;
	lua_vm_type["saved_client"] = config.LuaVmType;

	auto always_enable_mod = find_or_create_option(lua, root, ModConfigurationOptions::AlwaysEnableMod.name);
	always_enable_mod["saved"] = config.AlwaysEnableMod;
	always_enable_mod["saved_client"] = config.AlwaysEnableMod;

	auto disable_jit_when_server = find_or_create_option(lua, root, ModConfigurationOptions::DisableJITWhenServer.name);
	disable_jit_when_server["saved"] = config.DisableJITWhenServer;
	disable_jit_when_server["saved_client"] = config.DisableJITWhenServer;

	auto enabled_gen_gc = find_or_create_option(lua, root, ModConfigurationOptions::EnabledGenGC.name);
	enabled_gen_gc["saved"] = config.EnabledGenGC;
	enabled_gen_gc["saved_client"] = config.EnabledGenGC;

	bool enable_vbpool = ModConfigurationOptions::EnableVBPool.default_value;
	if (auto it = config.business_options.find("EnableVBPool");
	    it != config.business_options.end() && it->second.type == ds::plugin::ConfigValueType::Bool) {
		enable_vbpool = it->second.b;
	}
	auto enable_vbpool_opt = find_or_create_option(lua, root, ModConfigurationOptions::EnableVBPool.name);
	enable_vbpool_opt["saved"] = enable_vbpool;
	enable_vbpool_opt["saved_client"] = enable_vbpool;

	const auto serialized_after = serialize_lua_chunk(sol::make_object(lua, root));
	if (serialized_before == serialized_after) {
		return true;
	}

	std::error_code ec;
	std::filesystem::create_directories(path.parent_path(), ec);
	if (ec) {
		spdlog::error("failed to create mod config directory {}: {}", path.parent_path().string(), ec.message());
		return false;
	}
	if (!SetPersistentString(path.string(), serialized_after, true)) {
		spdlog::error("failed to write mod configuration to {}", path.string());
		return false;
	}
	spdlog::info("updated mod configuration at {}", path.string());
	return true;
}
