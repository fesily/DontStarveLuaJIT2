// Client save write-back for GameJitModConfig projection (L0).
// Lives under config/write — load path is config/sources/*.
#include "gameModConfig.hpp"
#include "../../modinfo.hpp"
#include "plugins/plugin_render_angle/AngleOptionKeys.hpp"
#include "plugins/plugin_render_vbpool/VbpoolOptionKeys.hpp"
#include "util/PersistentString.hpp"

#include <cmath>
#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>

#include <spdlog/spdlog.h>
#include <sol/sol.hpp>

namespace {

static bool load_save_config_table(const std::filesystem::path &path, sol::state &lua, sol::table &root) {
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

static std::string escape_lua_string(std::string_view value) {
	std::string escaped;
	escaped.reserve(value.size() + 8);
	for (unsigned char ch : value) {
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
	for (const auto &[key, value] : table) {
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
	for (const auto &[key, value] : root) {
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

} // namespace

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
	if (auto it = config.business_options.find(std::string{ds::config::keys::kAngleBackend});
		it != config.business_options.end() && it->second.type == ds::plugin::ConfigValueType::String) {
		angle_backend = it->second.s;
	}
	auto angle_backend_opt = find_or_create_option(lua, root, ModConfigurationOptions::AngleBackend.name);
	angle_backend_opt["saved"] = angle_backend;
	angle_backend_opt["saved_client"] = angle_backend;

	// OB-S2: VM keys are owned by optional plugin_core_vm. When the cascade
	// view never carried them (has_vm_options=false), bag defaults are empty/
	// false and must not overwrite the user's save.
	if (config.has_vm_options) {
		auto lua_vm_type = find_or_create_option(lua, root, ModConfigurationOptions::LuaVmType.name);
		lua_vm_type["saved"] = config.LuaVmType;
		lua_vm_type["saved_client"] = config.LuaVmType;

		auto disable_jit_when_server =
			find_or_create_option(lua, root, ModConfigurationOptions::DisableJITWhenServer.name);
		disable_jit_when_server["saved"] = config.DisableJITWhenServer;
		disable_jit_when_server["saved_client"] = config.DisableJITWhenServer;

		auto enabled_gen_gc = find_or_create_option(lua, root, ModConfigurationOptions::EnabledGenGC.name);
		enabled_gen_gc["saved"] = config.EnabledGenGC;
		enabled_gen_gc["saved_client"] = config.EnabledGenGC;
	}

	auto always_enable_mod = find_or_create_option(lua, root, ModConfigurationOptions::AlwaysEnableMod.name);
	always_enable_mod["saved"] = config.AlwaysEnableMod;
	always_enable_mod["saved_client"] = config.AlwaysEnableMod;

	bool enable_vbpool = ModConfigurationOptions::EnableVBPool.default_value;
	if (auto it = config.business_options.find(std::string{ds::config::keys::kEnableVBPool});
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
		spdlog::error("failed to create mod config directory {}: {}", path.parent_path().string(),
					  ec.message());
		return false;
	}
	if (!SetPersistentString(path.string(), serialized_after, true)) {
		spdlog::error("failed to write mod configuration to {}", path.string());
		return false;
	}
	spdlog::info("updated mod configuration at {}", path.string());
	return true;
}
