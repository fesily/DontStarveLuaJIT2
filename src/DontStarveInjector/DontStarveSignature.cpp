#include <string>
#include <expected>

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include "util/platform.hpp"
#include "config.hpp"
#include "DontStarveSignature.hpp"
#include "SignatureJson.hpp"
#include "../missfunc.h"

static gboolean ListLuaFuncCb(const GumExportDetails *details,
							  void *user_data)
{
	if (details->type != _GumExportType::GUM_EXPORT_FUNCTION || missfuncs.find(details->name) != missfuncs.end())
	{
		return true;
	}
	if (!std::string_view(details->name).starts_with("lua"))
		return true;
#if USE_GAME_IO
	if (details->name == "luaL_openlibs"sv || details->name == "luaopen_io"sv)
	{
		return true;
	}
#endif
	auto &exports = *(ListExports_t *)user_data;
	exports.emplace_back(details->name, (GumAddress)details->address);
	return true;
}

static auto get_lua51_exports()
{
	ListExports_t exports;
	gum_module_enumerate_exports(lua51_name, ListLuaFuncCb, &exports);
	std::sort(exports.begin(), exports.end(), [](auto &l, auto &r)
			  { return l.second > r.second; });
	return exports;
}

static std::expected<std::tuple<ListExports_t, Signatures>, std::string>
create_signature(uintptr_t targetLuaModuleBase, const std::function<void(const Signatures &)> &updated)
{
	spdlog::warn("try create all signatures");
	auto exports = get_lua51_exports();
	Signatures signatures;
	for (auto &[name, address] : exports)
	{
		signatures.funcs[name] = 0;
	}
	constexpr auto lua_module_range =
#ifdef _WIN32
		30720;
#else
		66820;
#endif
	auto errormsg = update_signatures(signatures, targetLuaModuleBase, exports, lua_module_range, false);
	if (!errormsg.empty())
	{
		return std::unexpected(errormsg);
	}
	signatures.version = SignatureJson::current_version();
	updated(signatures);
	for (auto &[name, offset] : signatures.funcs)
	{
		spdlog::info("create signature [{}]: {}", name, offset);
	}
	return std::make_tuple(std::move(exports), std::move(signatures));
}

static std::expected<ListExports_t, std::string>
get_signatures(Signatures &signatures, uintptr_t targetLuaModuleBase, const std::function<void(const Signatures &)> &updated)
{
	auto &funcs = signatures.funcs;
	std::string errormsg;

	auto exports = get_lua51_exports();
	for (auto &[name, address] : exports)
	{
		if (!funcs.contains(name))
		{
			errormsg += name + ";";
		}
	}
	if (!errormsg.empty())
	{
		return std::unexpected(errormsg);
	}
	if (SignatureJson::current_version() != signatures.version)
	{
		errormsg = update_signatures(signatures, targetLuaModuleBase, exports);
		if (!errormsg.empty())
		{
			return std::unexpected(errormsg);
		}
		signatures.version = SignatureJson::current_version();
		updated(signatures);
	}
	return exports;
}

std::expected<SignatureUpdater, std::string> SignatureUpdater::create(bool isClient, uintptr_t luaModuleBaseAddress)
{
	SignatureUpdater updater;
	SignatureJson json(isClient);
	auto signatures = json.read_from_signatures();
	if (!signatures)
	{
		auto res = create_signature(luaModuleBaseAddress, [&json](auto &v)
									{ json.update_signatures(v); });
		if (!res)
		{
			return std::unexpected(res.error());
		}
		updater.exports = std::move(std::get<0>(res.value()));
		updater.signatures = std::move(std::get<1>(res.value()));
	}
	else
	{
		auto res = get_signatures(signatures.value(), luaModuleBaseAddress, [&json](auto &v)
								  { json.update_signatures(v); });
		if (!res)
		{
			return std::unexpected(res.error());
		}
		updater.exports = std::move(res.value());
		updater.signatures = std::move(signatures.value());
	}
	return updater;
}

static const std::string &get_lua51_path()
{
	static std::string path = []()
	{
		std::string res;
		gum_process_enumerate_modules(
			+[](const GumModuleDetails *details,
				gpointer user_data) -> gboolean
			{
				if (details->name == std::string_view(lua51_name))
				{
					auto r = (std::string *)user_data;
					*r = details->path;
					return false;
				}
				return true;
			},
			&res);
		return res;
	}();
	return path;
}

std::string update_signatures(Signatures &signatures, uintptr_t targetLuaModuleBase, const ListExports_t &exports, uint32_t range, bool updated)
{
	const auto &lua51_path = get_lua51_path();
	spdlog::warn("try fix all signatures");
	const auto luaModuleSignatures = create_signature(
		(void*)targetLuaModuleBase, [limit = targetLuaModuleBase + range](void *address)
		{ return address <= (void  *)limit; },
		range);
	auto &funcs = signatures.funcs;
	// fix all signatures
	for (size_t i = 0; i < exports.size(); i++)
	{
		auto &[name, _] = exports[i];
		auto original = (void *)gum_module_find_export_by_name(lua51_path.c_str(), name.c_str());
		if (original == nullptr)
		{
			return std::format("can't find address: {}", name.c_str());
		}
		auto old_offset = GPOINTER_TO_INT(funcs.at(name));
		spdlog::info("try fix signature [{}]: {}", name, old_offset);
		void *target = GSIZE_TO_POINTER(targetLuaModuleBase + old_offset);
		auto target1 = fix_func_address_by_signature(target, original, nullptr, range, updated);
		if (!target1)
		{
			return std::format("func[{}] can't fix address, wait for mod update", name);
			;
		}
		if (target1 == target)
			continue;
		auto new_offset = (intptr_t)target1 - (intptr_t)targetLuaModuleBase;
		spdlog::info("update signatures [{}]: {} to {}", name, old_offset, new_offset);
		funcs[name] = new_offset;
	}
	release_signature_cache();
	return {};
}
