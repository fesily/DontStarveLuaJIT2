#include <string>
#include <expected>

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include "util/platform.hpp"
#include "config.hpp"
#include "DontStarveSignature.hpp"

std::string update_signatures(Signatures &signatures, uintptr_t targetLuaModuleBase, const ListExports_t &exports, uint32_t range, bool updated)
{
	module_handler_t h51 = loadlib(lua51_name);
	spdlog::warn("try fix all signatures");
	auto &funcs = signatures.funcs;
	// fix all signatures
	for (size_t i = 0; i < exports.size(); i++)
	{
		auto &[name, _] = exports[i];
		auto original = loadlibproc(h51, name.c_str());
		auto old_offset = GPOINTER_TO_INT(funcs.at(name));
		spdlog::info("try fix signature [{}]: {}", name, old_offset);
		void *target = GSIZE_TO_POINTER(targetLuaModuleBase + old_offset);
		auto target1 = fix_func_address_by_signature(target, original, nullptr, range, updated);
		if (!target1)
		{
			auto msg = std::format("func[{}] can't fix address, wait for mod update", name);
			spdlog::error(msg);
			unloadlib(h51);
			return msg;
		}
		if (target1 == target)
			continue;
		auto new_offset = (intptr_t)target1 - (intptr_t)targetLuaModuleBase;
		spdlog::info("update signatures [{}]: {} to {}", name, old_offset, new_offset);
		funcs[name] = new_offset;
	}
	release_signature_cache();
	unloadlib(h51);
	return {};
}
