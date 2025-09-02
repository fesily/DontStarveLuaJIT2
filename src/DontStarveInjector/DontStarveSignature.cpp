#include <string>
#include <expected>
#include <algorithm>
#include <future>
#include <coroutine>

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include "util/platform.hpp"
#include "config.hpp"
#include "DontStarveSignature.hpp"

#include "MemorySignature.hpp"
#include "ctx.hpp"
#include "ModuleSections.hpp"
#include "Signature.hpp"
#include "SignatureJson.hpp"
#include "../missfunc.h"
#include "range/v3/range/conversion.hpp"
#include "ExectuableSignature.hpp"
#include "util/gum_platform.hpp"

#include <ranges>
#include "util/inlinehook.hpp"
#include "Progress.hpp"

using namespace std::literals;

static gboolean ListLuaFuncCb(const GumExportDetails *details,
                              void *user_data) {
constexpr auto only_base_api =
#ifdef __APPLE__
            //TODO: fix luaL_
            true;
#else
    false;
#endif
    if (details->type != GumExportType::GUM_EXPORT_FUNCTION) {
        return true;
    }
    const auto name = std::string_view{details->name};
    if (get_missfuncs().contains(name))
        return true;

    if (!(name.starts_with("lua_") || name.starts_with("luaL_") || name.starts_with("luaopen_")))
        return true;

    if (only_base_api && name.starts_with(("luaL_")))
        return true;

    auto &exports = *(ListExports_t *) user_data;
    exports.emplace_back(details->name, (GumAddress) details->address);
    return true;
}

static auto get_lua51_exports() {
    ListExports_t exports;
    auto m = gum_process_find_module_by_name(lua51_name);
    gum_module_enumerate_exports(m, ListLuaFuncCb, &exports);
    std::sort(exports.begin(), exports.end(), [](auto &l, auto &r) { return l.second > r.second; });
    return exports;
}

static std::expected<std::tuple<ListExports_t, Signatures>, std::string>
create_signature(uintptr_t targetLuaModuleBase, const std::function<void(const Signatures &)> &updated) {
    spdlog::warn("try create all signatures");
    auto exports = get_lua51_exports();
    Signatures signatures;
    for (auto &[name, address]: exports) {
        signatures.funcs[name] = {};
    }
    constexpr auto lua_module_range =
#ifdef _WIN32
            30720;
#else
#if defined(__APPLE__)
            0x21F79;
#else
    66820;
#endif
#endif
    auto errormsg = update_signatures_from_disasm(signatures, targetLuaModuleBase, exports, lua_module_range, false);
    if (!errormsg.empty()) {
        return std::unexpected(errormsg);
    }
    signatures.version = SignatureJson::current_version();
    updated(signatures);
    for (auto &[name, signature]: signatures.funcs) {
        spdlog::info("create signature [{}]: {}", name, signature.offset);
    }
    return std::make_tuple(std::move(exports), std::move(signatures));
}

static std::expected<ListExports_t, std::string>
get_signatures(Signatures &signatures, uintptr_t targetLuaModuleBase,
               const std::function<void(const Signatures &)> &updated) {
    auto &funcs = signatures.funcs;
    std::string errormsg;

    auto exports = get_lua51_exports();
    for (auto &[name, address]: exports) {
        if (!funcs.contains(name)) {
            errormsg += name + ";";
        }
    }
    if (!errormsg.empty()) {
        return std::unexpected(errormsg);
    }
    if (SignatureJson::current_version() != signatures.version) {
        spdlog::warn("try fix all signatures");
        errormsg = update_signatures_from_disasm(signatures, targetLuaModuleBase, exports);
        if (!errormsg.empty()) {
            return std::unexpected(errormsg);
        }
        signatures.version = SignatureJson::current_version();
        updated(signatures);
    }
    return exports;
}

std::expected<SignatureUpdater, std::string> SignatureUpdater::create(uintptr_t luaModuleBaseAddress) {
    SignatureUpdater updater;
    auto res = create_signature(luaModuleBaseAddress, [](auto &v) {});
    if (!res) {
        return std::unexpected(res.error());
    }
    updater.exports = std::move(std::get<0>(res.value()));
    updater.signatures = std::move(std::get<1>(res.value()));
    return updater;
}

std::expected<SignatureUpdater, std::string>
SignatureUpdater::create_or_update(bool isClient, uintptr_t luaModuleBaseAddress) {
    SignatureUpdater updater;
    SignatureJson json{isClient};
    auto signatures = json.read_from_signatures();
    if (!signatures) {
        auto res = create_signature(luaModuleBaseAddress, [&json](auto &v) { json.update_signatures(v); });
        if (!res) {
            return std::unexpected(res.error());
        }
        updater.exports = std::move(std::get<0>(res.value()));
        updater.signatures = std::move(std::get<1>(res.value()));
    } else {
        auto res = get_signatures(signatures.value(), luaModuleBaseAddress,
                                  [&json](auto &v) { json.update_signatures(v); });
        if (!res) {
            return std::unexpected(res.error());
        }
        updater.exports = std::move(res.value());
        updater.signatures = std::move(signatures.value());
    }
    return updater;
}

struct update_signatures_exception {
    explicit update_signatures_exception(const char* m) noexcept: msg{m} {};
    explicit update_signatures_exception(const std::string& m) noexcept: msg{m} {};
    std::string msg;
};


Generator<int> update_signatures(Signatures &signatures, uintptr_t targetLuaModuleBase, const ListExports_t &exports, uint32_t range,
                  bool updated) {
    const auto &lua51_path = get_module_path(lua51_name, 0);
    const auto &game_path = get_module_path(game_name, targetLuaModuleBase);
    function_relocation::ModuleSections modulelua51{}, moduleMain{};

#ifndef _WIN32
    auto fileSignature = function_relocation::FileSignature::read_file_signature(
            function_relocation::FileSignature::file_path);
    if (fileSignature)
        fileSignature->fix_ptr();
#endif
    if (!init_module_signature(lua51_path.c_str(), 0, modulelua51) ||
        !init_module_signature(game_path.c_str(), targetLuaModuleBase, moduleMain)
            ) {
                throw  update_signatures_exception{"init_module_signature failed!"};
            }

    auto lua51_module = gum_process_find_module_by_name(lua51_name);
#ifndef __APPLE__
    spdlog::info("lua51 module base address:{}", (void*)modulelua51.details.range.base_address);
    spdlog::info("game module base address:{}", (void*)moduleMain.details.range.base_address);
    //明确定位 index2adr
    moduleMain.set_known_function(targetLuaModuleBase, "index2adr");
    auto lua_type_fn = gum_module_find_export_by_name(lua51_module, "lua_type");
#if !defined(NDEBUG) && !defined(_WIN32)
    if (auto fn = modulelua51.find_function(lua_type_fn); fn && !fn->blocks.empty() &&
                                                          !fn->get_block(0)->call_functions.empty()) {
        const auto ptr = modulelua51.find_function(lua_type_fn)->get_block(0)->call_functions[0];
        assert(modulelua51.address_functions.contains(ptr) && modulelua51.address_functions[ptr]->name == "index2adr");
    }
#endif
#endif

    set_progress(0, "Find all export functions...");
    co_yield 0;
    for (size_t i = 0; i < exports.size(); i++) {
        auto &[name, _] = exports[i];
        auto original = (void *) gum_module_find_export_by_name(lua51_module, name.c_str());

#ifdef _WIN32
        original = format_address((uint8_t *) original);
#endif
        if (original == nullptr || !modulelua51.find_function((uintptr_t) original)) {
            throw update_signatures_exception{fmt::format("can't find address: {}", name)};
        }
        modulelua51.set_known_function((uintptr_t) original, name.c_str());
        auto originalFunc = modulelua51.find_function((uintptr_t) original);
        if (!originalFunc) {
            throw update_signatures_exception{fmt::format("can't find {} at module lua51", name)};
        }
    }
    set_progress(1, "");
    co_yield 1;

    auto &funcs = signatures.funcs;
    // fix all signatures
    for (size_t i = 0; i < exports.size(); i++) {
        auto &[name, _] = exports[i];
        auto originalFunc = modulelua51.known_functions.at(name.c_str());
        set_progress(1, "patch:" + name);
        co_yield 1;

        auto &signature = funcs.at(name);
        auto old_offset = GPOINTER_TO_INT(signature.offset);
        if (old_offset == 0)
            spdlog::info("try create signature [{}]", name);
        else
            spdlog::info("try fix signature [{}]: {}", name, old_offset);

        auto maybe_target = targetLuaModuleBase + old_offset;

        uintptr_t target = 0;
        if (!updated && !signature.pattern.empty()) {
            function_relocation::MemorySignature scan{signature.pattern.c_str(), signature.pattern_offset, false};
            if (scan.targets.size() == 1) {
                target = scan.target_address;
            } else {
                const auto targets = scan.targets | std::ranges::views::filter(
                        [targetLuaModuleBase](auto addr) { return addr > targetLuaModuleBase; }) |
                                     ranges::to<std::vector>();
                if (targets.size() == 1) {
                    target = scan.scan(moduleMain.details.path.c_str());
                }
            }
        }
#ifndef _WIN32
        if (target == 0 || target < targetLuaModuleBase) {
            if (fileSignature) {
                auto iter = fileSignature->section.known_functions.find(name);
                if (iter != fileSignature->section.known_functions.end()) {
                    auto fn = iter->second;
                    target = moduleMain.try_fix_func_address(*fn, &signature, targetLuaModuleBase);
                }
            }
        }
#endif
        if (target == 0 || target < targetLuaModuleBase)
            target = moduleMain.try_fix_func_address(*originalFunc,
                                                     &signature, targetLuaModuleBase);

        if (!target || target < targetLuaModuleBase) {
            throw update_signatures_exception{fmt::format("func[{}] can't fix address, wait for mod update", name)};
        }
        if (target == maybe_target)
            continue;
        // fix the offset by module
        if (moduleMain.find_function(target) == nullptr) {
            spdlog::info("can't find function at address: {}", (void *) target);
            auto all_address =
                    moduleMain.address_functions | std::ranges::views::transform([](auto &p) { return p.first; }) |
                    ranges::to<std::vector>();
            std::ranges::sort(all_address);
            auto pattern_address = target - signature.pattern_offset;
            auto iter = std::ranges::adjacent_find(all_address,
                                                   [pattern_address](auto l, auto r) {
                                                       return l <= pattern_address && pattern_address < r;
                                                   });
            if (iter == all_address.end()) {
                throw update_signatures_exception{fmt::format("func[{}] can't find the real address", name)};
            }
            const auto fn = moduleMain.find_function(*iter);
            target = fn->address;
            auto pattern_offset = (intptr_t) target - (intptr_t) pattern_address;
            spdlog::info("refix signature pattern offset: [{}]->[{}]", signature.pattern_offset, pattern_offset);
            signature.pattern_offset = pattern_offset;
        }
        auto new_offset = target - targetLuaModuleBase;
        spdlog::info("update signatures [{}:{}]: {} to {}", name, (void *) target, old_offset, new_offset);
        signature.offset = new_offset;
    }
    function_relocation::release_signature_cache();
    co_return;
}

std::string
update_signatures_from_disasm(Signatures &signatures, uintptr_t targetLuaModuleBase, const ListExports_t &exports, uint32_t range,
                  bool updated) {
    try
    {
        auto gen = update_signatures(signatures, targetLuaModuleBase, exports, range, updated);
        if (InjectorConfig::instance().disable_progress || !InjectorConfig::instance().DontStarveInjectorIsClient) {
            NoShowProgressWindow(0, gen);
        } else {
            ShowProgressWindow(exports.size() + 1, gen);
        }
    }
    catch(const update_signatures_exception& e)
    {
        return e.msg;
    }
   return "";
}