#include <string>
#include <expected>
#include <algorithm>
#include <future>
#include <coroutine>
#include <unordered_set>
#include <vector>

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include "util/platform.hpp"
#include "config/InjectorHostConfig.hpp"
#include "DontStarveSignature.hpp"

#include "MemorySignature.hpp"
#include "ctx.hpp"
#include "ModuleSections.hpp"
#include "FunctionRanges.hpp"
#include "Signature.hpp"
#include "SignatureJson.hpp"
#include "NucleusAdapter.hpp"
#include "disasm.h"
#include "missfunc.h"
#include "range/v3/range/conversion.hpp"
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
    auto exports = get_lua51_exports();

    // Stale signature DBs (or a richer lua51.dll export set) must refresh —
    // do not showError with a raw "name;name;..." list and abort the game.
    bool need_update = SignatureJson::current_version() != signatures.version;
    for (auto &[name, address] : exports) {
        (void)address;
        if (!funcs.contains(name)) {
            funcs[name] = {};
            need_update = true;
            spdlog::warn("signature DB missing export {}; will refresh", name);
        }
    }

    if (need_update) {
        spdlog::warn("try fix all signatures (version and/or export set changed)");
        auto errormsg =
            update_signatures_from_disasm(signatures, targetLuaModuleBase, exports);
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
SignatureUpdater::create_or_update(bool isClient, uintptr_t luaModuleBaseAddress,
                                   std::string signatures_path) {
    SignatureUpdater updater;
    SignatureJson json{isClient};
    if (!signatures_path.empty()) {
        json.file_path = std::move(signatures_path);
    }
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

    // Phase 1: section ranges + symbol names only (no heuristic function starts).
    if (!init_module_signature(lua51_path.c_str(), 0, modulelua51) ||
        !init_module_signature(game_path.c_str(), targetLuaModuleBase, moduleMain)
            ) {
                throw  update_signatures_exception{"init_module_signature failed!"};
            }

    // Phase 2: Nucleus is sole start|end|size authority (export split only inside
    // nucleus_analyze_file for real SYM_TYPE_FUNC). No ScanCtx table cuts.
    {
        auto train_nt = function_relocation::nucleus_analyze_file(lua51_path);
        if (!train_nt) {
            throw update_signatures_exception{
                    fmt::format("nucleus_analyze_file(lua51) failed: {}", train_nt.error())};
        }
        if (!function_relocation::apply_nucleus_function_table(modulelua51, train_nt->table,
                                                              train_nt->image_base)) {
            throw update_signatures_exception{"apply_nucleus_function_table(lua51) failed"};
        }

        auto target_nt = function_relocation::nucleus_analyze_file(game_path);
        if (!target_nt) {
            throw update_signatures_exception{
                    fmt::format("nucleus_analyze_file(game) failed: {}", target_nt.error())};
        }
        if (!function_relocation::apply_nucleus_function_table(moduleMain, target_nt->table,
                                                              target_nt->image_base)) {
            throw update_signatures_exception{"apply_nucleus_function_table(game) failed"};
        }

        // Phase 3: disasm each Nucleus body for soft-match features.
        if (!function_relocation::scan_module_function_features(modulelua51) ||
            !function_relocation::scan_module_function_features(moduleMain)) {
            throw update_signatures_exception{"scan_module_function_features failed"};
        }

        // Optional pdata cross-check (log only; Nucleus remains authority).
        {
            std::vector<function_relocation::FuncRange> pdata_ranges;
            if (function_relocation::enumerate_function_ranges_win(moduleMain, pdata_ranges)) {
                size_t compared = 0;
                size_t mismatches = 0;
                for (const auto &sp: moduleMain.function_table.spans()) {
                    const function_relocation::FuncRange *hit = nullptr;
                    size_t hits = 0;
                    for (const auto &pr: pdata_ranges) {
                        if (pr.start <= sp.start && sp.start < pr.end) {
                            hit = &pr;
                            ++hits;
                        }
                    }
                    if (hits != 1 || hit == nullptr) {
                        continue;
                    }
                    ++compared;
                    if (hit->end != sp.end) {
                        ++mismatches;
                        const auto delta = static_cast<intptr_t>(hit->end) -
                                           static_cast<intptr_t>(sp.end);
                        if (delta >= 0x20 || delta <= -0x20) {
                            spdlog::warn(
                                    "pdata/nucleus end mismatch start={} nucleus_end={} pdata_end={} delta={}",
                                    (void *) sp.start, (void *) sp.end, (void *) hit->end, delta);
                        }
                    }
                }
                spdlog::info("pdata cross-check: compared={} mismatches={} (Nucleus not overridden)",
                             compared, mismatches);
            } else {
                spdlog::info("pdata cross-check: no .pdata ranges for {}", moduleMain.details.path);
            }
        }
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
        if (originalFunc->size == 0) {
            throw update_signatures_exception{
                    fmt::format("func[{}] has size 0 after Nucleus sizing (no containing span)", name)};
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
        if (target == 0 || target < targetLuaModuleBase)
            target = moduleMain.try_fix_func_address(*originalFunc,
                                                     &signature, targetLuaModuleBase);

        if (!target || target < targetLuaModuleBase) {
            // Soft-match fail-closed / unique-byte miss: keep previous entry and continue
            // so a single hard export does not abort the whole signature pass.
            spdlog::error("func[{}] can't fix address, keeping previous signature (offset={})",
                          name, old_offset);
            continue;
        }
        if (target == maybe_target)
            continue;
        // Resolve to a Function* when possible. If soft/unique_const refined an
        // entry that is not a Nucleus span start (coarse over-merge), keep it —
        // do NOT snap back to containing() which can be thousands of bytes away.
        if (moduleMain.find_function(target) == nullptr) {
            if (!moduleMain.function_table.empty()) {
                const auto pattern_address =
                        static_cast<uintptr_t>(static_cast<intptr_t>(target) -
                                               static_cast<intptr_t>(signature.pattern_offset));
                const uint64_t entry = moduleMain.function_table.containing(
                        signature.pattern_offset == 0 ? target : pattern_address);
                if (entry == 0) {
                    // Refined entry outside table still allowed if in text.
                    if (!moduleMain.in_text(target)) {
                        throw update_signatures_exception{
                                fmt::format("func[{}] match not in target FunctionTable", name)};
                    }
                    spdlog::info("keep refined entry [{}] outside Nucleus span starts",
                                 (void *) target);
                } else {
                    const auto match = signature.pattern_offset == 0
                                               ? target
                                               : pattern_address;
                    const auto dist = target >= entry ? target - entry : entry - target;
                    // Only adopt Nucleus start when we are still in the prologue
                    // region (pattern hit near entry). Far distances mean unique_const
                    // / train-off recovered a real interior export start.
                    if (dist <= 16) {
                        const auto new_po =
                                static_cast<intptr_t>(entry) - static_cast<intptr_t>(match);
                        spdlog::info("refix signature via FunctionTable: [{}]->[{}] entry={}",
                                     signature.pattern_offset, new_po, (void *) entry);
                        signature.pattern_offset = static_cast<int>(new_po);
                        target = static_cast<uintptr_t>(entry);
                    } else {
                        spdlog::info(
                                "keep refined entry [{}] (Nucleus containing {:#x} dist={})",
                                (void *) target, entry, dist);
                    }
                }
            } else {
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
        }
        // Snap only when target is a few bytes past a Nucleus start (mid-prologue
        // hit). Never pull a refined far entry back into a coarse over-merged span.
        if (!moduleMain.function_table.empty()) {
            const uint64_t entry = moduleMain.function_table.containing(target);
            if (entry != 0 && entry != target) {
                const auto dist = target >= entry ? target - entry : entry - target;
                if (dist <= 16) {
                    const auto pattern_address =
                            static_cast<uintptr_t>(static_cast<intptr_t>(target) -
                                                   static_cast<intptr_t>(signature.pattern_offset));
                    const auto new_po =
                            static_cast<intptr_t>(entry) - static_cast<intptr_t>(pattern_address);
                    spdlog::info("snap signature [{}] {} -> nucleus entry {} (pattern_offset {}->{})",
                                 name, (void *) target, (void *) entry,
                                 signature.pattern_offset, new_po);
                    signature.pattern_offset = static_cast<int>(new_po);
                    target = static_cast<uintptr_t>(entry);
                }
            }
        }
        auto new_offset = target - targetLuaModuleBase;
        // Reject two exports claiming the same RVA (equal-family collisions).
        bool dup = false;
        for (const auto &[other, osig]: funcs) {
            if (other == name) continue;
            if (osig.offset != 0 && osig.offset == static_cast<uintptr_t>(new_offset)) {
                spdlog::error("func[{}] offset {} already claimed by [{}], keeping previous",
                              name, new_offset, other);
                dup = true;
                break;
            }
        }
        if (dup) continue;
        spdlog::info("update signatures [{}:{}]: {} to {}", name, (void *) target, old_offset, new_offset);
        signature.offset = new_offset;
        moduleMain.set_known_function(target, name.c_str());
    }

    // --- Call-graph seed pass -------------------------------------------------
    // After soft/short-body matching, unresolved exports can still be recovered
    // when a *resolved* train caller has a CALL/JMP edge to them: map that edge
    // onto the target caller's same-module call list (ordinal + size fingerprint).
    // Example: train lua_pushstring tails to lua_pushnil; if game still has a
    // direct edge, pushnil is seeded. (Inlined callees need short-body instead.)
    {
        auto collect_named_callees =
                [](function_relocation::Function &fn,
                   function_relocation::ModuleSections &mod)
                -> std::vector<std::pair<std::string, uint64_t>> {
            function_relocation::ensure_function_features(fn);
            std::vector<std::pair<std::string, uint64_t>> out;
            std::unordered_set<uint64_t> seen;
            for (const auto block_addr: fn.blocks) {
                auto *block = mod.address_blocks.contains(block_addr)
                                      ? mod.address_blocks.at(block_addr)
                                      : nullptr;
                if (!block) continue;
                for (const auto ct: block->call_functions) {
                    if (!seen.insert(ct).second) continue;
                    auto *cf = mod.find_function(ct);
                    if (!cf || cf->name.empty()) continue;
                    if (!mod.known_functions.contains(cf->name)) continue;
                    out.emplace_back(cf->name, ct);
                }
            }
            return out;
        };

        auto collect_target_callees =
                [](function_relocation::Function &fn,
                   function_relocation::ModuleSections &mod)
                -> std::vector<uint64_t> {
            function_relocation::ensure_function_features(fn);
            std::vector<uint64_t> out;
            std::unordered_set<uint64_t> seen;
            for (const auto block_addr: fn.blocks) {
                auto *block = mod.address_blocks.contains(block_addr)
                                      ? mod.address_blocks.at(block_addr)
                                      : nullptr;
                if (!block) continue;
                for (const auto ct: block->call_functions) {
                    uint64_t entry = 0;
                    if (auto *cf = mod.find_function(ct); cf) {
                        entry = cf->address;
                    } else if (!mod.function_table.empty()) {
                        entry = mod.function_table.containing(ct);
                    }
                    if (entry == 0) continue;
                    if (!seen.insert(entry).second) continue;
                    out.push_back(entry);
                }
            }
            return out;
        };

        for (int round = 0; round < 4; ++round) {
            bool any = false;
            for (size_t i = 0; i < exports.size(); i++) {
                auto &name = exports[i].first;
                auto &signature = funcs.at(name);
                if (signature.offset != 0) continue;

                auto *train_fn = modulelua51.known_functions.at(name);
                if (!train_fn || train_fn->size == 0) continue;

                // Find a resolved train caller that lists this export as a named callee.
                for (size_t j = 0; j < exports.size(); j++) {
                    auto &caller_name = exports[j].first;
                    if (caller_name == name) continue;
                    auto &caller_sig = funcs.at(caller_name);
                    if (caller_sig.offset == 0) continue;

                    auto *train_caller = modulelua51.known_functions.at(caller_name);
                    if (!train_caller) continue;
                    const auto train_callees = collect_named_callees(*train_caller, modulelua51);
                    size_t ordinal = static_cast<size_t>(-1);
                    for (size_t k = 0; k < train_callees.size(); ++k) {
                        if (train_callees[k].first == name) {
                            ordinal = k;
                            break;
                        }
                    }
                    if (ordinal == static_cast<size_t>(-1)) continue;

                    const uintptr_t tgt_caller =
                            targetLuaModuleBase + static_cast<uintptr_t>(caller_sig.offset);
                    auto *target_caller = moduleMain.find_function(tgt_caller);
                    if (!target_caller) continue;
                    const auto tgt_callees = collect_target_callees(*target_caller, moduleMain);
                    if (tgt_callees.empty()) continue;

                    uint64_t chosen = 0;
                    if (tgt_callees.size() == train_callees.size() &&
                        ordinal < tgt_callees.size()) {
                        // Same arity: take matching ordinal.
                        chosen = tgt_callees[ordinal];
                    } else {
                        // Size fingerprint among target callees not yet claimed.
                        std::vector<uint64_t> candidates;
                        for (auto e: tgt_callees) {
                            bool claimed = false;
                            for (size_t k = 0; k < exports.size(); k++) {
                                auto &os = funcs.at(exports[k].first);
                                if (os.offset != 0 &&
                                    targetLuaModuleBase + static_cast<uintptr_t>(os.offset) == e) {
                                    claimed = true;
                                    break;
                                }
                            }
                            if (claimed) continue;
                            auto *tf = moduleMain.find_function(e);
                            if (!tf || tf->size == 0) continue;
                            const double ratio =
                                    static_cast<double>(tf->size) /
                                    static_cast<double>(std::max<size_t>(1, train_fn->size));
                            if (ratio >= 0.4 && ratio <= 3.0) {
                                candidates.push_back(e);
                            }
                        }
                        if (candidates.size() == 1) {
                            chosen = candidates.front();
                        }
                    }
                    if (chosen == 0 || chosen < targetLuaModuleBase) continue;

                    const auto new_offset = chosen - targetLuaModuleBase;
                    bool claimed = false;
                    for (const auto &[other, osig]: funcs) {
                        if (other != name && osig.offset != 0 &&
                            osig.offset == static_cast<uintptr_t>(new_offset)) {
                            claimed = true;
                            break;
                        }
                    }
                    if (claimed) continue;
                    signature.offset = new_offset;
                    signature.pattern.clear();
                    signature.pattern_offset = 0;
                    moduleMain.set_known_function(chosen, name.c_str());
                    spdlog::info("graph-seed [{}] via caller [{}] ordinal={} -> {:#x} (offset={})",
                                 name, caller_name, ordinal, chosen, new_offset);
                    any = true;
                    break;
                }
            }
            if (!any) break;
            spdlog::info("graph-seed round {} filled more exports", round);
        }

        // Reverse seed: unresolved E calls known K → find unclaimed target
        // callers of K with size fingerprint (e.g. loadstring → loadbuffer,
        // loadbuffer → lua_load, isstring → lua_type).
        for (int round = 0; round < 4; ++round) {
            bool any = false;
            for (size_t i = 0; i < exports.size(); i++) {
                auto &name = exports[i].first;
                auto &signature = funcs.at(name);
                if (signature.offset != 0) continue;
                auto *train_fn = modulelua51.known_functions.at(name);
                if (!train_fn || train_fn->size == 0) continue;

                // Direct named callees, plus one-level transitive (target may
                // inline a direct callee: train loadstring→JMP loadbuffer→lua_load
                // becomes game loadstring→CALL lua_load).
                std::vector<std::string> seed_callees;
                {
                    std::unordered_set<std::string> seen;
                    const auto direct = collect_named_callees(*train_fn, modulelua51);
                    for (const auto &[cn, _ct]: direct) {
                        if (!funcs.contains(cn) || funcs.at(cn).offset == 0) continue;
                        if (seen.insert(cn).second) seed_callees.push_back(cn);
                        auto *cfn = modulelua51.known_functions.contains(cn)
                                            ? modulelua51.known_functions.at(cn)
                                            : nullptr;
                        if (!cfn) continue;
                        for (const auto &[cn2, _ct2]: collect_named_callees(*cfn, modulelua51)) {
                            if (!funcs.contains(cn2) || funcs.at(cn2).offset == 0) continue;
                            if (seen.insert(cn2).second) seed_callees.push_back(cn2);
                        }
                    }
                }
                for (const auto &callee_name: seed_callees) {
                    auto &callee_sig = funcs.at(callee_name);
                    const uintptr_t tgt_callee =
                            targetLuaModuleBase + static_cast<uintptr_t>(callee_sig.offset);

                    std::vector<uint64_t> candidates;
                    for (auto &fn: moduleMain.functions) {
                        if (fn.address < targetLuaModuleBase || fn.size == 0) continue;
                        bool claimed = false;
                        for (size_t k = 0; k < exports.size(); k++) {
                            auto &os = funcs.at(exports[k].first);
                            if (os.offset != 0 &&
                                targetLuaModuleBase + static_cast<uintptr_t>(os.offset) ==
                                        fn.address) {
                                claimed = true;
                                break;
                            }
                        }
                        if (claimed) continue;
                        // Leaf for size ratio; walk min(span,128) for E8/E9 so
                        // calls after short fall-through still count.
                        const size_t train_leaf =
                                function_relocation::function_leaf_size(*train_fn, 128);
                        const size_t tgt_leaf =
                                function_relocation::function_leaf_size(fn, 128);
                        const double ratio =
                                static_cast<double>(std::max<size_t>(1, tgt_leaf)) /
                                static_cast<double>(std::max<size_t>(1, train_leaf));
                        if (ratio < 0.4 || ratio > 2.5) continue;

                        const size_t walk = std::min(fn.size, size_t{128});
                        if (function_relocation::body_calls_entry(
                                    moduleMain, fn.address, walk, tgt_callee)) {
                            candidates.push_back(fn.address);
                        }
                    }
                    uint64_t chosen = 0;
                    if (candidates.size() == 1) {
                        chosen = candidates.front();
                    } else if (candidates.size() > 1) {
                        // Disambiguate: closest leaf length to train leaf.
                        // Recompute train leaf via first RET within 128B.
                        size_t want = train_fn->size;
                        {
                            const size_t cap = std::min(train_fn->size, size_t{128});
                            function_relocation::disasm ds{
                                    std::span{reinterpret_cast<uint8_t *>(train_fn->address), cap}};
                            for (auto &insn: ds) {
                                if (insn.id == X86_INS_RET || insn.id == X86_INS_RETF ||
                                    insn.id == X86_INS_RETFQ) {
                                    want = static_cast<size_t>(insn.address + insn.size -
                                                               train_fn->address);
                                    break;
                                }
                                if (insn.id == X86_INS_JMP) {
                                    const auto &op = insn.detail->x86.operands[0];
                                    if (op.type == X86_OP_IMM) {
                                        const uint64_t t = static_cast<uint64_t>(op.imm);
                                        if (t < train_fn->address ||
                                            t >= train_fn->address + train_fn->size) {
                                            want = static_cast<size_t>(
                                                    insn.address + insn.size - train_fn->address);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        size_t best_diff = SIZE_MAX;
                        uint64_t best = 0;
                        size_t ties = 0;
                        for (const auto cand: candidates) {
                            auto *fn = moduleMain.find_function(cand);
                            if (!fn) continue;
                            size_t leaf = fn->size;
                            const size_t cap = std::min(fn->size, size_t{128});
                            function_relocation::disasm ds{
                                    std::span{reinterpret_cast<uint8_t *>(fn->address), cap}};
                            for (auto &insn: ds) {
                                if (insn.id == X86_INS_RET || insn.id == X86_INS_RETF ||
                                    insn.id == X86_INS_RETFQ) {
                                    leaf = static_cast<size_t>(insn.address + insn.size -
                                                               fn->address);
                                    break;
                                }
                                if (insn.id == X86_INS_JMP) {
                                    const auto &op = insn.detail->x86.operands[0];
                                    if (op.type == X86_OP_IMM) {
                                        const uint64_t t = static_cast<uint64_t>(op.imm);
                                        if (t < fn->address || t >= fn->address + fn->size) {
                                            leaf = static_cast<size_t>(insn.address + insn.size -
                                                                       fn->address);
                                            break;
                                        }
                                    }
                                }
                            }
                            const size_t diff = leaf > want ? leaf - want : want - leaf;
                            if (diff < best_diff) {
                                best_diff = diff;
                                best = cand;
                                ties = 1;
                            } else if (diff == best_diff) {
                                ties++;
                            }
                        }
                        // Accept only unique closest and reasonably close (≤16B).
                        if (ties == 1 && best != 0 && best_diff <= 16) {
                            chosen = best;
                            spdlog::info(
                                    "graph-seed-rev [{}] via [{}] disambiguated by leaf "
                                    "(diff={}, candidates={})",
                                    name, callee_name, best_diff, candidates.size());
                        } else {
                            spdlog::info(
                                    "graph-seed-rev [{}] via [{}] ambiguous candidates={} "
                                    "(best_diff={} ties={})",
                                    name, callee_name, candidates.size(), best_diff, ties);
                            continue;
                        }
                    } else {
                        continue;
                    }
                    const auto new_offset = chosen - targetLuaModuleBase;
                    bool claimed = false;
                    for (const auto &[other, osig]: funcs) {
                        if (other != name && osig.offset != 0 &&
                            osig.offset == static_cast<uintptr_t>(new_offset)) {
                            claimed = true;
                            break;
                        }
                    }
                    if (claimed) continue;
                    signature.offset = new_offset;
                    signature.pattern.clear();
                    signature.pattern_offset = 0;
                    moduleMain.set_known_function(chosen, name.c_str());
                    spdlog::info("graph-seed-rev [{}] via callee [{}] -> {:#x} (offset={})",
                                 name, callee_name, chosen, new_offset);
                    any = true;
                    break;
                }
            }
            if (!any) break;
            spdlog::info("graph-seed-rev round {} filled more exports", round);
        }
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
        auto ictx = InjectorCtx::instance();
        if (ictx->config.disable_progress || !ictx->DontStarveInjectorIsClient) {
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