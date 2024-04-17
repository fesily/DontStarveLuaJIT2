#include "ModuleSections.hpp"

#include <unordered_set>
#include <ranges>
#include <algorithm>
#include <cassert>

#ifdef _WIN32
#include <pe-parse/parse.h>
#else

#include <dlfcn.h>

#endif

#include <range/v3/all.hpp>

#include "ctx.hpp"
#include "disasm.h"
#include "ScanCtx.hpp"

template<typename T>
size_t hash_vector(const std::vector<T> &vec) {
    auto seed = vec.size();
    for (const auto &v: vec) {
        seed ^= std::hash<T>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
    return seed;
}

template<>
struct std::hash<function_relocation::CodeBlock> {
    size_t operator()(const function_relocation::CodeBlock &block) noexcept {
        return hash_vector(block.consts);
    }
};

namespace function_relocation {
    using namespace std::literals;

    void *
    fix_func_address_by_signature(ModuleSections &target, const Function &original);

    bool ModuleSections::in_text(uintptr_t address) const {
        return text.base_address <= address && address <= text.base_address + text.size;
    }

    bool ModuleSections::in_plt(uintptr_t address) const {
        return plt.base_address <= address && address <= plt.base_address + plt.size;
    }

    bool ModuleSections::in_got_plt(uintptr_t address) const {
        return got_plt.base_address <= address && address <= got_plt.base_address + got_plt.size;
    }

    bool ModuleSections::in_rodata(uintptr_t address) const {
        return rodata.base_address <= address && address <= rodata.base_address + rodata.size;
    }

    ModuleSections::~ModuleSections() {
        if (details)
            gum_module_details_free(details);
    }

    static GumModuleDetails *get_module_details(const char *path) {
        if (path == nullptr) {
            return gum_module_details_copy(gum_process_get_main_module());
        }
        GumModuleDetails *out_details;
        auto fn = [&](const GumModuleDetails *details) -> gboolean {
            if (strcmp(details->path, path) == 0
                || std::string_view(details->path).ends_with(path)) {
                out_details = gum_module_details_copy(details);
                return FALSE;
            }
            return TRUE;
        };
        gum_process_enumerate_modules(+[](const GumModuleDetails *details,
                                          gpointer user_data) -> gboolean {
            return (*static_cast<decltype(fn) *>(user_data))(details);
        }, (void *) &fn);
        return out_details;
    }

    static ModuleSections get_module_sections(const char *path) {
        const auto details = get_module_details(path);
        ModuleSections sections{};
#ifdef _WIN32
        const auto pe = peparse::ParsePEFromFile(details->path);
        if (pe)
        {
            auto args = std::tuple{&sections, details->range->base_address};
            peparse::IterSec(pe, +[](void* user_data,
                const peparse::VA& secBase,
                const std::string& secName,
                const peparse::image_section_header& s,
                const peparse::bounded_buffer* data)
                {
                    auto& [sections, base_address] = *(decltype(args)*)user_data;
                    auto real_address = s.VirtualAddress + base_address;
                    auto len = data->bufLen;
                    if (secName == ".text")
                        sections->text = { real_address, len };
                    else if (secName == ".rdata")
                        sections->rodata = { real_address, len };
                    return 0;
                }, (void*)&args);
            peparse::DestructParsedPE(pe);
        }
#else

        gum_module_enumerate_sections(path, +[](const GumSectionDetails *details, gpointer user_data) -> gboolean {
            if (details->name == ".text"sv)
                (*(ModuleSections *) user_data).text = {details->address, details->size};
            else if (details->name == ".rodata"sv)
                (*(ModuleSections *) user_data).rodata = {details->address, details->size};
            else if (details->name == ".plt"sv)
                (*(ModuleSections *) user_data).plt = {details->address, details->size};
            else if (details->name == ".got.plt"sv)
                (*(ModuleSections *) user_data).got_plt = {details->address, details->size};
            return TRUE;
        }, (void *) &sections);
#endif
        sections.details = details;
        return sections;
    }


    ModuleSections init_module_signature(const char *path, uintptr_t scan_start_address) {
        auto sections = get_module_sections(path);
        ScanCtx ctx{sections, scan_start_address};
        // try get the function name by debug info
#ifndef _WIN32
        gum_module_enumerate_symbols(path, +[](const GumSymbolDetails *details, gpointer data) -> gboolean {
            if (details->type == GUM_SYMBOL_FUNCTION || details->type == GUM_SYMBOL_OBJECT) {
                const auto ptr = (decltype(ctx) *) data;
                if (ptr->m.in_text(details->address))
                    ptr->known_functions.try_emplace(details->address,
                                                     Function{.address=details->address, .size=(size_t) details->size, .name=details->name});
            }
            return true;
        }, &ctx);
#endif
        ctx.scan();

        {
            const auto vec = sections.functions | std::ranges::views::transform(
                    [](auto &func) { return std::make_pair(func.address, &func); }) | ranges::to<std::vector>;
            sections.address_functions = {vec.begin(), vec.end()};
        }
        for (const auto &[address, func]: ctx.known_functions) {
            sections.known_functions[address] = func.name;
        }

        std::list<std::pair<int, int>> arcs;
        for (auto &func: sections.functions) {
#if 1
            if (!sections.known_functions.contains(func.address))
                fprintf(stderr, "unkown ptr: %p\n", (void *) func.address);
#endif
            for (const auto &block: func.blocks) {
                for (const auto &c: block.consts) {
                    if (c->ref == 1 && (func.const_key == nullptr || c->value.size() > func.const_key->size())) {
                        func.const_key = &c->value;
                    }
                }
                for (const auto call_func_addr: block.call_functions) {
                    assert(sections.address_functions.contains(call_func_addr));
                    auto call_func = sections.address_functions[call_func_addr];
                    assert(call_func);
                    if (call_func) {
                        arcs.emplace_back(&func - sections.functions.data(), call_func - sections.functions.data());
                    }
                }
            }

            func.consts_hash = hash_vector(func.blocks);
        }

        sections.staticDigraph.build(sections.functions.size(), arcs.begin(), arcs.end());
        return sections;
    }


    struct MatchConfig {
        const float consts_score = 2;
        const float call_score = 1;
        const float const_numbers_score = 0.8;
        const float const_offset_score = 0.2;

        int string_huge_limit = 48;
        int string_huge_group = 1;
        int string_long_limit = 24;
        int string_long_group = 2;
        int string_medium_limit = 16;
        int string_medium_group = 3;
        int const_complex_limit = 16;
        int const_complex_group = 1;
        const float match_score = 999;
    };

    struct FunctionMatchCtx {
        struct Match {
            const Function *matched;
            float score;

            operator bool() const {
                return matched != nullptr;
            }
        };

        ModuleSections &sections;

        MatchConfig &config;

        std::vector<Match> match_function(std::string_view key) {
            return sections.functions | std::views::filter([key](const auto &function) {
                if (*function.const_key == key)
                    return true;
                auto block = std::ranges::find_if(function.blocks, [key](const auto &v) {
                    return std::ranges::find_if(v.consts, [key](const auto &c) {
                        return c->value == key;
                    }) != v.consts.end();
                });
                return block != function.blocks.end();
            }) | std::views::transform([this](const auto &function) {
                return Match{&function, config.match_score};
            }) | ranges::to<std::vector>();
        }

        std::vector<Match> match_function(const Function &func1) {
            const auto target = func1.consts_hash;
            std::vector<Match> res;
            for (auto &func: sections.functions) {
                if (target == func.consts_hash)
                    res.emplace_back(Match{&func, config.match_score});
            }
            return res;
        }

        Match match_function_search(const Function &func) {
            float max = 0;
            const CodeBlock *maybeBlock = nullptr;
            for (const auto &fn: sections.functions) {
                for (const auto &block: fn.blocks) {
                    for (const auto &target_block: func.blocks) {
                        auto score = calc_match_score(block, target_block);
                        if (score > max) {
                            maybeBlock = &block;
                            max = score;
                        }
                    }
                }
            }
            return Match{maybeBlock->function, max};
        };

        auto known_functions(const CodeBlock &block) {
            std::vector known1 = block.call_functions | std::views::transform([this](const auto &addr) {
                auto iter = sections.known_functions.find(addr);
                return iter != sections.known_functions.end() ? iter->second : std::string_view{};
            }) | std::views::filter([](const auto &v) { return !v.empty(); }) | ranges::to<std::vector>();
            return known1;
        }

        float calc_match_score(const CodeBlock &block, const CodeBlock &target_block) {
            std::vector<Const *> intersectionConst;

            std::ranges::set_intersection(block.consts, target_block.consts,
                                          std::back_inserter(intersectionConst));

            if (!target_block.consts.empty() && intersectionConst.empty()) {
                return {};
            }
            std::vector<uint64_t> intersectionNumber;
            std::ranges::set_intersection(block.const_numbers, target_block.const_numbers,
                                          std::back_inserter(intersectionNumber));
            if (!target_block.const_numbers.empty() && intersectionNumber.empty()) {
                return {};
            }
            std::vector<uint64_t> intersectionOffNumber;
            std::ranges::set_intersection(block.const_offset_numbers, target_block.const_numbers,
                                          std::back_inserter(intersectionOffNumber));
            if (!target_block.const_offset_numbers.empty() && intersectionOffNumber.empty()) {
                return {};
            }
            std::vector<std::string_view> intersectionCall;
            auto known = known_functions(target_block);
            auto known1 = known_functions(block);
            std::ranges::set_intersection(known, known1,
                                          std::back_inserter(intersectionCall));

            if (!known.empty() && intersectionCall.empty()) {
                return {};
            }

            return intersectionConst.size() * config.consts_score +
                   intersectionNumber.size() * config.const_numbers_score +
                   intersectionOffNumber.size() * config.const_offset_score +
                   intersectionCall.size() * config.call_score;
        }


        const CodeBlock &max_block(const Function &func) {
            return *std::ranges::max_element(func.blocks, [this](auto &l, auto &r) {
                return calc_score(l) > calc_score(r);
            });
        }

        float calc_score(const CodeBlock &block) {
            return block.consts.size() * config.consts_score + block.call_functions.size() * config.call_score +
                   block.const_numbers.size() * config.const_numbers_score;
        }
    };

    static float calc_score(const Function &func, const MatchConfig &config) {
        float res = 0;
        for (const auto &block: func.blocks) {
            res += block.consts.size() * config.consts_score + block.call_functions.size() * config.call_score +
                   block.const_numbers.size() * config.const_numbers_score;
        }
        return res;
    }

    uintptr_t ModuleSections::try_fix_func_address(const Function &original, uint64_t maybe_addr) {
        MatchConfig config;
        FunctionMatchCtx ctx{*this, config};
        const auto targetScore = calc_score(original, config);
        if (original.const_key != nullptr) {
            auto matched = ctx.match_function(*original.const_key);
            assert(matched.size() <= 1);
            if (matched.size() == 1) {
                return matched[0].matched->address;
            }
        } else {
            auto matched = ctx.match_function_search(original);
            if (matched && matched.score > targetScore * 0.95) {
                return matched.matched->address;
            }
        }
        return (uintptr_t) fix_func_address_by_signature(*this, original);
    }

}
