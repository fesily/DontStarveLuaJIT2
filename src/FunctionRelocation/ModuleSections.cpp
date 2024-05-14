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
#include "../DontStarveInjector/util/platform.hpp"

#include <thread>

struct SignatureInfo;

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
    fix_func_address_by_signature(ModuleSections &target, const Function &original, uintptr_t limit_address, SignatureInfo *signature);

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

    bool ModuleSections::in_module(uintptr_t address) const {
        return details->range->base_address <= address && address <= details->range->base_address + details->range->size;
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

    static bool get_module_sections(const char *path, ModuleSections& sections) {
        const auto details = get_module_details(path);
#ifdef _WIN32
        const auto pe = peparse::ParsePEFromFile(details->path);
        if (pe)
        {
            auto args = std::tuple{&sections, details->range->base_address};
            IterSec(pe, +[](void* user_data,
                            const peparse::VA& secBase,
                            const std::string& secName,
                            const peparse::image_section_header& s,
                            const peparse::bounded_buffer* data)
            {
	            auto& [sections, base_address] = *static_cast<decltype(args)*>(user_data);
	            auto real_address = s.VirtualAddress + base_address;
	            auto len = data->bufLen;
	            if (secName == ".text")
		            sections->text = { real_address, len };
	            else if (secName == ".rdata")
		            sections->rodata = { real_address, len };
	            return 0;
            }, (void*)&args);
            DestructParsedPE(pe);
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
        return true;
    }


    bool init_module_signature(const char *path, uintptr_t scan_start_address, ModuleSections& sections, bool noScan) {
        if (!get_module_sections(path, sections)) return false;
        if (noScan) return true;
        ScanCtx ctx{sections, scan_start_address};
        // try get the function name by debug info
#ifdef _WIN32
        static auto loadflag = std::once_flag{};
        std::call_once(loadflag, loadlib, "dbghelp.dll");
#endif
        gum_module_enumerate_symbols(path, +[](const GumSymbolDetails *details, gpointer data) -> gboolean {
            if (details->type == GUM_SYMBOL_FUNCTION || details->type == GUM_SYMBOL_OBJECT) {
                const auto ptr = (decltype(ctx) *) data;
                if (ptr->m.in_text(details->address) && details->address >= ptr->text.base_address)
                    ptr->known_functions.try_emplace(details->address,
                                                     Function{.address=details->address, .size=(size_t) details->size, .name=details->name});
            }
            return true;
        }, &ctx);
        ctx.scan();

        {
            const auto vec = sections.functions | std::ranges::views::transform(
                    [](auto &func) { return std::make_pair(func->address, func.get()); }) | ranges::to<std::vector>;
            sections.address_functions = {vec.begin(), vec.end()};
        }
        for (auto &[address, func]: ctx.known_functions) {
            if (!sections.address_functions.contains(address)) {
                assert(false);
                continue;
            }
            sections.known_functions[func.name] = sections.address_functions[address];
            sections.address_functions[address]->name = func.name;
        }

        for (auto &func: sections.functions) {
#if 1
            if (scan_start_address == 0 && func->name.empty())
                fprintf(stderr, "unkown ptr: %p\n", (void *) func->address);
#endif
            for (const auto &block: func->blocks) {
                for (const auto &c: block->consts) {
                    if (c->ref == 1 && (func->const_key == nullptr || c->value.size() > func->const_key->size())) {
                        func->const_key = &c->value;
                    }
                }
            }

            func->consts_hash = hash_vector(func->blocks);
        }

        return true;
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

    static float calc_score(const Function &func, const MatchConfig &config) {
        float res = 0;
        for (const auto &block: func.blocks) {
            res += block->consts.size() * config.consts_score + block->call_functions.size() * config.call_score +
                   block->const_numbers.size() * config.const_numbers_score;
        }
        return res;
    }

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
                if (function->const_key && (*function->const_key == key))
                    return true;
                auto block = std::ranges::find_if(function->blocks, [key](const auto &v) {
                    return std::ranges::find_if(v->consts, [key](const auto &c) {
                        return c->value == key;
                    }) != v->consts.end();
                });
                return block != function->blocks.end();
            }) | std::views::transform([this](const auto &function) {
                       return Match{function.get(), config.match_score};
            }) | ranges::to<std::vector>();
        }

        std::vector<Match> match_function(const Function &func1) {
            const auto target = func1.consts_hash;
            std::vector<Match> res;
            for (auto &func: sections.functions) {
                if (target == func->consts_hash)
                    res.emplace_back(Match{func.get(), config.match_score});
            }
            return res;
        }

        std::optional<Match> match_function_search(const Function &func) {
            float max = 0;
            const CodeBlock *maybeBlock = nullptr;
            for (const auto &fn: sections.functions) {
                if (func.insn_count * 0.9 > fn->insn_count || fn->insn_count > func.insn_count * 1.1) continue;
                if (func.blocks.size() != fn->blocks.size()) continue;
                if (func.calls_count() != fn->calls_count()) continue;
                for (const auto &block: fn->blocks) {
                    for (const auto &target_block: func.blocks) {
                        auto score = calc_match_score(*block, *target_block);
                        if (score > max) {
                            maybeBlock = block;
                            max = score;
                        }
                    }
                }
            }
            if (!maybeBlock) return std::nullopt;
            return Match{maybeBlock->function,  function_relocation::calc_score(*maybeBlock->function, config)};
        };

        float calc_match_score(const CodeBlock &block, const CodeBlock &target_block) {
            std::vector<Const *> intersectionConst;

            if (!target_block.consts.empty()) {
                std::ranges::set_intersection(block.consts, target_block.consts,
                                            std::back_inserter(intersectionConst));
                if (intersectionConst.empty())
                    return {};
            }

            std::vector<uint64_t> intersectionNumber;

            if (!target_block.const_numbers.empty()) {
                std::ranges::set_intersection(block.const_numbers, target_block.const_numbers,
                                std::back_inserter(intersectionNumber));
                if (intersectionNumber.empty())
                    return {};
            }
            std::vector<uint64_t> intersectionOffNumber;

            if (!target_block.const_offset_numbers.empty()) {
                std::ranges::set_intersection(block.const_offset_numbers, target_block.const_numbers,
                                std::back_inserter(intersectionOffNumber));
                if (intersectionOffNumber.empty())
                    return {};
            }

            return intersectionConst.size() * config.consts_score +
                   intersectionNumber.size() * config.const_numbers_score +
                   intersectionOffNumber.size() * config.const_offset_score;
        }


        const CodeBlock &max_block(const Function &func) {
            return **std::ranges::max_element(func.blocks, [this](auto l, auto r) {
                return calc_score(*l) > calc_score(*r);
            });
        }

        float calc_score(CodeBlock &block) {
            return block.consts.size() * config.consts_score + block.call_functions.size() * config.call_score +
                   block.const_numbers.size() * config.const_numbers_score;
        }
    };

    uintptr_t ModuleSections::try_fix_func_address(const Function &original, SignatureInfo *signature, uintptr_t limit_address) {
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
            if (matched && matched.value().score > targetScore * 0.95) {
                return matched.value().matched->address;
            }
        }
        return (uintptr_t) fix_func_address_by_signature(*this, original, limit_address, signature);
    }

    size_t Function::consts_count() const
    {
        return ranges::accumulate(blocks | ranges::views::transform([](CodeBlock* v){return v->consts.size();}), 0);
    }
    size_t Function::calls_count() const
    {
        return ranges::accumulate(blocks | ranges::views::transform([](CodeBlock *v) {  return v->call_functions.size(); }), 0);
    }
    size_t Function::const_count() const
    {
        return ranges::accumulate(blocks | ranges::views::transform([](CodeBlock *v) {  return v->const_numbers.size(); }), 0);
    }
    size_t Function::const_offset_count() const
    {
        return ranges::accumulate(blocks | ranges::views::transform([](CodeBlock *v) {  return v->const_offset_numbers.size(); }), 0);
    }
}
