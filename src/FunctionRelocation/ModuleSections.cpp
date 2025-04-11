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
#include <spdlog/spdlog.h>

#include "ctx.hpp"
#include "disasm.h"
#include "ScanCtx.hpp"
#include "config.hpp"
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


    CodeBlock *Function::get_block(size_t index) const {
        const auto address = blocks[index];
        return module->address_blocks[address];
    }

    void *
    fix_func_address_by_signature(ModuleSections &target, const Function &original, uintptr_t limit_address,
                                  SignatureInfo *signature);

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

    bool ModuleSections::in_module(uintptr_t address) const {
        return details.range.base_address <= address && address <= details.range.base_address + details.range.size;
    }

    static GumModule *get_module(const char *path) {
        if (path == nullptr) {
            return gum_process_get_main_module();
        }
        GumModule *out_details;
        auto fn = [&](GumModule *module) -> gboolean {
            auto module_path = gum_module_get_path(module);
            if (strcmp(module_path, path) == 0 || std::string_view(module_path).ends_with(path)) {
                out_details = module;
                return FALSE;
            }
            return TRUE;
        };
        gum_process_enumerate_modules(+[](GumModule *module,
                                          gpointer user_data) -> gboolean { return (*static_cast<decltype(fn) *>(user_data))(module);
        }, (void *) &fn);
        return out_details;
    }

    bool get_module_sections(const char *path, ModuleSections &sections) {
        const auto module = get_module(path);
        auto module_path = gum_module_get_path(module);
#ifdef _WIN32
        const auto pe = peparse::ParsePEFromFile(module_path);
        if (pe)
        {
            auto module_range = gum_module_get_range(module);
            auto args = std::tuple{&sections, module_range->base_address};
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
                else if (secName == ".pdata")
                    sections->pdata = { real_address, len };
                return 0;
            }, (void*)&args);
            DestructParsedPE(pe);
        }
#else

        gum_module_enumerate_sections(path, +[](const GumSectionDetails *details, gpointer user_data) -> gboolean {
            if (details->name == ".text"sv || details->name == "__text"sv)
                (*(ModuleSections *) user_data).text = {details->address, details->size};
            else if (details->name == ".rodata"sv || details->name == "__cstring"sv)
                (*(ModuleSections *) user_data).rodata = {details->address, details->size};
            else if (details->name == ".plt"sv || details->name == "__stubs"sv)
                (*(ModuleSections *) user_data).plt = {details->address, details->size};
            else if (details->name == ".got.plt"sv || details->name == "__got"sv)
                (*(ModuleSections *) user_data).got_plt = {details->address, details->size};
            return TRUE;
        }, (void *) &sections);
#endif
        sections.details = {
                .name = gum_module_get_name(module),
                .range = *gum_module_get_range(module),
                .path = module_path
        };
        return true;
    }

    bool init_module_signature(const char *path, uintptr_t scan_start_address, ModuleSections &sections) {
        if (!get_module_sections(path, sections)) {
            spdlog::get(logger_name)->error("cannot get_module_sections: {}", path);
            return false;
        }
        ScanCtx ctx{sections, scan_start_address};
        // try get the function name by debug info
#ifdef _WIN32
        static auto loadflag = std::once_flag{};
        std::call_once(loadflag, loadlib, "dbghelp.dll");
        //TODO: symbols is error, should special the pdb search path
         gum_load_symbols(std::filesystem::path{path}.filename().string().c_str());
#endif
         const auto module = get_module(path);
         gum_module_enumerate_symbols(module, +[](const GumSymbolDetails *details, gpointer data) -> gboolean {
            if (details->type == GUM_SYMBOL_FUNCTION || details->type == GUM_SYMBOL_OBJECT
                #if defined(__MACH__) && defined(__APPLE__)
                || details->type == GUM_SYMBOL_SECTION
#endif
                    ) {
                const auto ptr = (decltype(ctx) *) data;
                if (ptr->m.in_text(details->address) && details->address >= ptr->text.base_address)
                    ptr->known_functions.try_emplace(details->address,
                                                     Function{.address=details->address, .size=(size_t) (
                                                             details->size == -1 ? 0
                                                                                 : details->size), .name=details->name});
            }
            return true;
        }, &ctx);
        ctx.scan();

        {
            const auto vec = sections.functions | std::ranges::views::transform(
                    [](auto &func) { return std::make_pair(func.address, &func); }) | ranges::to<std::vector>;
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
            if (scan_start_address == 0 && func.name.empty())
                fprintf(stderr, "unkown ptr: %p\n", (void *) func.address);
#endif
            for (const auto &block_address: func.blocks) {
                auto block = sections.address_blocks[block_address];
                for (const auto &c: block->consts) {
                    auto &constV = sections.Consts.at(c);
                    if (constV.ref == 1 &&
                        (func.const_key == nullptr || constV.value.size() > func.const_key->size())) {
                        func.const_key = &constV.value;
                    }
                }
            }

            func.consts_hash = hash_vector(func.blocks);
        }

        return true;
    }

    uintptr_t
    ModuleSections::try_fix_func_address(const Function &original, SignatureInfo *signature, uintptr_t limit_address) {
        return (uintptr_t) fix_func_address_by_signature(*this, original, limit_address, signature);
    }

    size_t Function::consts_count() const {
        return ranges::accumulate(blocks | ranges::views::transform(
                [this](uintptr_t address) { return module->address_blocks[address]->consts.size(); }), 0);
    }

    size_t Function::calls_count() const {
        return ranges::accumulate(blocks | ranges::views::transform(
                [this](uintptr_t address) { return module->address_blocks[address]->call_functions.size(); }), 0);
    }

    size_t Function::const_count() const {
        return ranges::accumulate(blocks | ranges::views::transform(
                [this](uintptr_t address) { return module->address_blocks[address]->const_numbers.size(); }), 0);
    }

    size_t Function::const_offset_count() const {
        return ranges::accumulate(blocks | ranges::views::transform(
                [this](uintptr_t address) { return module->address_blocks[address]->const_offset_numbers.size(); }), 0);
    }
}
