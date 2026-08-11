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
#include "FunctionTable.hpp"
#ifdef _WIN32
#include <windows.h>
#include <filesystem>
#else
#include "../DontStarveInjector/util/platform.hpp"
#endif

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
                else if (secName == ".data")
                    sections->bss = { real_address, len };
                sections->sections[secName] = { real_address, len };
                return 0;
            }, (void*)&args);
            DestructParsedPE(pe);
        }
#else

        gum_module_enumerate_sections(module, +[](const GumSectionDetails *details, gpointer user_data) -> gboolean {
            auto& msec = *(ModuleSections *) user_data;
            if (details->name == ".text"sv || details->name == "__text"sv)
                msec.text = {details->address, details->size};
            else if (details->name == ".rodata"sv || details->name == "__cstring"sv)
                msec.rodata = {details->address, details->size};
            else if (details->name == ".plt"sv || details->name == "__stubs"sv)
                msec.plt = {details->address, details->size};
            else if (details->name == ".got.plt"sv || details->name == "__got"sv)
                msec.got_plt = {details->address, details->size};
            else if (details->name == ".bss"sv || details->name == "__bss"sv)
                msec.bss = {details->address, details->size};
            else if (details->name == ".eh_frame" || details->name == "__eh_frame")
                msec.ehframe = {details->address, details->size};
            msec.sections[details->name] = {details->address, details->size};
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
        (void) scan_start_address;
        if (!get_module_sections(path, sections)) {
            spdlog::get(logger_name)->error("cannot get_module_sections: {}", path);
            return false;
        }
        // Sections + symbol names only. Function start|end come from Nucleus
        // (apply_nucleus_function_table). Do not run CALL/FDE/ret heuristics.
#ifdef _WIN32
        static auto loadflag = std::once_flag{};
        std::call_once(loadflag, [] {
            (void) LoadLibraryA("dbghelp.dll");
        });
         gum_load_symbols(std::filesystem::path{path}.filename().string().c_str());
#endif
        const auto module = get_module(path);
        sections.symbol_names.clear();
        gum_module_enumerate_symbols(module, +[](const GumSymbolDetails *details, gpointer data) -> gboolean {
            auto *secs = static_cast<ModuleSections *>(data);
            if (details->type == GUM_SYMBOL_FUNCTION || details->type == GUM_SYMBOL_OBJECT
#if defined(__MACH__) && defined(__APPLE__)
                || details->type == GUM_SYMBOL_SECTION
#endif
                    ) {
                if (secs->in_text(details->address) && details->name != nullptr && details->name[0] != '\0') {
                    secs->symbol_names.try_emplace(details->address, details->name);
                }
            }
            return true;
        }, &sections);
        return true;
    }

    uintptr_t
    ModuleSections::try_fix_func_address(const Function &original, SignatureInfo *signature, uintptr_t limit_address) {
        return (uintptr_t) fix_func_address_by_signature(*this, original, limit_address, signature);
    }

    bool apply_nucleus_function_table(ModuleSections &sections,
                                      const FunctionTable &image_table,
                                      uint64_t image_base) {
        sections.function_table.clear();
        auto log = spdlog::get(logger_name);
        if (image_table.empty()) {
            if (log) {
                log->error("apply_nucleus_function_table: empty table for {}",
                           sections.details.path);
            }
            return false;
        }

        const auto process_base = sections.details.range.base_address;
        for (const auto &sp: image_table.spans()) {
            if (sp.end <= sp.start) {
                continue;
            }
            const uint64_t start = process_base + (sp.start - image_base);
            const uint64_t end = process_base + (sp.end - image_base);
            sections.function_table.add(FunctionSpan{start, end});
        }

        if (sections.function_table.empty()) {
            if (log) {
                log->error("apply_nucleus_function_table: remapped table empty for {}",
                           sections.details.path);
            }
            return false;
        }

        // Rebuild Function list strictly from Nucleus spans. No ScanCtx split.
        sections.functions.clear();
        sections.blocks.clear();
        sections.Consts.clear();
        sections.address_functions.clear();
        sections.address_blocks.clear();
        sections.known_functions.clear();

        for (const auto &sp: sections.function_table.spans()) {
            if (sp.end <= sp.start) {
                continue;
            }
            // Only materialize bodies that start in .text (Nucleus may emit
            // spans covering non-exec ranges on messy game binaries).
            if (!sections.in_text(sp.start)) {
                continue;
            }
            Function fn;
            fn.address = sp.start;
            // Clamp size to remaining .text so feature scan cannot walk off.
            const uint64_t text_end = sections.text.base_address + sections.text.size;
            const uint64_t clamped_end = std::min(sp.end, text_end);
            if (clamped_end <= sp.start) {
                continue;
            }
            fn.size = static_cast<size_t>(clamped_end - sp.start);
            fn.module = &sections;
            if (auto it = sections.symbol_names.find(sp.start); it != sections.symbol_names.end()) {
                fn.name = it->second;
            }
            sections.functions.push_back(std::move(fn));
        }

        for (auto &func: sections.functions) {
            sections.address_functions[func.address] = &func;
            if (!func.name.empty()) {
                sections.known_functions[func.name] = &func;
            }
        }

        // Exports that sit strictly inside a parent span (rare on ELF after
        // NucleusAdapter export split; still label for train-side lookup).
        // Do NOT cut FunctionTable — entry for soft match is always span.start.
        for (const auto &[addr, name]: sections.symbol_names) {
            if (sections.address_functions.contains(addr)) {
                continue;
            }
            const FunctionSpan *sp = sections.function_table.span_containing(addr);
            if (!sp) {
                continue;
            }
            // Named export interior to a span: keep a Function* at the export
            // VA for train known_functions lookup, size = remaining parent body.
            Function fn;
            fn.address = addr;
            fn.size = static_cast<size_t>(sp->end - addr);
            fn.name = name;
            fn.module = &sections;
            sections.functions.push_back(std::move(fn));
            auto *p = &sections.functions.back();
            sections.address_functions[addr] = p;
            sections.known_functions[name] = p;
        }

        if (log) {
            log->info("apply_nucleus_function_table: {} spans, {} functions, {} named ({})",
                      sections.function_table.size(), sections.functions.size(),
                      sections.known_functions.size(), sections.details.path);
        }
        return !sections.functions.empty();
    }

    bool scan_module_function_features(ModuleSections &sections) {
        if (sections.function_table.empty()) {
            if (auto log = spdlog::get(logger_name)) {
                log->error("scan_module_function_features: empty FunctionTable for {}",
                           sections.details.path);
            }
            return false;
        }
        // Prefer named exports (train lib). For game binaries with few/no
        // symbols, scan all text-clamped Nucleus bodies (already filtered).
        ScanCtx ctx{sections, sections.text.base_address};
        const bool has_names = !sections.known_functions.empty();
        if (has_names) {
            // Only disasm named bodies — enough for train-side soft features.
            std::vector<std::pair<uintptr_t, size_t>> named;
            for (const auto &[name, fn]: sections.known_functions) {
                (void) name;
                if (fn && fn->size > 0) {
                    named.emplace_back(fn->address, fn->size);
                }
            }
            sections.blocks.clear();
            sections.address_blocks.clear();
            sections.Consts.clear();
            for (auto &fn: sections.functions) {
                fn.blocks.clear();
                fn.insn_count = 0;
                fn.const_key = nullptr;
                fn.consts_hash = 0;
            }
            for (const auto &[address, size]: named) {
                ctx.body_hard_end = address + size;
                ctx.function_limit = ctx.body_hard_end - 1;
                ctx.cur = nullptr;
                ctx.scan_function(address);
                ctx.body_hard_end = 0;
            }
        } else {
            ctx.scan_nucleus_bodies();
        }

        for (auto &func: sections.functions) {
            for (const auto &block_address: func.blocks) {
                auto *block = sections.address_blocks[block_address];
                if (!block) {
                    continue;
                }
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
        if (auto log = spdlog::get(logger_name)) {
            log->info("scan_module_function_features: {} functions, {} blocks ({})",
                      sections.functions.size(), sections.blocks.size(), sections.details.path);
        }
        return true;
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
