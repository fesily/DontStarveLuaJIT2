#include "ModuleSections.hpp"

#include <unordered_set>
#include <ranges>
#include <algorithm>
#include <cassert>

#ifdef _WIN32
#include <pe-parse/parse.h>
#endif

#include <range/v3/all.hpp>

#include "ctx.hpp"

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

    static bool reg_is_ip(x86_reg reg) {
        return reg == x86_reg::X86_REG_RIP || reg == x86_reg::X86_REG_EIP || reg == x86_reg::X86_REG_IP;
    };

    static const char *read_data_string(const char *data) {
        constexpr auto data_limit = 16;
        if (!gum_memory_is_readable(data, data_limit))
            return nullptr;
        for (size_t i = 0; i < 256; i++) {
            if (!std::isprint(data[i]))
                return data[i] == 0 ? data : nullptr;
        }
        return nullptr;
    }

    static uintptr_t filter_jmp_or_call(ModuleSections &m, uintptr_t imm) {
        const auto hcs = get_ctx().hcs;
        auto insn = cs_malloc(hcs);
        auto addr = imm;
        size_t size = 32;
        auto code = (const uint8_t *) imm;
        if (cs_disasm_iter(hcs, &code, &size, reinterpret_cast<uint64_t *>(&addr), insn)) {
            if (insn->id == X86_INS_JMP) {
                auto &op = insn->detail->x86.operands[0];
                if (op.type == x86_op_type::X86_OP_MEM) {
                    auto target = insn->address + insn->size + op.mem.disp;
                    if (m.in_got_plt(target)) {
                        imm = (intptr_t) *(void **) target;
                    }
                } else if (op.type == x86_op_type::X86_OP_IMM) {
                    imm = op.imm;
                }
            }
        }
        cs_free(insn, 1);
        return imm;
    }

    struct ScanCtx {
        ModuleSections &m;

        cs_insn *insns;
        size_t insns_count;
        size_t index = 0;

        ScanCtx(ModuleSections &_m, uint64_t scan_address) : m{_m} {
            scan_address = std::max(m.text.base_address, scan_address);
            const auto address = scan_address;
            const GumMemoryRange &text = {scan_address,
                                          (m.text.base_address + m.text.size - scan_address) / sizeof(char)};
            const auto hcs = get_ctx().hcs;
            insns_count = cs_disasm(hcs, reinterpret_cast<const uint8_t *>(text.base_address), text.size,
                                    address,
                                    0,
                                    &insns);
        }

        ~ScanCtx() {
            if (insns)
                cs_free(insns, insns_count);
        }

        Function *cur = nullptr;
        CodeBlock *cur_block = nullptr;
        uint64_t function_limit = 0;

        void function_end() {
            function_limit = 0;
            cur = nullptr;
            cur_block = nullptr;
        }

        CodeBlock *createBlock(uint64_t addr) {
            return &cur->blocks.emplace_back(CodeBlock{addr});
        }

        void scan_function() {
            std::unordered_map<uint64_t, bool> sureFunctions;
            for (; index < insns_count; ++index) {
                const auto &insn = insns[index];
                if (cur == nullptr) {
                    cur = &m.functions.emplace_back(Function{insn.address});
                    cur_block = createBlock(insn.address);
                }
                assert(m.in_text(insn.address));
                const auto &x86_details = insn.detail->x86;
                switch (insn.id) {
                    case X86_INS_JMP:
                    case X86_INS_CALL: {
                        const auto &operand = x86_details.operands[0];
                        if (operand.type != x86_op_type::X86_OP_INVALID && operand.type != x86_op_type::X86_OP_REG) {
                            uint64_t imm =
                                    x86_details.disp == 0 ? operand.imm : insn.address + insn.size + x86_details.disp;
#ifndef _WIN32
                            if (m.in_plt(imm)) {
                                imm = filter_jmp_or_call(m, imm);
                            }
#endif
                            if (m.in_text(imm)) {
                                sureFunctions.emplace(imm, false);
                                cur_block->call_functions.emplace_back(imm);
                            } else {
                                // unknown function
                                cur_block->call_functions.emplace_back(imm);
                            }
                        }
                    }
                        if (insn.id != X86_INS_JMP) {
                            break;
                        }
                        [[fallthrough]];
                    case X86_INS_RET:
                    case X86_INS_RETFQ:
                        if (function_limit < insn.address + insn.size) {
                            function_end();
                        } else {
                            cur_block = createBlock(insn.address + insn.size);
                        }
                        break;
                    case X86_INS_MOV:
                    case X86_INS_LEA: {
                        if (x86_details.op_count == 2) {
                            if (x86_details.disp != 0 &&
                                ((x86_details.operands[1].type == x86_op_type::X86_OP_MEM &&
                                  !reg_is_ip(x86_details.operands[1].mem.base)) ||
                                 (x86_details.operands[0].type == x86_op_type::X86_OP_MEM &&
                                  !reg_is_ip(x86_details.operands[0].mem.base))))
                                cur_block->const_offset_numbers.emplace_back(x86_details.disp);
                            else if (x86_details.operands[1].type == X86_OP_IMM)
                                cur_block->const_numbers.emplace_back(x86_details.operands[1].imm);
                        }
                        const char *str = nullptr;
                        if (x86_details.op_count == 2 && x86_details.operands[0].type == x86_op_type::X86_OP_REG) {
                            const auto &op = x86_details.operands[1];
                            if (insn.id == X86_INS_LEA) {
                                if (op.type == x86_op_type::X86_OP_MEM && op.mem.base == x86_reg::X86_REG_RIP &&
                                    op.mem.index == x86_reg::X86_REG_INVALID &&
                                    op.mem.segment == x86_reg::X86_REG_INVALID) {
                                    auto target = insn.address + insn.size + op.mem.disp;
                                    if (m.in_rodata(target))
                                        str = read_data_string((char *) target);
                                }
                            } else if (insn.id == X86_INS_MOV) {
                                if (op.type == x86_op_type::X86_OP_IMM) {
                                    auto target = op.imm;
                                    if (m.in_rodata(target))
                                        str = read_data_string((char *) target);
                                }
                            }
                            if (str != nullptr && strlen(str) > 0) {
                                if (m.Consts.contains(str)) {
                                    m.Consts[str].ref++;
                                } else {
                                    m.Consts[str] = {str, 1};
                                }
                                cur_block->consts.emplace_back(&m.Consts[str]);
                            }
                        }
                    }
                        break;
                    default:
                        if (insn.id >= X86_INS_JAE || insn.id <= X86_INS_JS) {
                            assert(x86_details.op_count == 1 &&
                                   x86_details.operands[0].type == x86_op_type::X86_OP_IMM);
                            auto addr = (uint64_t) x86_details.operands[0].imm;
                            function_limit = std::max(addr, function_limit);

                            cur_block = createBlock(insn.address + insn.size);
                        }
                        break;
                }
            }
        }
    };

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
        ModuleSections sections;
#ifdef _WIN32
        const auto details = get_module_details(path);

        const auto pe = peparse::ParsePEFromPointer((uint8_t*)details->range->base_address, details->range->size);
        if (pe)
        {
            peparse::IterSec(pe, +[](void* user_data,
                const peparse::VA& secBase,
                const std::string& secName,
                const peparse::image_section_header& s,
                const peparse::bounded_buffer* data)
                {
                    if (secName == ".text")
                        ((ModuleSections*)user_data)->text = { secBase, data ? 0 : data->bufLen };
                    else if (secName == ".rdata")
                        ((ModuleSections*)user_data)->rodata = { secBase, data ? 0 : data->bufLen };
                    return 1;
                }, (void*)&sections);
        }
        peparse::DestructParsedPE(pe);
        gum_module_details_free(details);
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
        return sections;
    }


    ModuleSections init_module_signature(const char *path, uintptr_t scan_start_address) {
        auto sections = get_module_sections(path);
        sections.details = get_module_details(path);
        ScanCtx ctx{sections, scan_start_address};
        ctx.scan_function();
        for (auto &func: sections.functions) {
            for (const auto &block: func.blocks) {
                for (const auto &c: block.consts) {
                    if (c->ref == 1 && c->value.size() > func.const_key.size()) {
                        func.const_key = c->value;
                    }
                }
            }

            func.consts_hash = hash_vector(func.blocks);
        }
        return sections;
    }


    struct MatchConfig {
        const float consts_score = 1;
        const float call_score = 0.8;
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
                if (function.const_key == key)
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
        if (!original.const_key.empty()) {
            auto matched = ctx.match_function(original.const_key);
            assert(matched.size() <= 1);
            if (matched.size() == 1) {
                return matched[0].matched->address;
            }
        } else {
            auto matched = ctx.match_function(original);
            std::ranges::sort(matched, [](auto &l, auto &r) {
                return l.score > r.score;
            });
            for (const auto &match: matched) {
                if (!match) continue;
                if (match.score >= targetScore) {
                    return match.matched->address;
                }
            }
        }

        return (uintptr_t) fix_func_address_by_signature(*this, original);
    }

}
