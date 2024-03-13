#include <string_view>
#include <functional>
#include <cassert>
#include <regex>
#include <optional>
#include <algorithm>
#include <ranges>

#ifdef _WIN32
#include <pe-parse/parse.h>
#endif

#include <frida-gum.h>
#include <spdlog/spdlog.h>
#include <range/v3/all.hpp>

#include "Signature.hpp"

static gboolean
gum_memory_is_execute(gconstpointer address,
                      gsize len) {
    GumPageProtection prot;
    if (!gum_memory_query_protection(address, &prot))
        return FALSE;
    return (prot & GUM_PAGE_EXECUTE) != 0;
}

using in_function_t = std::function<bool(void *)>;

static Signature
create_signature(void *func, const in_function_t &in_func, size_t limit = size_t(-1));

using namespace std::literals;
static csh hcs;

bool signature_init() {
    if (hcs)
        return true;
    cs_arch_register_x86();
    auto ec = cs_open(CS_ARCH_X86, CS_MODE_64, &hcs);
    if (ec != CS_ERR_OK)
        return false;
    cs_option(hcs, CS_OPT_DETAIL, CS_OPT_ON);
    return true;
}

void signature_deinit() {
    cs_close(&hcs);
}

constexpr auto page = GUM_PAGE_EXECUTE;

static gboolean sacnBaseAddrCb(GumAddress address, gsize size, gpointer user_data) {
    auto self = (MemorySignature *) user_data;
    assert(self->target_address == 0);
    self->target_address = address + self->pattern_offset;
    return true;
}

static gboolean findBaseAddrCb(const GumRangeDetails *details, gpointer user_data) {
    auto self = (MemorySignature *) user_data;
    gum_memory_scan(details->range, self->match_pattern, sacnBaseAddrCb, user_data);
    return true;
}

uintptr_t MemorySignature::scan(const char *m) {
    target_address = 0;
    auto match_pattern = gum_match_pattern_new_from_string(pattern);
    gum_module_enumerate_ranges(m, page, findBaseAddrCb, (gpointer) this);
    gum_match_pattern_unref(match_pattern);
    fprintf(stdout, "Signature %s: %p\n", pattern, (void *) target_address);
    return target_address;
}

std::string Signature::to_string() const {
    size_t length = 0;
    for (auto &code: this->asm_codes) {
        length += code.size();
    }
    std::string ret;
    ret.reserve(length + 1);
    for (auto &code: this->asm_codes) {
        ret.append(code);
        ret.append("\n");
    }
    return ret;
}

bool Signature::operator==(const Signature &other) const {
    if (this->asm_codes.size() != other.asm_codes.size())
        return false;
    for (size_t i = 0; i < this->asm_codes.size(); i++) {
        if (this->asm_codes[i] != other.asm_codes[i])
            return false;
    }
    return true;
}

static const char *read_data_string(const char *data) {
    constexpr auto data_limit = 256;
    if (!gum_memory_is_readable(data - 1, 256 + 1))
        return nullptr;
    if (data[-1] != 0)
        return nullptr;
    for (size_t i = 0; i < data_limit; i++) {
        if (!std::isgraph(data[i]))
            return nullptr;
        if (data[i] == 0) {
            return data;
        }
    }
    return {};
}

static auto regx1 = std::regex(R"(\[r(.)x \+ rax\*(\d+) (\+\-) 0x([0-9a-z]+)\])");
static auto regx2 = std::regex("0x[0-9a-z]+");

static bool is_valid_remote_offset(int64_t offset) {
    return offset >= std::numeric_limits<short>::min() && offset <= std::numeric_limits<short>::max();
}

static void
filter_signature(cs_insn *insn, uint64_t &maybe_end, decltype(Signature::asm_codes) &asm_codes) {
    const auto &csX86 = insn->detail->x86;
    std::string op_str = insn->op_str;
#ifndef _WIN32
    // linux上fpic生成的so跟直接生成应用程序的二进制上，对于加载确定的位置内存方式有一些差别
    // 把类似与 mov reg, 0x????? 转成 lea reg, [rip + 0x????]
    if (insn->id == X86_INS_MOV && csX86.op_count == 2) {
        if (csX86.operands[0].type == x86_op_type::X86_OP_REG &&
            csX86.operands[1].type == x86_op_type::X86_OP_IMM) {
            auto imm = csX86.operands[1].imm;
            if (is_valid_remote_offset(imm)) {
                asm_codes.push_back("lea");
                asm_codes.push_back(std::regex_replace(op_str, regx2,
                                                       imm > 0 ? "[rip + 0x?]" : "[rip - 0x?]"));
                return;
            }
        }
    }
#endif
    std::string signature = op_str;
    int64_t imm = 0;
    bool rva = false;
    if (csX86.disp != 0 && csX86.op_count == 2) {
        const auto &operand = csX86.operands[1];
        if (operand.type == x86_op_type::X86_OP_MEM) {
            if (operand.mem.base == x86_reg::X86_REG_RIP) {
                signature = std::regex_replace(op_str, regx2,
                                               csX86.disp > 0 ? "[rip + 0x?]" : "[rip - 0x?]");
                rva = insn->id == X86_INS_JMP || insn->id == X86_INS_CALL;
            } else if (operand.mem.index != x86_reg::X86_REG_INVALID) {
                signature = std::regex_replace(op_str, regx1, "[r$1x + rax*$2 $3 0x?]");
            }
        }
    } else if (csX86.op_count == 1) {
        const auto &operand = csX86.operands[0];
        if (operand.type == x86_op_type::X86_OP_IMM) {
            imm = operand.imm;
            if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS) {
                signature = "0x?";
            } else {
                if (imm > maybe_end)
                    maybe_end = imm;
                int64_t offset = imm - (insn->address + insn->size);
                signature = std::to_string(offset);
            }
        }
    }
    do {
        if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) {
            if (imm != 0) {
                auto data = (void *) imm;

                if (rva && !gum_memory_is_execute(data, sizeof(void *))) {
                    data = *(void **) data;
                    if (!gum_memory_is_execute(data, sizeof(void *)))
                        break;
                }
                signature.clear();
                auto sub_signatures = create_signature(data, nullptr, insn->id == X86_INS_CALL ? 4 : 1);
                if (sub_signatures.size() > 0) {
                    asm_codes.insert(asm_codes.end(), sub_signatures.asm_codes.cbegin(),
                                     sub_signatures.asm_codes.cend());
                    return;
                }
            }
        }
    } while (0);
    asm_codes.push_back(insn->mnemonic);
    asm_codes.push_back(std::move(signature));
}


Signature create_signature(void *func, const in_function_t &in_func, size_t limit) {
    Signature ret;

    const uint8_t *binary = (uint8_t *) func;
    auto insn = cs_malloc(hcs);
    uint64_t address = (uint64_t) func;
    size_t insn_len = 1024;
    size_t count = 0;
    uint64_t maybe_end = 0;
    while (cs_disasm_iter(hcs, &binary, &insn_len, &address, insn)) {
        if (count >= limit)
            break;

        count++;

        filter_signature(insn, maybe_end, ret.asm_codes);
        if (insn->id == X86_INS_JMP || insn->id == X86_INS_INT3 || insn->id == X86_INS_RET) {
            if (maybe_end >= (insn->address + insn->size))
                continue;
            if (!in_func || !in_func((void *) ((char *) address + insn->size))) {
                break;
            }
        }
    }
    cs_free(insn, 1);
    return ret;
}

static std::unordered_map<void *, Signature> signature_cache;
static std::unordered_map<void *, std::string> signature_first_cache;

void release_signature_cache() {
    signature_cache.clear();
    signature_first_cache.clear();
}

static const Signature *get_signature_cache(void *fix_target, const std::string &first) {
    Signature *target_s;
    if (signature_cache.find(fix_target) != signature_cache.end()) {
        target_s = &signature_cache[fix_target];
    } else {
        auto first_s = create_signature(fix_target, nullptr, 1);
        if (first_s.empty())
            return nullptr;
        if (first_s[0] != first) {
            return nullptr;
        }
        signature_cache[fix_target] = create_signature(fix_target, nullptr, size_t(-1));
        target_s = &signature_cache[fix_target];
    }
    return target_s;
}

static int longestCommonSubstring(const std::vector<std::string> &text1, const std::vector<std::string> &text2) {
    int m = text1.size(), n = text2.size();
    std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));
    for (int i = 1; i <= m; i++) {
        auto c1 = text1.at(i - 1);
        for (int j = 1; j <= n; j++) {
            auto c2 = text2.at(j - 1);
            if (c1 == c2) {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = std::max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
    }
    return dp[m][n];
}

#if 1
#define OUTPUT_SIGNATURE(addr, s) fprintf(stderr, "---%p---\n%s\n\n\n", addr, s.c_str())
#else
#define OUTPUT_SIGNATURE(addr, s)
#endif


bool is_same_signature_fast(void *target, void *original) {
    constexpr auto short_signature_len = 16;
    return create_signature(target, nullptr, short_signature_len) ==
           create_signature(original, nullptr, short_signature_len);
}

static void *
fix_func_address_by_signature(ModuleSections &target, Function &original) {
    auto original_s = create_signature((void *) original.address, [&original](auto address) {
        return original.in_function((uintptr_t) address);
    });

    size_t maybe_target_count = 1;
    void *maybe_target_addr = nullptr;

    for (const auto &[addr, func]: target.functions) {
        auto fix_target = (void *) addr;
        auto target_s = get_signature_cache(fix_target, original_s[0]);
        if (!target_s)
            continue;
        auto max = longestCommonSubstring(original_s.asm_codes, target_s->asm_codes);
        if (max == original_s.size())
            return fix_target;
        if (max > maybe_target_count) {
            maybe_target_count = max;
            maybe_target_addr = fix_target;
        }
    }
    if (maybe_target_addr) {
        OUTPUT_SIGNATURE((void *) original.address, original_s.to_string());
        fprintf(stderr, "maybe target:\n");
        OUTPUT_SIGNATURE(maybe_target_addr, get_signature_cache(maybe_target_addr, original_s[0])->to_string());
        return maybe_target_addr;
    }
    OUTPUT_SIGNATURE((void *) original.address, original_s.to_string());
    return nullptr;
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

Function *ModuleSections::get_function(uint64_t address) {
    auto iter = functions.begin(), end = functions.end();
    auto finder = end;
    for (; iter != end; ++iter) {
        if (address >= iter->first) {
            finder = iter;
        } else {
            break;
        }
    }
    return finder != end ? &finder->second : nullptr;
}

static bool reg_is_ip(x86_reg reg) {
    return reg == x86_reg::X86_REG_RIP || reg == x86_reg::X86_REG_EIP || reg == x86_reg::X86_REG_IP;
};

static void scan_module(ModuleSections &m, uint64_t scan_address) {
    cs_insn *insns;
    const auto address = m.details->range->base_address;
    // .text
    scan_address = std::max(m.text.base_address, scan_address);
    const GumMemoryRange &text = {scan_address, (m.text.base_address + m.text.size - scan_address) / sizeof(char)};
    auto count = cs_disasm(hcs, reinterpret_cast<const uint8_t *>(text.base_address), text.size,
                           address,
                           size_t(-1),
                           &insns);
    std::unordered_map<uint64_t, Const *> consts;
    std::unordered_set<uint64_t> nops;
    std::unordered_multimap<uint64_t, uint64_t> calls;
    std::unordered_map<uint64_t, int64_t> const_numbers;
    std::unordered_map<uint64_t, int64_t> const_offset_numbers;
    for (int i = 0; i < count; ++i) {
        const auto &insn = insns[i];
        const auto &x86_details = insn.detail->x86;
        switch (insn.id) {
            case X86_INS_JMP:
            case X86_INS_CALL: {
                const auto &operand = x86_details.operands[0];
                if (operand.type != x86_op_type::X86_OP_INVALID) {
                    uint64_t imm = x86_details.disp == 0 ? operand.imm : insn.address + insn.size + x86_details.disp;
#ifndef _WIN32
                    // 计算相对转跳的最终地址
                    if (m.in_plt(imm)) {
                        auto insn = cs_malloc(hcs);
                        auto addr = address;
                        size_t size = 32;
                        auto code = (const uint8_t *) imm;
                        if (cs_disasm_iter(hcs, &code, &size, &addr, insn)) {
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
                    }
#endif
                    calls.emplace(insn.address, imm);
                    m.functions[imm] = {imm};
                }
            }
                break;
            case X86_INS_MOV:

                if (x86_details.op_count == 2) {
                    if (x86_details.disp != 0 &&
                        ((x86_details.operands[1].type == x86_op_type::X86_OP_MEM &&
                          !reg_is_ip(x86_details.operands[1].mem.base)) ||
                         (x86_details.operands[0].type == x86_op_type::X86_OP_MEM &&
                          !reg_is_ip(x86_details.operands[0].mem.base))))
                        const_offset_numbers.emplace(insn.address, x86_details.disp);
                    else if (x86_details.operands[1].type == X86_OP_IMM)
                        const_numbers.emplace(insn.address, x86_details.operands[1].imm);
                }
                [[fallthrough]];
            case X86_INS_LEA: {
                const char *str = nullptr;
                // 尝试读取一个指向const常量的字符串
                if (x86_details.op_count == 2 && x86_details.operands[0].type == x86_op_type::X86_OP_REG) {
                    const auto &op = x86_details.operands[1];
                    if (insn.id == X86_INS_LEA) {
                        if (op.type == x86_op_type::X86_OP_MEM && op.mem.base == x86_reg::X86_REG_RIP &&
                            op.mem.index == x86_reg::X86_REG_INVALID && op.mem.segment == x86_reg::X86_REG_INVALID) {
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
                    if (str != nullptr) {
                        if (m.Consts.contains(str)) {
                            m.Consts[str].ref++;
                        } else {
                            m.Consts[str] = {str, 1};
                        }
                        consts[insn.address] = &m.Consts[str];
                    }
                }
            }
                break;
            case X86_INS_NOP: {
                // 有可能是函数之间的分割填充
                nops.insert(insn.address);
            }
            default:
                break;
        }

    }
    cs_free(insns, count);
    for (const auto &[addr, constStr]: consts) {
        auto func = m.get_function(addr);
        if (!func) continue;
        // unique const str
        if (std::ranges::find(func->consts, constStr) != func->consts.end())
            func->consts.push_back(constStr);
    }
    for (const auto &[addr, callAddr]: calls) {
        auto func = m.get_function(addr);
        if (!func) continue;
        func->call_functions.push_back(callAddr);
    }
    for (const auto &[addr, num]: const_numbers) {
        auto func = m.get_function(addr);
        if (!func) continue;
        func->const_numbers.push_back(num);
    }
    for (const auto &[addr, num]: const_offset_numbers) {
        auto func = m.get_function(addr);
        if (!func) continue;
        func->const_offset_numbers.push_back(num);
    }
    for (auto &func: m.functions | std::views::values) {
        std::ranges::sort(func.call_functions);
        std::ranges::sort(func.const_numbers);
        std::ranges::sort(func.consts, [](auto &l, auto &r) { return l->value < r->value; });
        for (const auto &c: func.consts) {
            if (c->ref == 1) {
                func.const_key = c->value;
            } else {
                // maybe same const ref by same function
                if (std::ranges::count(func.consts, c) == c->ref) {
                    func.const_key = c->value;
                }
            }
        }
    }
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
                ((ModuleSections*)user_data)->text = { secBase, data?0: data->bufLen };
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
    scan_module(sections, scan_start_address);
    return sections;
}

template<typename T>
size_t hash_vector(const std::vector<T> &vec) {
    auto seed = vec.size();
    for (const auto &v: vec) {
        seed ^= std::hash<T>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
    return seed;
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

    std::vector<Match> match_function(const char *key) {
        return
                sections.functions | std::views::filter([key, this](const auto &func1) {
                    return func1.second.const_key && std::string_view(func1.second.const_key) == key;
                }) | std::views::transform([this](const auto &func1) {
                    return Match{&func1.second, config.match_score};
                }) | ranges::to<std::vector>();
    }

    std::vector<Match> match_function(Function &func1) {
        const auto target = func1.get_consts_hash();
        std::vector<Match> res;
        // 全部字符串组合
        for (auto &func: sections.functions) {
            if (target == func.second.get_consts_hash())
                res.emplace_back(Match{&func.second, config.match_score});
        }
        if (res.empty()) {

            auto fn = [&func1](const Const *str) {
                return std::ranges::find_if(func1.consts, [target = std::string_view(str->value)](const auto v) {
                    return v->value == target;
                }) != func1.consts.cend();
            };

            auto view = sections.functions | std::views::transform([&fn](auto &p) {
                return std::pair{&p.second, std::ranges::count_if(p.second.consts, fn)};
            }) | ranges::to<std::vector>();

            std::ranges::sort(view, [](auto &l, auto &r) {
                return l.second > r.second;
            });

            const auto score = view.front().second;
            auto v1 = view | std::views::take_while([score](auto &v) {
                return v.second == score;
            }) | std::views::transform([this](auto &v) { return Match{v.first, v.second * config.consts_score}; });

            for (const auto &m: v1) {
                res.emplace_back(m);
            }
        }
        return res;
    }

};

static float calc_score(Function &func, MatchConfig &config) {
    return func.consts.size() * config.consts_score + func.call_functions.size() * config.call_score +
           func.const_numbers.size() * config.const_numbers_score;
}

static bool is_simple_function(Function &func) {
    return func.consts.empty() && func.call_functions.empty();
}

uintptr_t ModuleSections::try_fix_func_address(Function &original, uint64_t maybe_addr) {
    MatchConfig config;
    FunctionMatchCtx ctx{*this, config};
    if (!is_simple_function(original)) {
        const auto targetScore = calc_score(original, config);
        auto res = original.const_key ? ctx.match_function(original.const_key) : ctx.match_function(original);
        if (!res.empty()) {
            for (const auto func: res) {
                if (!func) continue;
                if (func.score >= targetScore) {
                    return func.matched->address;
                }
            }
        }
    }
    return (uintptr_t) fix_func_address_by_signature(*this, original);
}

size_t Function::get_consts_hash() {
    if (consts_hash == 0) {
        consts_hash = get_consts_hash();
    }
    return consts_hash;
}
