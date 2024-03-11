#include <string_view>
#include <functional>
#include <cassert>
#include <regex>
#include <optional>
#include <algorithm>
#include <ranges>
#include <frida-gum.h>
#include <pe-parse/parse.h>

#include "platform.hpp"
#include "Signature.hpp"

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
    match_pattern = gum_match_pattern_new_from_string(pattern);
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
                                                       imm > 0 ? "[rip + 0x??????]" : "[rip - 0x??????]"));
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
                                               csX86.disp > 0 ? "[rip + 0x????????]" : "[rip - 0x????????]");
                rva = insn->id == X86_INS_JMP || insn->id == X86_INS_CALL;
            } else if (operand.mem.index != x86_reg::X86_REG_INVALID) {
                signature = std::regex_replace(op_str, regx1, "[r$1x + rax*$2 $3 0x??]");
            }
        }
    } else if (csX86.op_count == 1) {
        const auto &operand = csX86.operands[0];
        if (operand.type == x86_op_type::X86_OP_IMM) {
            imm = operand.imm;
            if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS) {
                signature = "0x????????";
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
                if (rva && !memory_is_execute(data)) {
                    data = *(void **) data;
                    if (!memory_is_execute(data))
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


Signature create_signature(void *func, const in_function_t &in_func, size_t limit, bool readRva) {
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

        ret.memory_ranges.push_back({insn->address, insn->size});
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

static constexpr size_t func_aligned() {
#ifdef _M_X86
    return 8;
#elif defined(__i386__)
    return 8;
#else
    return 16;
#endif
}

static std::unordered_map<void *, Signature> signature_cache;
static std::unordered_map<void *, std::string> signature_first_cache;

void release_signature_cache() {
    signature_cache.clear();
    signature_first_cache.clear();
}

const Signature *get_signature_cache(void *fix_target, const std::string &first) {
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
        signature_cache[fix_target] = create_signature(fix_target, nullptr, size_t(-1), true);
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

void *fix_func_address_by_signature(void *target, void *original, const in_function_t &in_func, uint32_t range,
                                    bool updated) {
    constexpr auto short_signature_len = 16;
    if (create_signature(target, nullptr, short_signature_len, false) ==
        create_signature(original, in_func, short_signature_len, false)) {
        return target;
    }
    auto original_s = create_signature(original, in_func);
    // 基于以下假设，函数地址必然被对齐分配
    constexpr auto aligned = func_aligned();
    auto limit = range / aligned;

    size_t maybe_target_count = 1;
    void *maybe_target_addr = nullptr;

    for (size_t i = 0; i < limit; i++) {
        auto fix_target = (void *) ((intptr_t) target + i * aligned);
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
        if (updated) {
            fix_target = (void *) ((intptr_t) target - i * aligned);
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
    }
    if (maybe_target_addr) {
        OUTPUT_SIGNATURE(original, original_s.to_string());
        fprintf(stderr, "maybe target:\n");
        OUTPUT_SIGNATURE(maybe_target_addr, get_signature_cache(maybe_target_addr, original_s[0])->to_string());
        return maybe_target_addr;
    }
    OUTPUT_SIGNATURE(original, original_s.to_string());
    return nullptr;
}

bool ModuleSections::in_plt(intptr_t address) const {
    return plt.base_address <= address && address <= plt.base_address + plt.size;
}

bool ModuleSections::in_got_plt(intptr_t address) const {
    return got_plt.base_address <= address && address <= got_plt.base_address + got_plt.size;
}

bool ModuleSections::in_rodata(intptr_t address) const {
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
                if (x86_details.op_count == 2 && x86_details.disp != 0) {
                    const_numbers.emplace(insn.address, x86_details.disp);
                }
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
        func->consts.push_back(constStr);
        if (constStr->ref == 1) {
            func->const_key = constStr->value;
        }
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
    for (auto &[_, func]: m.functions) {
        std::ranges::sort(func.call_functions);
        std::ranges::sort(func.const_numbers);
        std::ranges::sort(func.consts, [](auto &l, auto &r) { return l->value < r->value; });
    }
}

static ModuleSections get_module_sections(const char *path) {
#ifdef _WIN32
#error "not support"
#else

    ModuleSections sections;
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
    return sections;
#endif
}

void init_module_signature(const char *path, uintptr_t scan_start_address) {
    auto sections = get_module_sections(path);
    if (path == nullptr) {
        sections.details = gum_module_details_copy(gum_process_get_main_module());
    } else {
        auto fn = [&](const GumModuleDetails *details) -> gboolean {
            if (strcmp(details->path, path) == 0
                || std::string_view(details->path).ends_with(path)) {
                sections.details = gum_module_details_copy(details);
                return FALSE;
            }
            return TRUE;
        };
        gum_process_enumerate_modules(+[](const GumModuleDetails *details,
                                          gpointer user_data) -> gboolean {
            return (*((decltype(fn) *) user_data))(details);
        }, (void *) &fn);
    }
    scan_module(sections, scan_start_address);
}

Function *match_function(const char *key, ModuleSections &sections) {
    auto iter = std::ranges::find_if(sections.functions, [key](const auto &func1) {
        return std::string_view(func1.second.const_key) == key;
    });
    return iter != sections.functions.end() ? &iter->second : nullptr;
}

template<typename T>
size_t hash_vector(const std::vector<T> &vec) {
    auto seed = vec.size();
    for (const auto &v: vec) {
        seed ^= std::hash<T>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
    return seed;
}

Function *match_function(Function &func1, ModuleSections &sections) {
    const auto target = func1.get_consts_hash();
    // 全部字符串组合
    for (auto &func: sections.functions) {
        if (target == func.second.get_consts_hash())
            return &func.second;
    }
    auto iter = std::ranges::max_element(sections.functions, [&func1](auto &l, auto &r) {
        auto fn = [&func1](const Const *str) {
            return std::ranges::find(func1.consts, str) != func1.consts.cend();
        };
        return std::ranges::count_if(l.second.consts, fn) >
               std::ranges::count_if(r.second.consts, fn);
    });
    if (iter != sections.functions.end())
        return &iter->second;
    return nullptr;
}

void try_fix_func_address(ModuleSections &target, ModuleSections &original) {
    for (const auto &[addr, func]: target.functions) {
        if (func.const_key) {

        } else {
            // 尝试用字符串组来匹配函数

        }
    }
}

size_t Function::get_consts_hash() {
    if (consts_hash == 0) {
        consts_hash = get_consts_hash();
    }
    return consts_hash;
}
