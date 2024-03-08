#include <string_view>
#include <functional>
#include <cassert>
#include <regex>
#include <array>
#include <frida-gum.h>
#include <optional>

#include "platform.hpp"
#include <charconv>
#include "Signature.hpp"

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

static std::string read_data_string(const char *data) {
    constexpr auto data_limit = 256;
    if (!gum_memory_is_readable(data - 1, 256 + 1))
        return {};
    if (data[-1] != 0)
        return {};
    for (size_t i = 0; i < data_limit; i++) {
        if (!std::isgraph(data[i]))
            return {};
        if (data[i] == 0) {
            return std::string(data, data + i);
        }
    }
    return {};
}

static std::string conver_data_ptr(const char *data) {
    if (!gum_memory_is_readable(data, sizeof(void *))) {
        return "(unknown)";
    }
    if (!memory_is_execute((void *) data))
        return "(data)" + read_data_string(data);
    else {
        auto str = read_data_string(data);
        if (str.empty())
            return "code";
        return str;
    }
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
        const auto& operand = csX86.operands[1];
        if (operand.type == x86_op_type::X86_OP_MEM){
            if (operand.mem.base == x86_reg::X86_REG_RIP){

                signature = std::regex_replace(op_str, regx2,
                                               imm > 0 ? "[rip + 0x????????]" : "[rip - 0x????????]");
                rva = insn->id == X86_INS_JMP || insn->id == X86_INS_CALL;
            }else if (operand.mem.index != x86_reg::X86_REG_INVALID) {
                signature = std::regex_replace(op_str, regx1, "[r$1x + rax*$2 $3 0x??]");
            }
        }
    }else if(csX86.op_count == 1) {
        const auto& operand = csX86.operands[0];
        if (operand.type == x86_op_type::X86_OP_IMM){
            auto imm = operand.imm;
            if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS) {
                signature = "0x????????";
            }else {
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
                auto sub_signatures = create_signature(data, nullptr, insn->id == X86_INS_CALL?4:1);
                if (sub_signatures.size() > 0) {
                    asm_codes.insert(asm_codes.end(), sub_signatures.asm_codes.cbegin(), sub_signatures.asm_codes.cend());
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

#include <unordered_set>

std::unordered_set<void *> get_function_address(const GumMemoryRange &text, uint64_t address) {
    cs_insn *insns;
    std::unordered_set<void *> res;
    auto count = cs_disasm(hcs, reinterpret_cast<const uint8_t *>(text.base_address), text.size, address, size_t(-1),
                           &insns);

    for (int i = 0; i < count; ++i) {
        const auto &insn = insns[i];
        const auto &x86_details = insn.detail->x86;
        if (insn.id == X86_INS_JMP || insn.id == X86_INS_JMP) {
            const auto &operand = x86_details.operands[0];
            if (operand.type != x86_op_type::X86_OP_INVALID) {
                if (x86_details.disp == 0) {
                    res.insert((void *) operand.imm);
                } else {
                    res.insert((void *) (insn.address + insn.size + x86_details.disp));
                }
            }
        }
    }
    cs_free(insns, count);
    return res;
}

struct ModuleSections {
    GumModuleDetails details;
    GumMemoryRange text;
    GumMemoryRange rodata;
};

ModuleSections get_module_sections(const char *path, GumAddress base_address) {
#ifdef _WIN32
#error "not support"
#else

    ModuleSections sections;
    gum_module_enumerate_sections(path, +[](const GumSectionDetails *details, gpointer user_data) -> gboolean {
        if (details->name == ".text") {
            (*(ModuleSections *) user_data).text = {details->address, details->size};
        } else if (details->name == ".rodata")
            (*(ModuleSections *) user_data).rodata = {details->address, details->size};
        return TRUE;
    }, (void *) &sections);
#endif
}